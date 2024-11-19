package bchauth

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/core-coin/go-core/v2/common"
	"github.com/core-coin/go-core/v2/crypto"
	"github.com/go-redis/redis/v8"
	"golang.org/x/net/context"

	_ "github.com/lib/pq" // PostgreSQL driver
)

func init() {
	caddy.RegisterModule(BchAuth{})
}

type BchAuth struct {
	DB           *sql.DB
	RedisClient  *redis.Client
	DestWallet   string   `json:"dest_wallet"`
	MinFundsCTN  float64  `json:"funds_ctn"` // CTN amount required for 1 day of access
	PGConnString string   `json:"pg_conn_string"`
	RedisAddr    string   `json:"redis_addr"` // Redis address
	Whitelist    []string `json:"whitelist"`  // Public key whitelist
	NetworkId    int64    `json:"network_id"` // Network ID for blockchain addresses
}

// CaddyModule returns the Caddy module information.
func (BchAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.bchauth",
		New: func() caddy.Module { return new(BchAuth) },
	}
}

// Provision initializes the PostgreSQL and Redis connections.
func (bch *BchAuth) Provision(ctx caddy.Context) error {
	var err error

	// Initialize PostgreSQL connection
	bch.DB, err = sql.Open("postgres", bch.PGConnString)
	if err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL: %v", err)
	}

	// Test the connection
	if err := bch.DB.Ping(); err != nil {
		return fmt.Errorf("failed to ping PostgreSQL: %v", err)
	}

	// Initialize Redis connection
	bch.RedisClient = redis.NewClient(&redis.Options{
		Addr: bch.RedisAddr,
	})
	if _, err := bch.RedisClient.Ping(ctx).Result(); err != nil {
		return fmt.Errorf("failed to connect to Redis: %v", err)
	}

	return nil
}

// ServeHTTP verifies access based on blockchain transactions or whitelist.
func (bch *BchAuth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ctx := context.Background()
	pubKey := r.Header.Get("X-Pub-Key")
	if pubKey == "" {
		http.Error(w, "Missing X-Pub-Key", http.StatusForbidden)
		return nil
	}

	// Check whitelist
	if bch.isWhitelisted(pubKey) {
		return next.ServeHTTP(w, r)
	}

	// Check Redis cache
	cacheKey := "access:" + pubKey
	expiry, err := bch.RedisClient.Get(ctx, cacheKey).Result()
	expiryInt, pasrseErr := strconv.ParseInt(expiry, 10, 64)
	if pasrseErr != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil
	}
	if err == nil && time.Now().Before(time.Unix(0, 0).Add(time.Second*time.Duration(expiryInt))) {
		return next.ServeHTTP(w, r)
	}

	// Generate wallet address using Ed448
	address, err := bch.generateAddress(pubKey)
	if err != nil {
		http.Error(w, "Invalid Public Key", http.StatusForbidden)
		return nil
	}

	// Query PostgreSQL to calculate active service days
	activeDays, err := bch.checkActiveService(address, bch.MinFundsCTN)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil
	}

	if activeDays <= 0 {
		http.Error(w, "Service Expired", http.StatusForbidden)
		return nil
	}

	// Set Redis cache for remaining valid service days
	cacheDuration := int64(activeDays) * 86400 // Convert days to seconds
	bch.RedisClient.Set(ctx, cacheKey, cacheDuration, time.Duration(cacheDuration)*time.Second)

	return next.ServeHTTP(w, r)
}

// isWhitelisted checks if the public key is in the whitelist.
func (bch *BchAuth) isWhitelisted(pubKey string) bool {
	for _, whitelistedKey := range bch.Whitelist {
		if strings.EqualFold(whitelistedKey, pubKey) {
			return true
		}
	}
	return false
}

// checkActiveService queries the database for active service days based on the user's transactions.
func (bch *BchAuth) checkActiveService(address string, minFunds float64) (int, error) {
	query := `
		WITH RECURSIVE service_periods AS (
			SELECT
				t.timestamp AS start_date,
				t.timestamp + INTERVAL '1 day' * FLOOR(t.amount / $3) AS end_date,
				FLOOR(t.amount / $3) AS service_days
			FROM transactions t
			WHERE t.sender = $1 AND t.recipient = $2

			UNION ALL

			SELECT
				CASE
					WHEN t.timestamp > sp.end_date THEN t.timestamp
					ELSE sp.start_date
				END AS start_date,
				t.timestamp + INTERVAL '1 day' * FLOOR(t.amount / $3) AS end_date,
				sp.service_days + FLOOR(t.amount / $3) AS service_days
			FROM transactions t
			JOIN service_periods sp
				ON t.sender = $1 AND t.recipient = $2
			   AND t.timestamp > sp.end_date
		)
		SELECT SUM(service_days)
		FROM service_periods
		WHERE start_date <= NOW() AND end_date >= NOW();
	`

	var totalServiceDays int
	err := bch.DB.QueryRow(query, address, bch.DestWallet, minFunds).Scan(&totalServiceDays)
	if err != nil {
		return 0, err
	}

	return totalServiceDays, nil
}

// generateAddress derives the wallet address from the public key using Ed448.
func (bch *BchAuth) generateAddress(pubKey string) (string, error) {
	pubKeyBytes := common.FromHex(pubKey)
	if len(pubKeyBytes) != 57 {
		return "", errors.New("invalid public key length")
	}
	addr := crypto.SHA3(pubKeyBytes[:])[12:]
	checksum := common.Hex2Bytes(common.CalculateChecksum(addr, bch.NetworkIDPrefix()))
	return common.BytesToAddress(append(append(bch.NetworkIDPrefix(), checksum...), addr...)).Hex(), nil
}

// UnmarshalCaddyfile sets up the module from Caddyfile.
func (bch *BchAuth) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "dest_wallet":
				if !d.Args(&bch.DestWallet) {
					return d.Err("expected value for dest_wallet")
				}
			case "funds_ctn":
				var fundsCTNStr string
				if !d.Args(&fundsCTNStr) {
					return d.Err("expected value for funds_ctn")
				}
				fundsCTN, err := strconv.ParseFloat(fundsCTNStr, 64)
				if err != nil {
					return d.Err("invalid value for funds_ctn")
				}
				bch.MinFundsCTN = fundsCTN
			case "pg_conn_string":
				if !d.Args(&bch.PGConnString) {
					return d.Err("expected PostgreSQL connection string")
				}
			case "redis_addr":
				if !d.Args(&bch.RedisAddr) {
					return d.Err("expected Redis address")
				}
			case "network_id":
				var networkIdStr string
				if !d.Args(&networkIdStr) {
					return d.Err("expected network ID")
				}
				networkId, err := strconv.ParseInt(networkIdStr, 10, 64)
				if err != nil {
					return d.Err("invalid network ID format")
				}
				bch.NetworkId = networkId
			case "whitelist":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.Err("expected at least one public key in whitelist")
				}
				bch.Whitelist = args
			}
		}
	}
	return nil
}

// Cleanup closes the PostgreSQL connection.
func (bch *BchAuth) Cleanup() error {
	if bch.DB != nil {
		return bch.DB.Close()
	}
	return nil
}

func (bch *BchAuth) NetworkIDPrefix() []byte {
	if bch.NetworkId == 1 {
		return common.FromHex("cb")
	} else if bch.NetworkId == 3 {
		return common.FromHex("ab")
	} else {
		return common.FromHex("ce")
	}
}

// Interface guards
var (
	_ caddyhttp.MiddlewareHandler = (*BchAuth)(nil)
	_ caddyfile.Unmarshaler       = (*BchAuth)(nil)
)
