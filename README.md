
# BchAuth Plugin for Caddy

BchAuth is a middleware plugin for Caddy that verifies user access based on Core Blockchain (CTN) transactions.
It utilizes PostgreSQL for transaction storage and Redis for caching to optimize performance.

## Features

- Verifies blockchain transactions to control access to resources.
- Calculates service periods based on transactions in CTN.
- Caches access results in Redis to improve efficiency.
- Configurable via the Caddyfile.

## Installation

1. Clone this repository.
2. Build Caddy with the BchAuth module using `xcaddy`:

   ```bash
   xcaddy build --with github.com/DataLayerHost/bchauth
   ```

## Configuration

### Example Caddyfile

```caddyfile
:5432 {
    route /* {
        bchauth {
            dest_wallet "cb…"
            funds_ctn 10.0
            pg_conn_string "user=postgres password=secret host=localhost dbname=blockchain sslmode=disable"
            configured_table "sc_cb…"
            redis_addr "localhost:6379"
            whitelist "publicKey1" "publicKey2" "publicKey3"
        }
        reverse_proxy {
            to 192.168.1.10:5432
            to 192.168.1.11:5432
            to 192.168.1.12:5432

            lb_policy round_robin

            # Optional: Health check to ensure only healthy replicas are used
            health_path "/health"
            health_interval 10s
        }
    }
}
```

### Parameters

- `dest_wallet`: The target wallet to check for transactions.
- `funds_ctn`: CTN amount required for 1 day of access.
- `pg_conn_string`: PostgreSQL connection string.
- `configured_table`: Table name in PostgreSQL to store transactions.
- `redis_addr`: Redis server address.
- `whitelist`: List of public keys that are allowed access without a transaction.

## Read-only Mode

Each instance of PostgreSQL **MUST** be configured to run in read-only mode for Blockchain data. This is useful for scaling read-heavy workloads.

```sql
ALTER SYSTEM SET default_transaction_read_only = 'on';
SELECT pg_reload_conf();
```

## License

This project is licensed under the CORE License.
