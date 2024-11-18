
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
   xcaddy build --with github.com/yourusername/bchauth
   ```

## Configuration

### Example Caddyfile

```caddyfile
:8080 {
    route / {
        bchauth {
            dest_wallet "cb…"
            funds_ctn 10.0
            pg_conn_string "user=postgres password=secret host=localhost dbname=blockchain sslmode=disable"
            redis_addr "localhost:6379"
        }
        reverse_proxy localhost:5432
    }
}
```

### Parameters

- `dest_wallet`: The target wallet to check for transactions.
- `funds_ctn`: CTN amount required for 1 day of access.
- `pg_conn_string`: PostgreSQL connection string.
- `redis_addr`: Redis server address.

## License

This project is licensed under the CORE License.
