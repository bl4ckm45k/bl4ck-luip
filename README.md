# README

## Description
This project is designed for managing connections and blocking IP addresses using Marzban and a database.

## Environment Configuration
Before running the project, configure the `.env` file with the required parameters.

### General Parameters
- `BAN_MINUTES` – IP ban duration (in minutes). Default: `5`
- `MAX_CONNECTIONS` – Maximum allowed connections per user. Default: `1`

### Redis Settings
- `REDIS_PASSWORD` – Redis password (if set).
- `REDIS_PORT` – Redis server port (default `6379`).
- `REDIS_HOST` – Redis server host (default `127.0.0.1`).

### Database Settings
- `DATABASE_URL` – Database connection string. Default SQLite: `sqlite:///banned_ips.db`
- For PostgreSQL:
  ```env
  DB_HOST='127.0.0.1'
  DB_PORT=5432
  DB_USER=postgres
  DB_PASS='password'
  DB_NAME=bl4ck_luip
  DATABASE_URL=postgresql://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/bl4ck_luip
  ```
- For MySQL:
  ```env
  DATABASE_URL=mysql+asyncmy://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}
  ```

### Marzban Settings
- `SSL_ENABLED` – Whether to use SSL (`True`/`False`). Default: `True`.
- `MARZBAN_LOGIN` – Marzban panel login.
- `MARZBAN_PASSWORD` – Marzban panel password.
- `MARZBAN_HOST` – Domain name or IP address of the Marzban server.
- `MARZBAN_READ_PANEL` – `True` if using the Marzban panel for connections, otherwise `False`.
- `MARZBAN_TOKEN_LIFETIME` – Token lifetime (in minutes). Default: `1440`.

### Administrator Settings
- `ADMIN_LOGIN` – Administrator login.
- `ADMIN_PASSWORD` – Administrator password.

## Running the Project
1. Install dependencies (if required).
2. Create and configure the `.env` file based on the provided example.
3. Start the application.

## Support
If you have any questions or issues, please contact [me on TG: pay4fallwall](https://pay4fallwall.t.me/ "pay4fallwall")

