# Migration Guide: v1 (MongoDB) → v2 (MariaDB + Flask modernization)

This guide covers migrating the web portal from the legacy MongoDB-based codebase to the modernized v2dev branch using MariaDB via netranger-db.

## Prerequisites

- Python 3.10+
- Completed database migration (see netranger-db MIGRATEDB.md)
- Discord application credentials

## Environment Variable Changes

### Removed Variables

| Variable | Notes |
|----------|-------|
| `MONGO_*` | Replaced by `DB_*` (see netranger-db) |

### Renamed Variables

| Old | New | Notes |
|-----|-----|-------|
| `OAUTH2_REDIRECT_URI` | Same | Now auto-detected if not set |
| `SECRET_KEY` | Same | Defaults to `OAUTH2_CLIENT_SECRET` |
| `NRWEB_ENVIRONMENT` | Same | `prod` or `dev` |

### New Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DEBUG` | `false` | Enable debug mode and auto-reload |

### Required Variables

```bash
# Discord OAuth2 (same as before)
export OAUTH2_CLIENT_ID=your_discord_app_client_id
export OAUTH2_CLIENT_SECRET=your_discord_app_client_secret
export BOT_TOKEN=your_discord_bot_token
export GUILD_ID=your_discord_guild_id

# Database (new - from netranger-db)
export DB_HOST=localhost
export DB_PORT=3306
export DB_USER=netranger
export DB_PASS=your_password
export DB_NAME=netranger
```

## Installation

```bash
pip install git+https://github.com/disnog/netranger-web.git@v2dev
```

## Running

### Development

```bash
# Using the CLI entry point
nrweb

# Or with Flask directly (auto-reload enabled)
flask --app nrweb run --debug
```

### Production

```bash
gunicorn 'nrweb:app' -w 4 -b 0.0.0.0:5000
```

### Docker

```bash
docker build -t netranger-web .
docker run -p 5000:5000 --env-file .env netranger-web
```

## Code Changes

### Database Migration

| Old (v1) | New (v2dev) |
|----------|-------------|
| `flask-pymongo` / raw PyMongo | `netranger-db` (async MariaDB) |
| `db.users.find()` | `await db.users.list_members()` |
| `db.users.find_one()` | `await db.users.get(id)` |
| Inline MongoDB queries | Typed query interface with dataclasses |

### Session Handling

Sessions are now stored in signed cookies (using `itsdangerous`):
- No server-side session storage needed
- Stateless — scales horizontally
- Same security model as Flask sessions

### Key Framework Changes

| Area | Old | New |
|------|-----|-----|
| Sessions | Flask-Session (server-side) | Signed cookies (itsdangerous) |
| Database | PyMongo (sync) | netranger-db (async, connection-pooled) |
| Discord API | requests | httpx |
| Python | 3.7+ | 3.10+ |
| Dependencies | requirements.txt | pyproject.toml (hatchling) |
| Testing | None | pytest-flask with full coverage |
| Linting | None | ruff |

### Template Changes

Templates remain Jinja2 and are largely unchanged. Minor updates:
- Context variable names unchanged
- Flash messages use session-based flash system

## Endpoint Changes

| Old Path | New Path | Notes |
|----------|----------|-------|
| `/home` | `/` | Home now at root (also accessible at `/home`) |
| All others | Same | No changes |

## Docker/Kubernetes

### Dockerfile

The Dockerfile uses Python 3.12-slim and gunicorn:

```dockerfile
FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir .
COPY nrweb/ ./nrweb/
EXPOSE 5000
CMD ["gunicorn", "nrweb:app", "--bind", "0.0.0.0:5000", "--workers", "4"]
```

### Kubernetes

Update your K8s manifests to replace MongoDB env vars with MariaDB:

```yaml
# Replace these MongoDB vars:
#   MONGO_HOST, MONGO_USER, MONGO_NAME, MONGO_PASS
# With:
- name: DB_HOST
  valueFrom:
    secretKeyRef:
      name: network-ranger
      key: DB_HOST
- name: DB_PORT
  value: "3306"
- name: DB_USER
  valueFrom:
    secretKeyRef:
      name: network-ranger
      key: DB_USER
- name: DB_PASS
  valueFrom:
    secretKeyRef:
      name: network-ranger
      key: DB_PASS
- name: DB_NAME
  value: "netranger"
```

### Health Check

```yaml
# Kubernetes liveness probe
livenessProbe:
  httpGet:
    path: /
    port: 5000
  initialDelaySeconds: 10
```

## Testing the Migration

1. Start the application:
   ```bash
   nrweb
   ```

2. Verify endpoints:
   - `GET /` — Home page loads with member counts
   - `GET /login` — Redirects to Discord OAuth
   - `GET /rules` — Rules page loads
   - `GET /join` — Join flow works

3. Test OAuth flow:
   - Click Login
   - Authorize with Discord
   - Verify redirect back works

4. Test join flow:
   - Accept rules
   - Select userclass
   - Verify guild join

5. Run the test suite:
   ```bash
   pip install -e .[dev]
   pytest -v
   ```
