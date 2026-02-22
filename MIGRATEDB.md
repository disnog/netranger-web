# Migration Guide: Flask to FastAPI

This guide covers migrating the web portal from Flask to FastAPI.

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
pip install git+https://github.com/disnog/netranger-web.git
```

## Running

### Development

```bash
# Auto-reload enabled
DEBUG=true nrweb

# Or with uvicorn directly
uvicorn nrweb.main:app --reload --host 0.0.0.0 --port 8000
```

### Production

```bash
# Single worker
uvicorn nrweb.main:app --host 0.0.0.0 --port 8000

# Multiple workers (recommended)
uvicorn nrweb.main:app --host 0.0.0.0 --port 8000 --workers 4

# With gunicorn
gunicorn nrweb.main:app -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000
```

### Docker

```bash
docker build -t netranger-web .
docker run -p 8000:8000 --env-file .env netranger-web
```

## Code Changes

### Framework Migration

| Flask | FastAPI |
|-------|---------|
| `Flask()` | `FastAPI()` |
| `@app.route()` | `@app.get()` / `@app.post()` |
| `request.form` | `Form()` dependency |
| `session` | Signed cookie via `SessionManager` |
| `flash()` | `flash(session, msg, category)` |
| `flask-pymongo` | `netranger-db` |
| `render_template()` | `templates.TemplateResponse()` |
| `redirect()` | `RedirectResponse()` |

### Template Changes

Templates remain Jinja2 and are largely unchanged. Minor updates:
- `url_for()` replaced with direct paths
- Context variable names unchanged

### Session Handling

Sessions are now stored in signed cookies (using `itsdangerous`):
- No server-side session storage needed
- Stateless - scales horizontally
- Same security model as Flask sessions

## Endpoint Changes

| Old Path | New Path | Notes |
|----------|----------|-------|
| `/home` | `/` | Home now at root |
| All others | Same | No changes |

## Docker/Kubernetes

### Dockerfile Changes

```dockerfile
# Old (Flask + gunicorn)
CMD ["gunicorn", "nrweb:app", "-b", "0.0.0.0:8000"]

# New (FastAPI + uvicorn)
CMD ["uvicorn", "nrweb.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Health Check

```yaml
# Kubernetes liveness probe
livenessProbe:
  httpGet:
    path: /
    port: 8000
  initialDelaySeconds: 10
```

## Testing the Migration

1. Start the application:
   ```bash
   nrweb
   ```

2. Verify endpoints:
   - `GET /` - Home page loads
   - `GET /login` - Redirects to Discord OAuth
   - `GET /rules` - Rules page loads
   - `GET /join` - Join flow works

3. Test OAuth flow:
   - Click Login
   - Authorize with Discord
   - Verify redirect back works

4. Test join flow:
   - Accept rules
   - Select userclass
   - Verify guild join
