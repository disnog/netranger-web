# netranger-web

Web portal for the Networking Discord server. Built with FastAPI.

## Installation

```bash
pip install git+https://github.com/disnog/netranger-web.git
```

Or for development:

```bash
git clone https://github.com/disnog/netranger-web.git
cd netranger-web
pip install -e .
```

## Configuration

Set environment variables:

```bash
# Required
export OAUTH2_CLIENT_ID=your_discord_app_client_id
export OAUTH2_CLIENT_SECRET=your_discord_app_client_secret
export BOT_TOKEN=your_discord_bot_token
export GUILD_ID=your_discord_guild_id

# Database (via netranger-db)
export DB_HOST=localhost
export DB_PORT=3306
export DB_USER=netranger
export DB_PASS=secret
export DB_NAME=netranger

# Optional
export SECRET_KEY=your_secret_key  # defaults to OAUTH2_CLIENT_SECRET
export OAUTH2_REDIRECT_URI=https://yourdomain.com/login/callback
export NRWEB_ENVIRONMENT=prod  # or dev
export DEBUG=false
```

## Running

### Development

```bash
nrweb
# or
uvicorn nrweb.main:app --reload
```

### Production

```bash
uvicorn nrweb.main:app --host 0.0.0.0 --port 8000 --workers 4
# or with gunicorn
gunicorn nrweb.main:app -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000
```

### Docker

```bash
docker build -t netranger-web .
docker run -p 8000:8000 --env-file .env netranger-web
```

## Features

- Discord OAuth2 login
- Member directory
- User profiles
- Join flow with rules acceptance
- Automatic guild join with role assignment
- Welcome messages

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | / | Home page with stats |
| GET | /rules | Server rules |
| GET | /events | Events page |
| GET | /members | Member directory (requires login + Member role) |
| GET | /profile | Current user's profile |
| GET | /profile/{id} | User profile by ID |
| GET | /login | Start OAuth flow |
| GET | /login/callback | OAuth callback |
| GET | /logout | Log out |
| GET/POST | /join | Join flow |

## License

AGPL-3.0-or-later
