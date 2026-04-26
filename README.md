# netranger-web

Web portal for the Networking Discord server. Built with Flask.

## Installation

```bash
pip install git+https://github.com/disnog/netranger-web.git@v2dev
```

Or for development:

```bash
git clone https://github.com/disnog/netranger-web.git
cd netranger-web
pip install -e .
```

## Configuration

Copy `.env.example` to `.env` and fill in values, or export directly:

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
export SECRET_KEY=your_secret_key          # defaults to OAUTH2_CLIENT_SECRET
export OAUTH2_REDIRECT_URI=https://yourdomain.com/login_callback
export NRWEB_ENVIRONMENT=prod              # or: dev, staging
export DEBUG=false
```

## Running

### Development

```bash
nrweb
# or
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

## Features

- Discord OAuth2 login
- Member directory
- User profiles
- Join flow with rules acceptance
- Automatic guild join with role assignment
- Full-member number assignment during web join, including users who are already in the Discord guild
- OAuth access tokens are kept in the signed session only while a `guilds.join`
  flow is pending; refresh tokens are not stored

## Routes

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Home page with stats |
| GET | `/rules` | Server rules |
| GET | `/events` | Events page |
| GET | `/members` | Member directory (requires Member role) |
| GET | `/myprofile` | Current user's profile |
| GET | `/members/<id>` | Member profile by ID |
| GET | `/login` | Start OAuth2 flow |
| GET | `/login_callback` | OAuth2 callback |
| GET | `/logout` | Log out |
| GET/POST | `/join` | Join flow |
| GET | `/linkedin` | LinkedIn group redirect |
| GET | `/survey-dec2021` | Survey redirect |

## Development

### Setup

```bash
git clone https://github.com/disnog/netranger-web.git
cd netranger-web
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
cp .env.example .env   # edit with real values
```

### Running Tests

Tests use `pytest-flask` and mock the Discord API and database — **no live credentials or database are required**.

The required environment variables are set automatically by the test suite's `conftest.py` using placeholder values. You do **not** need a `.env` file to run tests.

```bash
# Run all tests
pytest -v

# Run with coverage report
pytest -v --cov=nrweb --cov-report=term-missing

# Run a specific test file
pytest tests/test_session.py -v
pytest tests/test_discord_client.py -v
pytest tests/test_views.py -v
```

### Test Structure

```
tests/
├── conftest.py           # Shared fixtures (Flask app, sessions, env vars)
├── test_config.py        # Settings loading and validation
├── test_session.py       # Cookie session, CSRF, flash messages
├── test_discord_client.py  # Discord OAuth2 and API client
└── test_views.py         # Flask routes (integration tests)
```

### Linting

```bash
ruff check .
ruff check . --fix   # auto-fix safe issues
```

## Session Security

Sessions are signed cookies. Set a dedicated high-entropy `SECRET_KEY` in
production and serve only over HTTPS. Discord OAuth access tokens are retained
only long enough to complete the `guilds.join` flow, then removed from the
session. Refresh tokens are not stored.

## License

AGPL-3.0-or-later
