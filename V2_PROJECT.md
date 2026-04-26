# DisNOG V2 Project: netranger-web

## GitHub Project Fields

| Field | Value |
| --- | --- |
| Project | DisNOG V2 |
| Repository | disnog/netranger-web |
| Branch | v2dev |
| Track | Web portal and join flow |
| Status | Ready for integration verification |
| Priority | P0 |
| Depends on | disnog/netranger-db v2dev, Discord OAuth app, Discord bot token |
| Enables | Web join, member directory, profile views |

## Item Summary

Modernize the Flask web portal from MongoDB-backed legacy views to a MariaDB-backed join and member portal using the shared `netranger-db` package, explicit tests, and Docker/CI workflows.

## Feature Differences From main

| Area | main | v2dev | Documentation |
| --- | --- | --- | --- |
| Database | Flask-PyMongo and inline MongoDB queries | Shared `netranger-db` MariaDB package | `README.md`, `MIGRATEDB.md` |
| Sessions | Flask signed session data | Explicit signed-cookie session manager | `README.md`, `MIGRATEDB.md` |
| OAuth redirect handling | Endpoint payload in session | App-local `next` URL validation | `tests/test_views.py` |
| Join flow | Assigns role and member number through MongoDB helper | Assigns role and Member number through MariaDB helper, then joins/syncs Discord | `README.md`, `MIGRATEDB.md` |
| Templates | Legacy Bootstrap/Jinja views | Updated templates, same route surface except `/` also serves home | `README.md`, `MIGRATEDB.md` |
| Packaging | Requirements-only app | `pyproject.toml`, console script, Docker build | `README.md` |
| Tests/CI | Minimal/no branch coverage | Unit/integration tests and lint | `.github/workflows/ci.yml` |

## Migration Path

1. Complete `netranger-db` migration and verify role/channel significance mappings.
2. Configure Discord OAuth callback for `/login_callback`.
3. Configure `OAUTH2_CLIENT_ID`, `OAUTH2_CLIENT_SECRET`, `BOT_TOKEN`, `GUILD_ID`, `DB_*`, and `SECRET_KEY`.
4. Deploy `netranger-web` from `v2dev`.
5. Verify public routes: `/`, `/rules`, `/events`, `/linkedin`, `/survey-dec2021`.
6. Verify OAuth login and callback with the production redirect URI.
7. Verify `/join` for Member, periphery, and recruiter users.
8. Verify full Members receive member numbers in MariaDB.
9. Verify `/members`, `/myprofile`, and `/members/<id>` with a migrated Member user.

## Acceptance Criteria

- Public routes render without live Discord calls.
- OAuth callback rejects invalid state and external redirect targets.
- `/join` requires `guilds.join` scope.
- Member join persists accepted role, first-joined timestamp, and member number before Discord guild sync.
- Existing guild members have roles synchronized without requiring a member-join event.
- Discord OAuth access token is removed from the session after successful join; refresh token is not stored.
- Docker image builds successfully.
- `pytest` and `ruff check .` pass.

## Audit Notes

- Fixed during audit: Dockerfile now copies package code before `pip install .`.
- Fixed during audit: full Member number assignment now happens in the web join path.
- Fixed during audit: OAuth refresh tokens are not stored and access tokens are cleared after successful join.
- Fixed during audit: test import ordering now satisfies ruff.
