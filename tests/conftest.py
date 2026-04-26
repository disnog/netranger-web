# tests/conftest.py
# Shared fixtures for netranger-web tests.
#
# IMPORTANT: env vars must be set before nrweb is imported, because
# nrweb/__init__.py calls get_settings() at module-load time.

from __future__ import annotations

import os

# Set required env vars before any nrweb imports.
os.environ.setdefault("OAUTH2_CLIENT_ID", "test-client-id")
os.environ.setdefault("OAUTH2_CLIENT_SECRET", "test-client-secret-that-is-long-enough")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-signing-cookies")
os.environ.setdefault("BOT_TOKEN", "test-bot-token")
os.environ.setdefault("GUILD_ID", "123456789")

import pytest

import nrweb.config as config_module
from nrweb.session import SessionData


@pytest.fixture(autouse=True)
def reset_settings_singleton():
    """Reset the settings singleton between tests."""
    original = config_module.settings
    yield
    config_module.settings = original


@pytest.fixture
def app():
    from nrweb import app as flask_app
    flask_app.config["TESTING"] = True
    flask_app.config["WTF_CSRF_ENABLED"] = False
    with flask_app.app_context():
        yield flask_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def logged_in_session():
    """A SessionData that is fully authenticated."""
    return SessionData(
        user_id="111222333",
        username="testuser",
        discriminator="0001",
        avatar="abc123",
        access_token="fake-access-token",
        token_scope="identify guilds.join",
    )


@pytest.fixture
def anonymous_session():
    return SessionData()
