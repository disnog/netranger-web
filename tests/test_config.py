# tests/test_config.py
# Unit tests for nrweb/config.py.

from __future__ import annotations

import pytest

import nrweb.config as config_module
from nrweb.config import Settings, get_settings


# ---------------------------------------------------------------------------
# Settings.from_env()
# ---------------------------------------------------------------------------

def test_from_env_loads_required_fields(monkeypatch):
    monkeypatch.setenv("OAUTH2_CLIENT_ID", "my-client")
    monkeypatch.setenv("OAUTH2_CLIENT_SECRET", "my-secret")
    config_module.settings = None

    s = Settings.from_env()

    assert s.oauth2_client_id == "my-client"
    assert s.oauth2_client_secret == "my-secret"


def test_from_env_raises_on_missing_client_id(monkeypatch):
    monkeypatch.delenv("OAUTH2_CLIENT_ID", raising=False)
    monkeypatch.setenv("OAUTH2_CLIENT_SECRET", "secret")

    with pytest.raises(KeyError):
        Settings.from_env()


def test_from_env_raises_on_missing_client_secret(monkeypatch):
    monkeypatch.setenv("OAUTH2_CLIENT_ID", "id")
    monkeypatch.delenv("OAUTH2_CLIENT_SECRET", raising=False)

    with pytest.raises(KeyError):
        Settings.from_env()


def test_from_env_optional_fields_have_defaults(monkeypatch):
    monkeypatch.setenv("OAUTH2_CLIENT_ID", "id")
    monkeypatch.setenv("OAUTH2_CLIENT_SECRET", "secret")
    monkeypatch.delenv("BOT_TOKEN", raising=False)
    monkeypatch.delenv("GUILD_ID", raising=False)

    s = Settings.from_env()

    assert s.bot_token == ""
    assert s.guild_id == ""
    assert s.environment == "prod"
    assert s.debug is False
    assert s.api_base_url == "https://discord.com/api/v10"


def test_from_env_debug_flag(monkeypatch):
    monkeypatch.setenv("OAUTH2_CLIENT_ID", "id")
    monkeypatch.setenv("OAUTH2_CLIENT_SECRET", "secret")
    monkeypatch.setenv("DEBUG", "true")

    s = Settings.from_env()

    assert s.debug is True


def test_from_env_environment_lowercased(monkeypatch):
    monkeypatch.setenv("OAUTH2_CLIENT_ID", "id")
    monkeypatch.setenv("OAUTH2_CLIENT_SECRET", "secret")
    monkeypatch.setenv("NRWEB_ENVIRONMENT", "DEV")

    s = Settings.from_env()

    assert s.environment == "dev"


def test_from_env_secret_key_falls_back_to_client_secret(monkeypatch):
    monkeypatch.setenv("OAUTH2_CLIENT_ID", "id")
    monkeypatch.setenv("OAUTH2_CLIENT_SECRET", "fallback-secret")
    monkeypatch.delenv("SECRET_KEY", raising=False)

    s = Settings.from_env()

    assert s.secret_key == "fallback-secret"


def test_from_env_custom_redirect_uri(monkeypatch):
    monkeypatch.setenv("OAUTH2_CLIENT_ID", "id")
    monkeypatch.setenv("OAUTH2_CLIENT_SECRET", "secret")
    monkeypatch.setenv("OAUTH2_REDIRECT_URI", "https://example.com/callback")

    s = Settings.from_env()

    assert s.oauth2_redirect_uri == "https://example.com/callback"


# ---------------------------------------------------------------------------
# Settings properties
# ---------------------------------------------------------------------------

def test_authorization_url_property():
    s = Settings(
        oauth2_client_id="id",
        oauth2_client_secret="secret",
        api_base_url="https://discord.com/api/v10",
    )

    assert s.authorization_url == "https://discord.com/api/v10/oauth2/authorize"


def test_token_url_property():
    s = Settings(
        oauth2_client_id="id",
        oauth2_client_secret="secret",
        api_base_url="https://discord.com/api/v10",
    )

    assert s.token_url == "https://discord.com/api/v10/oauth2/token"


def test_custom_api_base_url():
    s = Settings(
        oauth2_client_id="id",
        oauth2_client_secret="secret",
        api_base_url="https://ptb.discord.com/api/v10",
    )

    assert "ptb.discord.com" in s.authorization_url


# ---------------------------------------------------------------------------
# get_settings() singleton
# ---------------------------------------------------------------------------

def test_get_settings_returns_same_instance():
    config_module.settings = None
    s1 = get_settings()
    s2 = get_settings()

    assert s1 is s2


def test_get_settings_initializes_from_env(monkeypatch):
    config_module.settings = None
    monkeypatch.setenv("OAUTH2_CLIENT_ID", "singleton-test")
    monkeypatch.setenv("OAUTH2_CLIENT_SECRET", "singleton-secret")

    s = get_settings()

    assert s.oauth2_client_id == "singleton-test"
