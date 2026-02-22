# tests/test_discord_client.py
# Unit tests for nrweb/discord_client.py.

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from nrweb.discord_client import DiscordAPI, DiscordOAuth, DiscordToken, DiscordUser

# ---------------------------------------------------------------------------
# DiscordUser
# ---------------------------------------------------------------------------

def test_discord_user_display_name_legacy():
    user = DiscordUser(id="1", username="alice", discriminator="1234")
    assert user.display_name == "alice#1234"


def test_discord_user_display_name_new_system():
    user = DiscordUser(id="1", username="alice", discriminator="0")
    assert user.display_name == "alice"


def test_discord_user_display_name_no_discriminator():
    user = DiscordUser(id="1", username="alice", discriminator=None)
    assert user.display_name == "alice"


def test_discord_user_avatar_url_custom():
    user = DiscordUser(id="123456789", username="alice", discriminator="0", avatar="abcdef")
    assert user.avatar_url == "https://cdn.discordapp.com/avatars/123456789/abcdef.png"


def test_discord_user_avatar_url_default():
    user = DiscordUser(id="0", username="alice", discriminator="0", avatar=None)
    assert "embed/avatars" in user.avatar_url


# ---------------------------------------------------------------------------
# DiscordToken
# ---------------------------------------------------------------------------

def test_discord_token_scopes_split():
    token = DiscordToken(
        access_token="tok",
        token_type="Bearer",
        expires_in=604800,
        refresh_token="ref",
        scope="identify guilds.join",
    )
    assert "identify" in token.scopes
    assert "guilds.join" in token.scopes


def test_discord_token_single_scope():
    token = DiscordToken(
        access_token="t",
        token_type="Bearer",
        expires_in=3600,
        refresh_token="r",
        scope="identify",
    )
    assert token.scopes == ["identify"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(json_data, status_code=200):
    """Build a mock httpx.Response."""
    resp = MagicMock(spec=httpx.Response)
    resp.json.return_value = json_data
    resp.status_code = status_code
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Error", request=MagicMock(), response=resp
        )
    return resp


SAMPLE_TOKEN_RESPONSE = {
    "access_token": "access-abc",
    "token_type": "Bearer",
    "expires_in": 604800,
    "refresh_token": "refresh-xyz",
    "scope": "identify guilds.join",
}

SAMPLE_USER_RESPONSE = {
    "id": "111222333",
    "username": "testuser",
    "discriminator": "0",
    "avatar": "hash123",
}


# ---------------------------------------------------------------------------
# DiscordOAuth
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_oauth_settings():
    with patch("nrweb.discord_client.get_settings") as mock_settings:
        mock_settings.return_value.oauth2_client_id = "client-id"
        mock_settings.return_value.oauth2_client_secret = "client-secret"
        mock_settings.return_value.oauth2_redirect_uri = "https://example.com/callback"
        mock_settings.return_value.api_base_url = "https://discord.com/api/v10"
        mock_settings.return_value.authorization_url = "https://discord.com/api/v10/oauth2/authorize"
        mock_settings.return_value.token_url = "https://discord.com/api/v10/oauth2/token"
        yield mock_settings.return_value


def test_get_authorization_url_returns_url_and_state(mock_oauth_settings):
    oauth = DiscordOAuth()
    url, state = oauth.get_authorization_url(scope="identify")
    oauth.close()

    assert "discord.com" in url
    assert "client_id=client-id" in url
    assert "identify" in url
    assert len(state) > 10


def test_get_authorization_url_custom_state(mock_oauth_settings):
    oauth = DiscordOAuth()
    url, state = oauth.get_authorization_url(scope="identify", state="my-state")
    oauth.close()

    assert state == "my-state"
    assert "state=my-state" in url


def test_exchange_code_returns_token(mock_oauth_settings):
    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.post.return_value = _make_response(SAMPLE_TOKEN_RESPONSE)

        oauth = DiscordOAuth()
        token = oauth.exchange_code("auth-code")
        oauth.close()

    assert token.access_token == "access-abc"
    assert token.refresh_token == "refresh-xyz"
    assert "guilds.join" in token.scopes


def test_exchange_code_raises_on_http_error(mock_oauth_settings):
    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.post.return_value = _make_response({}, status_code=401)

        oauth = DiscordOAuth()
        with pytest.raises(httpx.HTTPStatusError):
            oauth.exchange_code("bad-code")
        oauth.close()


def test_get_user_returns_discord_user(mock_oauth_settings):
    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.get.return_value = _make_response(SAMPLE_USER_RESPONSE)

        token = DiscordToken(**SAMPLE_TOKEN_RESPONSE)
        oauth = DiscordOAuth()
        user = oauth.get_user(token)
        oauth.close()

    assert user.id == "111222333"
    assert user.username == "testuser"
    assert user.avatar == "hash123"


# ---------------------------------------------------------------------------
# DiscordAPI
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_api_settings():
    with patch("nrweb.discord_client.get_settings") as mock_settings:
        mock_settings.return_value.bot_token = "bot-token"
        mock_settings.return_value.api_base_url = "https://discord.com/api/v10"
        yield mock_settings.return_value


def test_get_guild_member_found(mock_api_settings):
    member_data = {"user": {"id": "111"}, "roles": ["role1"]}
    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.get.return_value = _make_response(member_data)

        api = DiscordAPI()
        result = api.get_guild_member("guild-1", "user-1")
        api.close()

    assert result == member_data


def test_get_guild_member_not_found(mock_api_settings):
    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        resp = _make_response({}, status_code=404)
        resp.raise_for_status = MagicMock()  # 404 is handled, not raised
        mock_client.get.return_value = resp

        api = DiscordAPI()
        result = api.get_guild_member("guild-1", "missing-user")
        api.close()

    assert result is None


def test_add_guild_member_returns_true_for_201(mock_api_settings):
    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        resp = _make_response({}, status_code=201)
        resp.raise_for_status = MagicMock()
        mock_client.put.return_value = resp

        api = DiscordAPI()
        was_added, status = api.add_guild_member("g", "u", "tok", ["r1"])
        api.close()

    assert was_added is True
    assert status == 201


def test_add_guild_member_returns_false_for_204(mock_api_settings):
    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        resp = _make_response({}, status_code=204)
        resp.raise_for_status = MagicMock()
        mock_client.put.return_value = resp

        api = DiscordAPI()
        was_added, status = api.add_guild_member("g", "u", "tok")
        api.close()

    assert was_added is False
    assert status == 204


def test_api_authorization_header_uses_bot_prefix(mock_api_settings):
    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.get.return_value = _make_response(SAMPLE_USER_RESPONSE)

        api = DiscordAPI()
        api.get_user("111")
        api.close()

    call_kwargs = mock_client.get.call_args[1]
    assert call_kwargs["headers"]["Authorization"] == "Bot bot-token"


def test_add_member_role_calls_put(mock_api_settings):
    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.put.return_value = _make_response({}, status_code=204)

        api = DiscordAPI()
        api.add_member_role("guild-1", "user-1", "role-1")
        api.close()

    mock_client.put.assert_called_once()
    url = mock_client.put.call_args[0][0]
    assert "guild-1" in url
    assert "user-1" in url
    assert "role-1" in url


def test_create_and_delete_webhook(mock_api_settings):
    webhook_data = {"id": "wh-id", "token": "wh-tok"}
    with patch("httpx.Client") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.post.return_value = _make_response(webhook_data)
        mock_client.delete.return_value = _make_response({}, status_code=204)

        api = DiscordAPI()
        result = api.create_webhook("channel-1", "MyBot")
        api.delete_webhook("wh-id", "wh-tok")
        api.close()

    assert result["id"] == "wh-id"
    mock_client.delete.assert_called_once()
