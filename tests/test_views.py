# tests/test_views.py
# Integration tests for Flask views using pytest-flask.

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nrweb.session import SessionData, SessionManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_signed_cookie(app, session_data: SessionData) -> str:
    """Produce a signed session cookie value for use in test requests."""
    from itsdangerous import URLSafeTimedSerializer
    from nrweb.config import get_settings
    s = URLSafeTimedSerializer(get_settings().secret_key)
    return s.dumps(session_data.to_dict())


# ---------------------------------------------------------------------------
# Public routes (no login required)
# ---------------------------------------------------------------------------

def test_home_route_renders(client):
    with patch("nrweb.views.db_query") as mock_db:
        mock_db.return_value = (5, 3, 1)
        resp = client.get("/home")
    assert resp.status_code == 200


def test_root_redirects_to_home_or_renders(client):
    with patch("nrweb.views.db_query") as mock_db:
        mock_db.return_value = (5, 3, 1)
        resp = client.get("/")
    assert resp.status_code in (200, 302)


def test_rules_route(client):
    resp = client.get("/rules")
    assert resp.status_code == 200


def test_events_route(client):
    resp = client.get("/events")
    assert resp.status_code == 200


def test_linkedin_redirects(client):
    resp = client.get("/linkedin")
    assert resp.status_code == 303
    assert "linkedin.com" in resp.headers["Location"]


def test_survey_redirects(client):
    resp = client.get("/survey-dec2021")
    assert resp.status_code == 303
    assert "google.com" in resp.headers["Location"]


# ---------------------------------------------------------------------------
# Login flow
# ---------------------------------------------------------------------------

def test_login_redirects_to_discord(client):
    with patch("nrweb.views.DiscordOAuth") as MockOAuth:
        instance = MockOAuth.return_value
        instance.get_authorization_url.return_value = (
            "https://discord.com/oauth2/authorize?...", "test-state"
        )
        resp = client.get("/login")

    assert resp.status_code == 302
    assert "discord.com" in resp.headers["Location"]


def test_login_callback_error_param_redirects_home(client, app):
    resp = client.get("/login_callback?error=access_denied")
    assert resp.status_code == 302
    assert "/home" in resp.headers["Location"] or "/" in resp.headers["Location"]


def test_login_callback_invalid_state_redirects_login(client, app):
    resp = client.get("/login_callback?state=wrong&code=abc")
    assert resp.status_code == 302


def test_logout_clears_session(client, app):
    resp = client.get("/logout")
    assert resp.status_code == 302


# ---------------------------------------------------------------------------
# requires_login decorator
# ---------------------------------------------------------------------------

def test_myprofile_redirects_anonymous(client):
    resp = client.get("/myprofile")
    assert resp.status_code == 302
    assert "login" in resp.headers["Location"]


def test_myprofile_accessible_when_logged_in(client, app, logged_in_session):
    cookie_val = _make_signed_cookie(app, logged_in_session)
    db_user = MagicMock()
    db_user.permanent_roles = ["Member"]

    with patch("nrweb.views.db_query", return_value=db_user), \
         patch("nrweb.views.DiscordAPI") as MockAPI:
        instance = MockAPI.return_value
        instance.get_user.return_value = {"id": "111222333", "username": "testuser"}

        resp = client.get(
            "/myprofile",
            headers={"Cookie": f"nrweb_session={cookie_val}"},
        )

    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# requires_member decorator
# ---------------------------------------------------------------------------

def test_members_route_forbidden_for_non_member(client, app, logged_in_session):
    cookie_val = _make_signed_cookie(app, logged_in_session)
    db_user = MagicMock()
    db_user.permanent_roles = ["periphery"]

    with patch("nrweb.views.db_query", return_value=db_user):
        resp = client.get(
            "/members",
            headers={"Cookie": f"nrweb_session={cookie_val}"},
        )

    assert resp.status_code == 403


def test_members_route_accessible_for_member(client, app, logged_in_session):
    cookie_val = _make_signed_cookie(app, logged_in_session)
    db_user = MagicMock()
    db_user.permanent_roles = ["Member"]

    def mock_db_query(coro):
        # First call: requires_member check; second call: list_members
        return db_user if not hasattr(mock_db_query, "_called") else []

    with patch("nrweb.views.db_query") as mock_db:
        mock_db.side_effect = [db_user, []]

        resp = client.get(
            "/members",
            headers={"Cookie": f"nrweb_session={cookie_val}"},
        )

    assert resp.status_code == 200


def test_profile_not_found_returns_404(client, app, logged_in_session):
    cookie_val = _make_signed_cookie(app, logged_in_session)
    db_user_member = MagicMock()
    db_user_member.permanent_roles = ["Member"]

    with patch("nrweb.views.db_query") as mock_db:
        mock_db.side_effect = [db_user_member, None]  # member check passes, profile not found

        resp = client.get(
            "/members/99999",
            headers={"Cookie": f"nrweb_session={cookie_val}"},
        )

    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Join form
# ---------------------------------------------------------------------------

def test_join_redirects_anonymous_to_login(client):
    resp = client.get("/join")
    assert resp.status_code == 302
    assert "login" in resp.headers["Location"]


def test_join_redirects_without_guilds_join_scope(client, app):
    session = SessionData(
        user_id="111",
        username="alice",
        access_token="tok",
        token_scope="identify",  # no guilds.join
    )
    cookie_val = _make_signed_cookie(app, session)

    resp = client.get(
        "/join",
        headers={"Cookie": f"nrweb_session={cookie_val}"},
    )

    assert resp.status_code == 302
    assert "login" in resp.headers["Location"]


def test_join_shows_form_for_new_user(client, app, logged_in_session):
    cookie_val = _make_signed_cookie(app, logged_in_session)

    with patch("nrweb.views.db_query", return_value=None), \
         patch("nrweb.views.get_settings") as mock_settings:
        mock_settings.return_value.guild_id = "123456789"

        resp = client.get(
            "/join",
            headers={"Cookie": f"nrweb_session={cookie_val}"},
        )

    assert resp.status_code == 200
    assert b"join" in resp.data.lower() or b"userclass" in resp.data.lower()


def test_join_post_missing_csrf_redirects(client, app, logged_in_session):
    cookie_val = _make_signed_cookie(app, logged_in_session)

    resp = client.post(
        "/join",
        data={"userclass": "Member", "accept_general_rules": "on"},
        headers={"Cookie": f"nrweb_session={cookie_val}"},
    )

    assert resp.status_code == 302
