# tests/test_session.py
# Unit tests for nrweb/session.py.

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from nrweb.session import (
    SessionData,
    SessionManager,
    flash,
    generate_csrf_token,
    get_flashed_messages,
    validate_csrf_token,
)

# ---------------------------------------------------------------------------
# SessionData properties
# ---------------------------------------------------------------------------

def test_is_logged_in_true(logged_in_session):
    assert logged_in_session.is_logged_in is True


def test_is_logged_in_false_no_user_id(anonymous_session):
    assert anonymous_session.is_logged_in is False


def test_is_logged_in_requires_both_user_id_and_access_token():
    s = SessionData(user_id="123", access_token=None)
    assert s.is_logged_in is False

    s2 = SessionData(user_id=None, access_token="tok")
    assert s2.is_logged_in is False


def test_has_guilds_join_scope_true(logged_in_session):
    assert logged_in_session.has_guilds_join_scope is True


def test_has_guilds_join_scope_false_identify_only():
    s = SessionData(token_scope="identify")
    assert s.has_guilds_join_scope is False


def test_has_guilds_join_scope_false_no_scope():
    s = SessionData(token_scope=None)
    assert s.has_guilds_join_scope is False


def test_flash_messages_default_empty():
    s = SessionData()
    assert s.flash_messages == []


def test_flash_messages_not_shared_between_instances():
    s1 = SessionData()
    s2 = SessionData()
    s1.flash_messages.append({"message": "hi", "category": "info"})
    assert s2.flash_messages == []


# ---------------------------------------------------------------------------
# SessionData serialization
# ---------------------------------------------------------------------------

def test_to_dict_roundtrip(logged_in_session):
    d = logged_in_session.to_dict()
    restored = SessionData.from_dict(d)

    assert restored.user_id == logged_in_session.user_id
    assert restored.username == logged_in_session.username
    assert restored.access_token == logged_in_session.access_token
    assert restored.token_scope == logged_in_session.token_scope


def test_from_dict_ignores_unknown_keys():
    data = {
        "user_id": "123",
        "username": "alice",
        "unknown_field": "should be ignored",
        "flash_messages": [],
    }
    s = SessionData.from_dict(data)
    assert s.user_id == "123"


def test_from_dict_empty():
    s = SessionData.from_dict({})
    assert s.user_id is None
    assert s.is_logged_in is False


# ---------------------------------------------------------------------------
# SessionManager
# ---------------------------------------------------------------------------

@pytest.fixture
def session_mgr():
    with patch("nrweb.session.get_settings") as mock_settings:
        mock_settings.return_value.secret_key = "test-secret"
        mock_settings.return_value.environment = "dev"
        return SessionManager()


def test_session_manager_get_empty_cookie(session_mgr, app):
    with app.test_request_context("/"):
        # No cookie present -> empty SessionData
        mock_req = MagicMock()
        mock_req.cookies = {}
        result = session_mgr.get_session(req=mock_req)
        assert isinstance(result, SessionData)
        assert result.is_logged_in is False


def test_session_manager_roundtrip(session_mgr, app):
    """Signed cookie can be written and read back."""
    session = SessionData(user_id="999", username="alice", access_token="tok")

    with app.test_request_context("/"):
        mock_response = MagicMock()
        session_mgr.set_session(mock_response, session)
        # Extract cookie value from the set_cookie call
        call_args = mock_response.set_cookie.call_args
        cookie_value = call_args[0][1]  # second positional arg

    # Now read it back
    mock_req = MagicMock()
    mock_req.cookies = {SessionManager.COOKIE_NAME: cookie_value}
    restored = session_mgr.get_session(req=mock_req)

    assert restored.user_id == "999"
    assert restored.username == "alice"


def test_session_manager_rejects_invalid_signature(session_mgr):
    mock_req = MagicMock()
    mock_req.cookies = {SessionManager.COOKIE_NAME: "invalid.cookie.value"}

    result = session_mgr.get_session(req=mock_req)

    assert isinstance(result, SessionData)
    assert result.user_id is None


def test_session_manager_clear_deletes_cookie(session_mgr, app):
    with app.test_request_context("/"):
        mock_response = MagicMock()
        session_mgr.clear_session(mock_response)
        mock_response.delete_cookie.assert_called_once_with(SessionManager.COOKIE_NAME)


def test_session_manager_set_cookie_flags_prod(app):
    with patch("nrweb.session.get_settings") as mock_settings:
        mock_settings.return_value.secret_key = "secret"
        mock_settings.return_value.environment = "prod"
        mgr = SessionManager()

        session = SessionData(user_id="1", access_token="t")
        mock_response = MagicMock()
        with app.test_request_context("/"):
            mgr.set_session(mock_response, session)

        kwargs = mock_response.set_cookie.call_args[1]
        assert kwargs["httponly"] is True
        assert kwargs["samesite"] == "lax"
        assert kwargs["secure"] is True


def test_session_manager_set_cookie_flags_dev(app):
    with patch("nrweb.session.get_settings") as mock_settings:
        mock_settings.return_value.secret_key = "secret"
        mock_settings.return_value.environment = "dev"
        mgr = SessionManager()

        session = SessionData(user_id="1", access_token="t")
        mock_response = MagicMock()
        with app.test_request_context("/"):
            mgr.set_session(mock_response, session)

        kwargs = mock_response.set_cookie.call_args[1]
        assert kwargs["secure"] is False


# ---------------------------------------------------------------------------
# flash() / get_flashed_messages()
# ---------------------------------------------------------------------------

def test_flash_adds_message():
    s = SessionData()
    flash(s, "Hello!", "success")

    assert len(s.flash_messages) == 1
    assert s.flash_messages[0] == {"message": "Hello!", "category": "success"}


def test_flash_default_category_info():
    s = SessionData()
    flash(s, "A message")

    assert s.flash_messages[0]["category"] == "info"


def test_get_flashed_messages_returns_and_clears():
    s = SessionData()
    flash(s, "msg1", "info")
    flash(s, "msg2", "danger")

    messages = get_flashed_messages(s)

    assert len(messages) == 2
    assert s.flash_messages == []  # cleared


def test_get_flashed_messages_empty():
    s = SessionData()
    messages = get_flashed_messages(s)
    assert messages == []


# ---------------------------------------------------------------------------
# generate_csrf_token() / validate_csrf_token()
# ---------------------------------------------------------------------------

def test_generate_csrf_token_stores_in_session():
    s = SessionData()
    token = generate_csrf_token(s)

    assert s.csrf_token == token
    assert len(token) > 20


def test_validate_csrf_token_correct():
    s = SessionData()
    token = generate_csrf_token(s)

    assert validate_csrf_token(s, token) is True


def test_validate_csrf_token_wrong():
    s = SessionData()
    generate_csrf_token(s)

    assert validate_csrf_token(s, "wrong-token") is False


def test_validate_csrf_token_empty_session():
    s = SessionData()  # no csrf_token set

    assert validate_csrf_token(s, "any-token") is False


def test_validate_csrf_token_empty_string():
    s = SessionData()
    generate_csrf_token(s)

    assert validate_csrf_token(s, "") is False


def test_generate_csrf_token_is_unique():
    s = SessionData()
    t1 = generate_csrf_token(s)
    t2 = generate_csrf_token(s)

    assert t1 != t2
