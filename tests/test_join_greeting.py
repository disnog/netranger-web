# tests/test_join_greeting.py
# The welcome announcement web posts to the DB-mapped greeting channel.

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tests.test_views import _make_signed_cookie

USER_ID = "111222333"


def _fake_db(*, roles, member_number, channels):
    """A netranger-db stand-in. ``channels`` maps significance -> channel id."""
    db_user = SimpleNamespace(permanent_roles=roles, member_number=member_number)
    db = MagicMock()
    db.users.upsert = AsyncMock()
    db.users.add_permanent_role = AsyncMock()
    db.users.assign_member_number = AsyncMock(return_value=member_number)
    db.users.get = AsyncMock(return_value=db_user)
    db.guilds.get_role_by_significance = AsyncMock(
        side_effect=lambda _guild, sig: SimpleNamespace(role_id=f"role-{sig}")
    )

    async def _channel(_guild, sig):
        if sig in channels:
            return SimpleNamespace(channel_id=channels[sig], significance=sig)
        return None

    db.guilds.get_channel_by_significance = AsyncMock(side_effect=_channel)
    return db


def _run_join(client, app, session, fake_db, *, status, member_roles=(), post=None):
    """Drive /join with Discord and the database mocked. Returns (resp, api)."""
    session.csrf_token = "csrf-token"
    client.set_cookie("nrweb_session", _make_signed_cookie(app, session))

    def run_db_query(coro_factory):
        return asyncio.run(coro_factory(fake_db))

    with patch("nrweb.views.db_query", side_effect=run_db_query), \
         patch("nrweb.views.get_settings") as mock_settings, \
         patch("nrweb.views.DiscordAPI") as MockAPI:
        mock_settings.return_value.guild_id = "123456789"
        api = MockAPI.return_value
        api.add_guild_member.return_value = (status == 201, status)
        api.get_guild_member.return_value = {"roles": list(member_roles)}
        api.create_webhook.return_value = {"id": "wh-1", "token": "wh-tok"}
        if post:
            resp = client.post("/join", data={"csrf_token": "csrf-token", **post})
        else:
            resp = client.get("/join")
    return resp, api


MEMBER_FORM = {
    "userclass": "Member",
    "accept_general_rules": "on",
    "accept_member_rules": "on",
}


def test_new_member_is_announced_in_greeting_channel(client, app, logged_in_session):
    fake_db = _fake_db(roles=["Member"], member_number=12, channels={"greeting": "chan-g"})

    resp, api = _run_join(client, app, logged_in_session, fake_db, status=201, post=MEMBER_FORM)

    assert resp.status_code == 302
    api.create_webhook.assert_called_once_with("chan-g", "DisNOG.org")
    content = api.execute_webhook.call_args.args[2]
    assert content.startswith(f"Welcome <@{USER_ID}>, member #12!")
    api.delete_webhook.assert_called_once_with("wh-1", "wh-tok")


def test_new_periphery_user_is_announced_in_periphery_greeting(client, app, logged_in_session):
    fake_db = _fake_db(
        roles=["periphery"],
        member_number=None,
        channels={"greeting": "chan-g", "periphery_greeting": "chan-p"},
    )
    form = {"userclass": "periphery", "accept_general_rules": "on"}

    resp, api = _run_join(client, app, logged_in_session, fake_db, status=201, post=form)

    assert resp.status_code == 302
    api.create_webhook.assert_called_once_with("chan-p", "DisNOG.org")
    content = api.execute_webhook.call_args.args[2]
    assert content.startswith(f"Welcome <@{USER_ID}>!")
    assert "member #" not in content


def test_recruiter_is_announced_in_greeting_channel(client, app, logged_in_session):
    fake_db = _fake_db(
        roles=["recruiter"],
        member_number=None,
        channels={"greeting": "chan-g", "periphery_greeting": "chan-p"},
    )

    _resp, api = _run_join(client, app, logged_in_session, fake_db, status=201)

    api.create_webhook.assert_called_once_with("chan-g", "DisNOG.org")


def test_user_already_in_guild_is_announced_when_role_is_new(client, app, logged_in_session):
    """The common path: joined by invite, waited in #welcome, then accepted on web."""
    fake_db = _fake_db(roles=["Member"], member_number=13, channels={"greeting": "chan-g"})

    resp, api = _run_join(
        client, app, logged_in_session, fake_db, status=204, member_roles=[], post=MEMBER_FORM
    )

    assert resp.status_code == 302
    api.add_member_role.assert_called_once_with("123456789", USER_ID, "role-Member")
    api.create_webhook.assert_called_once_with("chan-g", "DisNOG.org")
    assert "member #13" in api.execute_webhook.call_args.args[2]


def test_user_who_already_has_role_is_not_announced_again(client, app, logged_in_session):
    fake_db = _fake_db(roles=["Member"], member_number=14, channels={"greeting": "chan-g"})

    resp, api = _run_join(
        client, app, logged_in_session, fake_db, status=204, member_roles=["role-Member"]
    )

    assert resp.status_code == 302
    api.add_member_role.assert_not_called()
    api.create_webhook.assert_not_called()


def test_missing_greeting_channel_skips_welcome_but_join_succeeds(client, app, logged_in_session):
    fake_db = _fake_db(roles=["Member"], member_number=15, channels={})

    resp, api = _run_join(client, app, logged_in_session, fake_db, status=201, post=MEMBER_FORM)

    assert resp.status_code == 302
    api.create_webhook.assert_not_called()


def test_webhook_failure_does_not_fail_join(client, app, logged_in_session):
    fake_db = _fake_db(roles=["Member"], member_number=16, channels={"greeting": "chan-g"})
    session = logged_in_session
    session.csrf_token = "csrf-token"
    client.set_cookie("nrweb_session", _make_signed_cookie(app, session))

    with patch("nrweb.views.db_query", side_effect=lambda f: asyncio.run(f(fake_db))), \
         patch("nrweb.views.get_settings") as mock_settings, \
         patch("nrweb.views.DiscordAPI") as MockAPI:
        mock_settings.return_value.guild_id = "123456789"
        api = MockAPI.return_value
        api.add_guild_member.return_value = (True, 201)
        api.create_webhook.return_value = {"id": "wh-1", "token": "wh-tok"}
        api.execute_webhook.side_effect = RuntimeError("discord down")

        resp = client.get("/join")

    assert resp.status_code == 302
    api.delete_webhook.assert_called_once_with("wh-1", "wh-tok")


@pytest.mark.parametrize(
    ("roles", "expected"),
    [
        (["Member"], "greeting"),
        (["recruiter"], "greeting"),
        (["Member", "periphery"], "greeting"),
        (["periphery"], "periphery_greeting"),
        (["eggs"], None),
        ([], None),
    ],
)
def test_greeting_channel_significance(roles, expected):
    from nrweb.views import _greeting_channel_significance

    assert _greeting_channel_significance(roles) == expected


def test_sync_roles_adds_only_missing_roles(app):
    from nrweb.views import _sync_roles

    with patch("nrweb.views.DiscordAPI") as MockAPI:
        api = MockAPI.return_value
        api.get_guild_member.return_value = {"roles": ["r1"]}

        added = _sync_roles("g", "u", ["r1", "r2"])

    assert added == 1
    api.add_member_role.assert_called_once_with("g", "u", "r2")
