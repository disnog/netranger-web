# views.py
# Copyright (C) 2020-2026 DisNOG.org
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Flask route handlers for the netranger web portal."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from functools import wraps
from typing import Any
from urllib.parse import urlsplit

import httpx
from flask import abort, g, redirect, render_template, request, url_for
from netranger_db import Database

from nrweb import app

from .config import get_settings
from .discord_client import DiscordAPI, DiscordOAuth, DiscordUser
from .session import (
    SessionData,
    SessionManager,
    generate_csrf_token,
    get_flashed_messages,
    validate_csrf_token,
)
from .session import (
    flash as session_flash,
)

_session_mgr = SessionManager()

USERCLASS_CHOICES = [
    ("Member", "Enterprise networking, enterprise wifi, and VOIP"),
    ("Member", "Network automation and DevOps"),
    ("Member", "Service provider networking, BGP, and MPLS"),
    ("Member", "I'm a student studying for enterprise or service provider networking"),
    ("periphery", "Home routers, wifi, servers, computers, and peripherals"),
    ("periphery", "General business or enterprise IT, server administration, or coding"),
    ("recruiter", "Posting network engineering jobs I'm hoping to fill"),
]


def _normalize_local_redirect_target(target: str | None) -> str | None:
    """Accept only app-local redirect targets."""
    if not target:
        return None

    candidate = target.strip()
    if not candidate or candidate.startswith("//"):
        return None

    parsed = urlsplit(candidate)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        return None
    if not parsed.path.startswith("/"):
        return None

    normalized = parsed.path
    if parsed.query:
        normalized = f"{normalized}?{parsed.query}"
    return normalized


def _current_request_target() -> str:
    """Build the current request target as an app-local path."""
    if not request.query_string:
        return request.path
    return f"{request.path}?{request.query_string.decode()}"


def db_query(coro_factory) -> Any:
    """Run an async netranger-db coroutine from sync Flask context."""
    async def _run():
        db = Database.from_env()
        await db.connect()
        try:
            return await coro_factory(db)
        finally:
            await db.close()
    return asyncio.run(_run())


@app.before_request
def load_session() -> None:
    g.session_data = _session_mgr.get_session()


@app.after_request
def save_session(response):
    _session_mgr.set_session(response, g.session_data)
    return response


@app.context_processor
def inject_session():
    session_data: SessionData = g.get("session_data", SessionData())
    flashed = get_flashed_messages(session_data)
    user = None
    if session_data.is_logged_in:
        user = DiscordUser(
            id=session_data.user_id,
            username=session_data.username or "",
            discriminator=session_data.discriminator or "0",
            avatar=session_data.avatar,
        )
    return {
        "session": session_data,
        "user": user,
        "flashed_messages": flashed,
    }


def requires_login(f):
    """Decorator: redirect to login if not authenticated."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not g.session_data.is_logged_in:
            g.session_data.post_login_url = _current_request_target()
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def requires_member(f):
    """Decorator: require Member permanent role in DB."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not g.session_data.is_logged_in:
            g.session_data.post_login_url = _current_request_target()
            return redirect(url_for("login"))
        user_id = int(g.session_data.user_id)
        db_user = db_query(lambda db: db.users.get(user_id))
        if not db_user or "Member" not in db_user.permanent_roles:
            abort(403)
        return f(*args, **kwargs)
    return wrapper


@app.route("/")
@app.route("/home")
def home():
    async def _counts(db):
        return (
            await db.users.count_by_role("Member"),
            await db.users.count_by_role("periphery"),
            await db.users.count_by_role("recruiter"),
        )
    member_count, periphery_count, recruiter_count = db_query(_counts)
    return render_template(
        "home.html",
        member_count=member_count,
        periphery_count=periphery_count,
        recruiter_count=recruiter_count,
    )


@app.route("/rules")
def rules():
    return render_template("rules.html")


@app.route("/events")
def events():
    return render_template("events.html")


@app.route("/linkedin")
def linkedin():
    return redirect("https://www.linkedin.com/groups/9073282", 303)


@app.route("/survey-dec2021")
def survey():
    return redirect(
        "https://docs.google.com/forms/d/e/1FAIpQLSeDHriZMhVDvz9aa74Y4x4Cu3oGDzuIl3Vf49EAGXnY_VAyJQ/viewform?usp=sf_link",
        303,
    )


@app.route("/members")
@requires_member
def members():
    member_list = db_query(lambda db: db.users.list_members())
    return render_template("members.html", members=member_list)


@app.route("/myprofile")
@requires_login
def myprofile():
    user_id = int(g.session_data.user_id)
    db_user = db_query(lambda db: db.users.get(user_id))
    if not db_user:
        return redirect(url_for("join"))
    api = DiscordAPI()
    try:
        discord_data = api.get_user(g.session_data.user_id)
    finally:
        api.close()
    return render_template("profile.html", profile_user=db_user, discord_user=discord_data)


@app.route("/members/<int:userid>")
@requires_member
def profile(userid: int):
    db_user = db_query(lambda db: db.users.get(userid))
    if not db_user:
        abort(404)
    api = DiscordAPI()
    try:
        discord_data = api.get_user(str(userid))
    finally:
        api.close()
    return render_template("profile.html", profile_user=db_user, discord_user=discord_data)


@app.route("/login")
def login():
    scope = request.args.get("scope", "identify")
    oauth = DiscordOAuth()
    try:
        auth_url, state = oauth.get_authorization_url(scope=scope)
    finally:
        oauth.close()
    g.session_data.oauth_state = state
    return redirect(auth_url)


@app.route("/login_callback")
def login_callback():
    if request.args.get("error"):
        session_flash(g.session_data, "Authentication was denied. Please try again.", "danger")
        return redirect(url_for("home"))

    state = request.args.get("state")
    if not state or state != g.session_data.oauth_state:
        session_flash(g.session_data, "Invalid OAuth state. Please try again.", "danger")
        return redirect(url_for("login"))

    code = request.args.get("code")
    if not code:
        session_flash(g.session_data, "No authorization code received.", "danger")
        return redirect(url_for("login"))

    oauth = DiscordOAuth()
    try:
        token = oauth.exchange_code(code)
        discord_user = oauth.get_user(token)
    except httpx.HTTPStatusError:
        session_flash(g.session_data, "Failed to authenticate with Discord.", "danger")
        return redirect(url_for("login"))
    finally:
        oauth.close()

    g.session_data.user_id = discord_user.id
    g.session_data.username = discord_user.username
    g.session_data.discriminator = discord_user.discriminator
    g.session_data.avatar = discord_user.avatar
    g.session_data.access_token = (
        token.access_token if "guilds.join" in token.scope.split() else None
    )
    g.session_data.token_scope = token.scope
    g.session_data.oauth_state = None

    session_flash(g.session_data, "Logged in successfully.", "success")

    if g.session_data.has_guilds_join_scope:
        post_login = _normalize_local_redirect_target(g.session_data.post_login_url)
        g.session_data.post_login_url = None
        return redirect(url_for("join", next=post_login) if post_login else url_for("join"))

    post_login = _normalize_local_redirect_target(g.session_data.post_login_url)
    g.session_data.post_login_url = None
    return redirect(post_login or "/")


@app.route("/join", methods=["GET", "POST"])
def join():
    if not g.session_data.is_logged_in or not g.session_data.has_guilds_join_scope:
        g.session_data.post_login_url = _normalize_local_redirect_target(
            request.args.get("next")
        )
        return redirect(url_for("login", scope="identify guilds.join"))

    settings = get_settings()
    user_id = int(g.session_data.user_id)

    if request.method == "POST":
        csrf_token = request.form.get("csrf_token", "")
        if not validate_csrf_token(g.session_data, csrf_token):
            session_flash(g.session_data, "Invalid form submission. Please try again.", "danger")
            return redirect(url_for("join"))

        userclass = request.form.get("userclass", "")
        if userclass not in ("Member", "periphery", "recruiter"):
            session_flash(g.session_data, "Please select a valid membership type.", "danger")
            return redirect(url_for("join"))

        if not request.form.get("accept_general_rules"):
            session_flash(g.session_data, "You must accept the general rules.", "danger")
            return redirect(url_for("join"))

        if userclass == "Member" and not request.form.get("accept_member_rules"):
            session_flash(g.session_data, "Full members must accept the membership rules.", "danger")
            return redirect(url_for("join"))

        _name = g.session_data.username or ""
        _discriminator = g.session_data.discriminator
        _userclass = userclass
        _joined_at = datetime.now(timezone.utc)

        async def _save_role(db):
            await db.users.upsert(
                user_id,
                _name,
                _discriminator,
                first_joined_at=_joined_at,
            )
            await db.users.add_permanent_role(user_id, _userclass)
            if _userclass == "Member":
                await db.users.assign_member_number(user_id)

        db_query(_save_role)

    db_user = db_query(lambda db: db.users.get(user_id))

    if not db_user or not set(db_user.permanent_roles).intersection({"Member", "periphery", "recruiter"}):
        csrf = generate_csrf_token(g.session_data)
        discord_user_obj = DiscordUser(
            id=g.session_data.user_id,
            username=g.session_data.username or "",
            discriminator=g.session_data.discriminator or "0",
            avatar=g.session_data.avatar,
        )
        return render_template(
            "join.html",
            user=discord_user_obj,
            userclass_choices=USERCLASS_CHOICES,
            csrf_token=csrf,
        )

    # User has a permanent role - add them to the Discord guild
    roles_to_assign = []
    if settings.guild_id:
        for role_sig in db_user.permanent_roles:
            _sig = role_sig
            guild_role = db_query(
                lambda db, s=_sig: db.guilds.get_role_by_significance(settings.guild_id, s)
            )
            if guild_role:
                roles_to_assign.append(guild_role.role_id)

    api = DiscordAPI()
    try:
        was_added, _status = api.add_guild_member(
            guild_id=settings.guild_id,
            user_id=g.session_data.user_id,
            access_token=g.session_data.access_token,
            roles=roles_to_assign,
        )
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 403:
            g.session_data.post_login_url = _normalize_local_redirect_target(
                request.args.get("next")
            )
            return redirect(url_for("login", scope="identify guilds.join"))
        app.logger.error("add_guild_member failed: %s", exc)
        session_flash(g.session_data, "Failed to join Discord server. Please try again.", "danger")
        return redirect(url_for("home"))
    finally:
        api.close()

    # Announce the member the first time they get their roles, as legacy web
    # did: when this request added them to the guild, or when they were
    # already in the guild (e.g. waiting in the welcome channel) and this
    # request gave them a role they didn't have. The bot doesn't announce
    # members who arrive with their roles already attached.
    if was_added:
        session_flash(
            g.session_data,
            "You've joined the Discord server! Check your Discord client.",
            "success",
        )
        newly_assigned = True
    else:
        newly_assigned = _sync_roles(settings.guild_id, g.session_data.user_id, roles_to_assign) > 0
        session_flash(g.session_data, "Your Discord roles have been synchronized.", "success")

    if newly_assigned:
        _greet_new_member(
            settings.guild_id,
            g.session_data.user_id,
            db_user.permanent_roles,
            db_user.member_number,
        )

    g.session_data.access_token = None
    g.session_data.token_scope = None

    next_url = _normalize_local_redirect_target(request.args.get("next")) or "/"
    return redirect(next_url)


def _sync_roles(guild_id: str, user_id: str, role_ids: list[str]) -> int:
    """Give an existing guild member any of ``role_ids`` they lack.

    Returns how many roles were newly assigned.
    """
    api = DiscordAPI()
    added = 0
    try:
        current_roles: set[str] = set()
        try:
            member = api.get_guild_member(guild_id, user_id)
            if member:
                current_roles = {str(r) for r in member.get("roles", [])}
        except Exception:
            app.logger.exception("Failed to read guild member %s", user_id)
        for role_id in role_ids:
            if str(role_id) in current_roles:
                continue
            try:
                api.add_member_role(guild_id, user_id, role_id)
                added += 1
            except Exception:
                app.logger.exception("Failed to assign role %s to user %s", role_id, user_id)
    finally:
        api.close()
    return added


GREETING_WEBHOOK_NAME = "DisNOG.org"


def _greeting_channel_significance(permanent_roles: list[str]) -> str | None:
    """Pick the DB channel significance that announces this kind of user."""
    roles = set(permanent_roles)
    if roles & {"Member", "recruiter"}:
        return "greeting"
    if "periphery" in roles:
        return "periphery_greeting"
    return None


def _greet_new_member(
    guild_id: str,
    user_id: str,
    permanent_roles: list[str],
    member_number: int | None,
) -> None:
    """Post the welcome announcement to the DB-mapped greeting channel.

    Mirrors legacy web: a short-lived webhook named "DisNOG.org" posts the
    message and is deleted. Any failure is logged and never fails the join.
    """
    significance = _greeting_channel_significance(permanent_roles)
    if not guild_id or not significance:
        return
    try:
        channel = db_query(
            lambda db: db.guilds.get_channel_by_significance(guild_id, significance)
        )
        if not channel:
            app.logger.warning(
                "No '%s' channel mapped for guild %s; welcome not posted", significance, guild_id
            )
            return

        if member_number:
            greeting = f"Welcome <@{user_id}>, member #{member_number}!"
        else:
            greeting = f"Welcome <@{user_id}>!"
        content = (
            f"{greeting} We're happy to have you. "
            "Please feel free to take a moment to introduce yourself!"
        )

        api = DiscordAPI()
        try:
            webhook = api.create_webhook(channel.channel_id, GREETING_WEBHOOK_NAME)
            try:
                api.execute_webhook(webhook["id"], webhook["token"], content)
            finally:
                api.delete_webhook(webhook["id"], webhook["token"])
        finally:
            api.close()
    except Exception:
        app.logger.exception("Failed to post welcome for user %s", user_id)


@app.route("/logout")
def logout():
    new_session = SessionData()
    session_flash(new_session, "Logged out successfully.", "info")
    g.session_data = new_session
    return redirect(url_for("home"))
