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
from functools import wraps
from typing import Any

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
            g.session_data.post_login_url = request.url
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def requires_member(f):
    """Decorator: require Member permanent role in DB."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not g.session_data.is_logged_in:
            g.session_data.post_login_url = request.url
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
    g.session_data.access_token = token.access_token
    g.session_data.refresh_token = token.refresh_token
    g.session_data.token_scope = token.scope
    g.session_data.oauth_state = None

    session_flash(g.session_data, "Logged in successfully.", "success")

    if g.session_data.has_guilds_join_scope:
        post_login = g.session_data.post_login_url
        g.session_data.post_login_url = None
        return redirect(url_for("join", next=post_login) if post_login else url_for("join"))

    post_login = g.session_data.post_login_url
    g.session_data.post_login_url = None
    return redirect(post_login or url_for("home"))


@app.route("/join", methods=["GET", "POST"])
def join():
    if not g.session_data.is_logged_in or not g.session_data.has_guilds_join_scope:
        g.session_data.post_login_url = request.args.get("next") or request.url
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

        async def _save_role(db):
            await db.users.upsert(user_id, _name, _discriminator)
            await db.users.add_permanent_role(user_id, _userclass)

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
            g.session_data.post_login_url = request.args.get("next")
            return redirect(url_for("login", scope="identify guilds.join"))
        app.logger.error("add_guild_member failed: %s", exc)
        session_flash(g.session_data, "Failed to join Discord server. Please try again.", "danger")
        return redirect(url_for("home"))
    finally:
        api.close()

    if was_added:
        session_flash(
            g.session_data,
            "You've joined the Discord server! Check your Discord client.",
            "success",
        )
    else:
        _sync_roles(settings.guild_id, g.session_data.user_id, roles_to_assign)
        session_flash(g.session_data, "Your Discord roles have been synchronized.", "success")

    next_url = request.args.get("next") or url_for("home")
    return redirect(next_url)


def _sync_roles(guild_id: str, user_id: str, role_ids: list[str]) -> None:
    """Assign roles to an existing guild member."""
    api = DiscordAPI()
    try:
        for role_id in role_ids:
            try:
                api.add_member_role(guild_id, user_id, role_id)
            except Exception:
                app.logger.exception("Failed to assign role %s to user %s", role_id, user_id)
    finally:
        api.close()


@app.route("/logout")
def logout():
    new_session = SessionData()
    session_flash(new_session, "Logged out successfully.", "info")
    g.session_data = new_session
    return redirect(url_for("home"))
