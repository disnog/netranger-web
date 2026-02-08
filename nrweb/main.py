# main.py
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

"""FastAPI application for Network Ranger web portal."""

from __future__ import annotations

import logging
logger = logging.getLogger(__name__)

# import asyncio  # unused
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request, Response, Form, Depends, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from netranger_db import Database

from .config import get_settings
from .discord import DiscordOAuth, DiscordAPI
from .session import SessionManager, SessionData, flash, get_flashed_messages, generate_csrf_token, validate_csrf_token


# Module-level state
db: Optional[Database] = None
discord_api: Optional[DiscordAPI] = None
session_mgr: Optional[SessionManager] = None
templates: Optional[Jinja2Templates] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    global db, discord_api, session_mgr, templates
    
    # Startup
    db = Database.from_env()
    await db.connect()
    
    discord_api = DiscordAPI()
    session_mgr = SessionManager()
    
    template_dir = Path(__file__).parent / "templates"
    templates = Jinja2Templates(directory=str(template_dir))
    templates.env.filters["utctime"] = lambda ts: (
        datetime.utcfromtimestamp(ts).strftime("%Y-%b-%d %H:%M:%S UTC")
        if ts else ""
    )
    
    yield
    
    # Shutdown
    await db.close()
    await discord_api.close()


app = FastAPI(
    title="Network Ranger",
    description="Web portal for the DisNOG server",
    lifespan=lifespan,
)

# Mount static files
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


# Dependencies
def get_session(request: Request) -> SessionData:
    """Dependency to get current session."""
    return session_mgr.get_session(request)


def require_login(session: SessionData = Depends(get_session)) -> SessionData:
    """Dependency that requires a logged-in user."""
    if not session.is_logged_in:
        raise HTTPException(status_code=401, detail="Not logged in")
    return session


# Helper to save session and return response
def redirect_with_session(
    url: str,
    session: SessionData,
    status_code: int = 303,
) -> Response:
    """Create redirect response with session cookie."""
    response = RedirectResponse(url=url, status_code=status_code)
    session_mgr.set_session(response, session)
    return response


def render(
    request: Request,
    template: str,
    session: SessionData,
    context: dict = None,
) -> Response:
    """Render a template with session context."""
    ctx = {
        "request": request,
        "user": {
            "id": session.user_id,
            "username": session.username,
            "discriminator": session.discriminator,
            "avatar": session.avatar,
        } if session.is_logged_in else None,
        "flashed_messages": get_flashed_messages(session),
        **(context or {}),
    }
    
    response = templates.TemplateResponse(template, ctx)
    session_mgr.set_session(response, session)
    return response


# Routes

@app.get("/", response_class=HTMLResponse)
async def home(request: Request, session: SessionData = Depends(get_session)):
    """Home page with member stats."""
    
    member_count = await db.users.count_by_role("Member")
    periphery_count = await db.users.count_by_role("periphery")
    recruiter_count = await db.users.count_by_role("recruiter")
    
    return render(request, "home.html", session, {
        "member_count": member_count,
        "periphery_count": periphery_count,
        "recruiter_count": recruiter_count,
    })


@app.get("/rules", response_class=HTMLResponse)
async def rules(request: Request, session: SessionData = Depends(get_session)):
    """Server rules page."""
    return render(request, "rules.html", session)


@app.get("/events", response_class=HTMLResponse)
async def events(request: Request, session: SessionData = Depends(get_session)):
    """Events page."""
    return render(request, "events.html", session)


@app.get("/members", response_class=HTMLResponse)
async def members(
    request: Request,
    session: SessionData = Depends(require_login),
):
    """Member listing (requires Member role)."""
    # Check if user has Member role
    if not session.user_id:
        return RedirectResponse("/join")
    
    user = await db.users.get(int(session.user_id))
    if not user or "Member" not in user.permanent_roles:
        flash(session, "You must be a Member to view the member list.", "warning")
        return redirect_with_session("/join", session)
    
    member_list = await db.users.list_members()
    
    return render(request, "members.html", session, {
        "members": member_list,
    })


@app.get("/profile", response_class=HTMLResponse)
@app.get("/profile/{user_id}", response_class=HTMLResponse)
async def profile(
    request: Request,
    user_id: Optional[int] = None,
    session: SessionData = Depends(require_login),
):
    """User profile page."""
    if user_id is None:
        user_id = int(session.user_id)
    
    user = await db.users.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Enrich with Discord data
    discord_user = await discord_api.get_user(str(user_id))
    
    return render(request, "profile.html", session, {
        "profile_user": user,
        "discord_user": discord_user,
    })


@app.get("/login")
async def login(
    request: Request,
    next: Optional[str] = None,
    scope: str = "identify",
    session: SessionData = Depends(get_session),
):
    """Start OAuth2 login flow."""
    settings = get_settings()
    redirect_uri = settings.oauth2_redirect_uri or str(request.url_for("login_callback"))
    
    oauth = DiscordOAuth(redirect_uri=redirect_uri)
    url, state = oauth.get_authorization_url(scope=scope)
    
    session.oauth_state = state
    session.post_login_url = next or "/"
    
    return redirect_with_session(url, session)


@app.get("/login/callback")
async def login_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    session: SessionData = Depends(get_session),
):
    """OAuth2 callback."""
    settings = get_settings()
    if error:
        flash(session, f"Login failed: {error}", "danger")
        return redirect_with_session("/", session)
    
    if not code or not state:
        flash(session, "Invalid callback parameters.", "danger")
        return redirect_with_session("/", session)
    
    if state != session.oauth_state:
        flash(session, "Invalid state. Please try again.", "danger")
        return redirect_with_session("/", session)
    
    redirect_uri = settings.oauth2_redirect_uri or str(request.url_for("login_callback"))
    
    try:
        oauth = DiscordOAuth(redirect_uri=redirect_uri)
        token = await oauth.exchange_code(code)
        user = await oauth.get_user(token)
        
        # Update session
        session.user_id = user.id
        session.username = user.username
        session.discriminator = user.discriminator
        session.avatar = user.avatar
        session.access_token = token.access_token
        session.refresh_token = token.refresh_token
        session.token_scope = token.scope
        session.oauth_state = None
        
        flash(session, "Logged in successfully.", "success")
        
        # Redirect to post-login URL or check if needs to join
        next_url = session.post_login_url or "/"
        session.post_login_url = None
        
        # If user has guilds.join scope, redirect to join
        if "guilds.join" in token.scopes:
            return redirect_with_session("/join", session)
        
        return redirect_with_session(next_url, session)
        
    except Exception as e:
        flash(session, f"Login error: {str(e)}", "danger")
        return redirect_with_session("/", session)


@app.get("/logout")
async def logout(session: SessionData = Depends(get_session)):
    """Log out and clear session."""
    response = RedirectResponse(url="/", status_code=303)
    session_mgr.clear_session(response)
    return response


@app.get("/join", response_class=HTMLResponse)
@app.post("/join", response_class=HTMLResponse)
async def join(
    request: Request,
    userclass: Optional[str] = Form(None),
    accept_general_rules: Optional[bool] = Form(False),
    accept_member_rules: Optional[bool] = Form(False),
    csrf_token: Optional[str] = Form(None),
    session: SessionData = Depends(get_session),
):
    """Join flow - accept rules and select userclass."""
    settings = get_settings()
    
    # Need to be logged in
    if not session.is_logged_in:
        return RedirectResponse('/login?scope=identify%20guilds.join&next=/join')
    
    # Need guilds.join scope
    if not session.has_guilds_join_scope:
        return RedirectResponse('/login?scope=identify%20guilds.join&next=/join')
    
    # Get or create user in DB
    user = await db.users.get(int(session.user_id))
    if not user:
        await db.users.upsert(
            int(session.user_id),
            session.username,
            session.discriminator,
        )
        user = await db.users.get(int(session.user_id))
    
    # If already has a userclass, join them to the guild
    if user and set(user.permanent_roles) & {"Member", "periphery", "recruiter"}:
        # Get role IDs for their permanent roles
        guild = await db.guilds.get(settings.guild_id)
        role_ids = []
        
        for role in guild.known_roles if guild else []:
            for sig in role.significances:
                if sig in user.permanent_roles and sig != "!eggs":
                    role_ids.append(role.role_id)
        
        # Add to guild
        try:
            was_added, status = await discord_api.add_guild_member(
                settings.guild_id,
                session.user_id,
                session.access_token,
                roles=role_ids,
            )
            
            if was_added:
                flash(session, "You've joined the Discord server!", "success")
                # Send greeting
                await send_greeting(session.user_id, user)
            else:
                # Already in guild, sync roles
                for role_id in role_ids:
                    try:
                        await discord_api.add_member_role(
                            settings.guild_id,
                            session.user_id,
                            role_id,
                        )
                    except Exception:
                        pass
                flash(session, "Your roles have been synchronized.", "success")
            
            return redirect_with_session("/", session)
            
        except Exception as e:
            flash(session, f"Error joining guild: {str(e)}", "danger")
    
    # Handle form submission
    if request.method == "POST" and userclass:
        # CSRF validation
        if not csrf_token or not validate_csrf_token(session, csrf_token):
            flash(session, "Invalid or missing CSRF token. Please try again.", "danger")
            return redirect_with_session("/join", session)
        
        if not accept_general_rules:
            flash(session, "You must accept the general rules.", "warning")
        elif userclass == "Member" and not accept_member_rules:
            flash(session, "You must accept the member rules.", "warning")
        elif userclass in ("Member", "periphery", "recruiter"):
            # Add permanent role
            await db.users.add_permanent_role(int(session.user_id), userclass)
            
            # Assign member number if Member
            if userclass in ("Member", "recruiter"):
                await db.users.assign_member_number(int(session.user_id))
            
            flash(session, f"Welcome! You've joined as {userclass}.", "success")
            return redirect_with_session("/join", session)  # Re-process to join guild
    
    # Show join form
    userclass_choices = [
        ("Member", "Enterprise networking, enterprise wifi, and VOIP"),
        ("periphery", "Home routers, wifi, servers, computers, and peripherals"),
        ("recruiter", "Posting network engineering jobs I'm hoping to fill"),
        ("Member", "Network automation and DevOps"),
        ("periphery", "General business or enterprise IT, server admin, or coding"),
        ("Member", "Service provider networking, BGP, and MPLS"),
        ("Member", "I'm a student studying for enterprise or service provider networking"),
    ]
    
    # Generate CSRF token for the form
    csrf = generate_csrf_token(session)
    
    return render(request, "join.html", session, {
        "userclass_choices": userclass_choices,
        "user": user,
        "csrf_token": csrf,
    })


async def send_greeting(user_id: str, user) -> None:
    """Send greeting message to appropriate channel."""
    settings = get_settings()
    guild = await db.guilds.get(settings.guild_id)
    if not guild:
        return
    
    # Determine channel based on userclass
    if set(user.permanent_roles) & {"Member", "recruiter"}:
        channel_sig = "greeting"
    else:
        channel_sig = "periphery_greeting"
    
    channel = await db.guilds.get_channel_by_significance(settings.guild_id, channel_sig)
    if not channel:
        return
    
    member_number = user.member_number or "?"
    content = f"Welcome <@{user_id}>, member #{member_number}! We're happy to have you. Please feel free to take a moment to introduce yourself!"
    
    webhook = None
    try:
        webhook = await discord_api.create_webhook(channel.channel_id, "DisNOG.org")
        await discord_api.execute_webhook(webhook["id"], webhook["token"], content)
    except Exception as e:
        logger.warning(f"Failed to send greeting: {e}")
    finally:
        if webhook:
            try:
                await discord_api.delete_webhook(webhook["id"], webhook["token"])
            except Exception as e:
                logger.warning(f"Failed to delete webhook: {e}")


# Redirects for legacy URLs
@app.get("/linkedin")
async def linkedin():
    return RedirectResponse("https://www.linkedin.com/groups/9073282", status_code=303)


def main():
    """CLI entry point."""
    import uvicorn
    uvicorn.run(
        "nrweb.main:app",
        host="0.0.0.0",
        port=8000,
        reload=get_settings().debug,
    )


if __name__ == "__main__":
    main()


# Legacy URL redirects for backward compatibility
from urllib.parse import unquote
import json


@app.get("/login/{path:path}")
async def login_legacy_redirect(
    request: Request,
    path: str,
):
    """Handle legacy /login/<postlogin> URLs.
    
    Redirects old /login/<postlogin> (where postlogin was either a simple path
    or URL-encoded JSON like {"endpoint": "join"}) to /login?next=<path>
    """
    try:
        # Try to decode JSON-encoded path (old format: %7B%22endpoint%22...%7D)
        decoded = unquote(path)
        data = json.loads(decoded)
        next_url = "/" + data.get("endpoint", "")
    except (json.JSONDecodeError, ValueError):
        # Plain path like "join" or "home"
        next_url = f"/{path}"
    
    return RedirectResponse(url=f"/login?next={next_url}", status_code=301)


@app.get("/join/{path:path}")
async def join_legacy_redirect(
    request: Request,
    path: str,
):
    """Handle legacy /join/<postlogin> URLs.
    
    Redirects old /join/<postlogin> to /join?next=<path>
    """
    try:
        decoded = unquote(path)
        data = json.loads(decoded)
        next_url = "/" + data.get("endpoint", "")
    except (json.JSONDecodeError, ValueError):
        next_url = f"/{path}"
    
    return RedirectResponse(url=f"/join?next={next_url}", status_code=301)
