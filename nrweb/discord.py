# discord.py
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

"""Discord OAuth2 and API client."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlencode

import httpx

from .config import get_settings


@dataclass
class DiscordUser:
    """Discord user from OAuth."""
    id: str
    username: str
    discriminator: str
    avatar: Optional[str] = None
    email: Optional[str] = None
    
    @property
    def display_name(self) -> str:
        # Handle Discord's new username system (no discriminator) vs legacy
        if self.discriminator and self.discriminator not in ("0", ""):
            return f"{self.username}#{self.discriminator}"
        return self.username
    
    @property
    def avatar_url(self) -> str:
        if self.avatar:
            return f"https://cdn.discordapp.com/avatars/{self.id}/{self.avatar}.png"
        # Default avatar
        default_num = (int(self.id) >> 22) % 6
        return f"https://cdn.discordapp.com/embed/avatars/{default_num}.png"


@dataclass
class DiscordToken:
    """OAuth2 token."""
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str
    scope: str
    
    @property
    def scopes(self) -> list[str]:
        return self.scope.split()


class DiscordOAuth:
    """Discord OAuth2 flow handler."""
    
    def __init__(self, redirect_uri: Optional[str] = None):
        self.settings = get_settings()
        self.redirect_uri = redirect_uri or self.settings.oauth2_redirect_uri
        self._http = httpx.AsyncClient()
    
    def get_authorization_url(self, scope: str = "identify", state: Optional[str] = None) -> tuple[str, str]:
        """
        Get OAuth2 authorization URL.
        Returns (url, state).
        """
        if state is None:
            state = secrets.token_urlsafe(32)
        
        params = {
            "client_id": self.settings.oauth2_client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": scope,
            "state": state,
        }
        
        url = f"{self.settings.authorization_url}?{urlencode(params)}"
        return url, state
    
    async def exchange_code(self, code: str) -> DiscordToken:
        """Exchange authorization code for token."""
        data = {
            "client_id": self.settings.oauth2_client_id,
            "client_secret": self.settings.oauth2_client_secret,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
        }
        
        resp = await self._http.post(
            self.settings.token_url,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        token_data = resp.json()
        
        return DiscordToken(
            access_token=token_data["access_token"],
            token_type=token_data["token_type"],
            expires_in=token_data["expires_in"],
            refresh_token=token_data["refresh_token"],
            scope=token_data["scope"],
        )
    
    async def get_user(self, token: DiscordToken) -> DiscordUser:
        """Get current user from token."""
        resp = await self._http.get(
            f"{self.settings.api_base_url}/users/@me",
            headers={"Authorization": f"Bearer {token.access_token}"},
        )
        resp.raise_for_status()
        data = resp.json()
        
        return DiscordUser(
            id=data["id"],
            username=data["username"],
            discriminator=data.get("discriminator"),  # None for new system
            avatar=data.get("avatar"),
            email=data.get("email"),
        )
    
    async def close(self):
        await self._http.aclose()


class DiscordAPI:
    """Discord Bot API client."""
    
    def __init__(self):
        self.settings = get_settings()
        self._http = httpx.AsyncClient()
    
    @property
    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bot {self.settings.bot_token}"}
    
    async def get_guild_member(self, guild_id: str, user_id: str) -> Optional[dict[str, Any]]:
        """Get a guild member. Returns None if not in guild."""
        resp = await self._http.get(
            f"{self.settings.api_base_url}/guilds/{guild_id}/members/{user_id}",
            headers=self._headers,
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()
    
    async def get_user(self, user_id: str) -> Optional[dict[str, Any]]:
        """Get a user by ID."""
        resp = await self._http.get(
            f"{self.settings.api_base_url}/users/{user_id}",
            headers=self._headers,
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()
    
    async def add_guild_member(
        self,
        guild_id: str,
        user_id: str,
        access_token: str,
        roles: list[str] = None,
    ) -> tuple[bool, int]:
        """
        Add a user to a guild using their OAuth token.
        Returns (was_added, status_code).
        201 = added, 204 = already in guild
        """
        data = {"access_token": access_token}
        if roles:
            data["roles"] = roles
        
        resp = await self._http.put(
            f"{self.settings.api_base_url}/guilds/{guild_id}/members/{user_id}",
            headers=self._headers,
            json=data,
        )
        resp.raise_for_status()
        return resp.status_code == 201, resp.status_code
    
    async def add_member_role(self, guild_id: str, user_id: str, role_id: str) -> None:
        """Add a role to a guild member."""
        resp = await self._http.put(
            f"{self.settings.api_base_url}/guilds/{guild_id}/members/{user_id}/roles/{role_id}",
            headers=self._headers,
        )
        resp.raise_for_status()
    
    async def create_webhook(self, channel_id: str, name: str) -> dict[str, Any]:
        """Create a webhook in a channel."""
        resp = await self._http.post(
            f"{self.settings.api_base_url}/channels/{channel_id}/webhooks",
            headers=self._headers,
            json={"name": name},
        )
        resp.raise_for_status()
        return resp.json()
    
    async def execute_webhook(self, webhook_id: str, webhook_token: str, content: str) -> None:
        """Execute a webhook."""
        resp = await self._http.post(
            f"{self.settings.api_base_url}/webhooks/{webhook_id}/{webhook_token}",
            json={"content": content},
        )
        resp.raise_for_status()
    
    async def delete_webhook(self, webhook_id: str, webhook_token: str) -> None:
        """Delete a webhook."""
        resp = await self._http.delete(
            f"{self.settings.api_base_url}/webhooks/{webhook_id}/{webhook_token}",
        )
        resp.raise_for_status()
    
    async def close(self):
        await self._http.aclose()
