# session.py
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

"""Session management using signed cookies for Flask."""

from __future__ import annotations

import secrets
from dataclasses import asdict, dataclass, field
from typing import Optional

from flask import request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.wrappers import Request, Response

from .config import get_settings


@dataclass
class SessionData:
    """Session data stored in cookie."""

    user_id: Optional[str] = None
    username: Optional[str] = None
    discriminator: Optional[str] = None
    avatar: Optional[str] = None
    access_token: Optional[str] = None
    token_scope: Optional[str] = None
    oauth_state: Optional[str] = None
    post_login_url: Optional[str] = None
    csrf_token: Optional[str] = None
    flash_messages: list[dict] = field(default_factory=list)

    @property
    def is_logged_in(self) -> bool:
        return self.user_id is not None

    @property
    def has_guilds_join_scope(self) -> bool:
        return bool(
            self.access_token
            and self.token_scope
            and "guilds.join" in self.token_scope.split()
        )

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "SessionData":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class SessionManager:
    """Manages session cookies for Flask."""

    COOKIE_NAME = "nrweb_session"
    MAX_AGE = 86400 * 7  # 7 days

    def __init__(self):
        settings = get_settings()
        self._serializer = URLSafeTimedSerializer(settings.secret_key)

    def get_session(self, req: Optional[Request] = None) -> SessionData:
        """Get session from request cookie."""
        if req is None:
            req = request
        cookie = req.cookies.get(self.COOKIE_NAME)
        if not cookie:
            return SessionData()

        try:
            data = self._serializer.loads(cookie, max_age=self.MAX_AGE)
            return SessionData.from_dict(data)
        except (BadSignature, SignatureExpired):
            return SessionData()

    def set_session(self, response: Response, session: SessionData) -> None:
        """Set session cookie on response."""
        value = self._serializer.dumps(session.to_dict())
        response.set_cookie(
            self.COOKIE_NAME,
            value,
            max_age=self.MAX_AGE,
            httponly=True,
            samesite="lax",
            secure=get_settings().environment == "prod",
        )

    def clear_session(self, response: Response) -> None:
        """Clear session cookie."""
        response.delete_cookie(self.COOKIE_NAME)


def flash(session: SessionData, message: str, category: str = "info") -> None:
    """Add a flash message to the session."""
    session.flash_messages.append({"message": message, "category": category})


def get_flashed_messages(session: SessionData) -> list[dict]:
    """Get and clear flash messages."""
    messages = session.flash_messages.copy()
    session.flash_messages.clear()
    return messages


def generate_csrf_token(session: SessionData) -> str:
    """Generate a new CSRF token for the session."""
    token = secrets.token_urlsafe(32)
    session.csrf_token = token
    return token


def validate_csrf_token(session: SessionData, token: str) -> bool:
    """Validate a CSRF token against the session."""
    if not session.csrf_token:
        return False
    return secrets.compare_digest(session.csrf_token, token)
