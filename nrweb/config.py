# config.py
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

"""Configuration from environment variables."""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class Settings:
    """Application settings loaded from environment."""

    # Discord OAuth2
    oauth2_client_id: str
    oauth2_client_secret: str
    oauth2_redirect_uri: Optional[str] = None

    # Discord API
    bot_token: str = ""
    guild_id: str = ""
    api_base_url: str = "https://discord.com/api/v10"

    # Session
    secret_key: str = ""

    # Environment
    environment: str = "prod"
    debug: bool = False

    @classmethod
    def from_env(cls) -> "Settings":
        """Load settings from environment variables."""
        return cls(
            oauth2_client_id=os.environ["OAUTH2_CLIENT_ID"],
            oauth2_client_secret=os.environ["OAUTH2_CLIENT_SECRET"],
            oauth2_redirect_uri=os.environ.get("OAUTH2_REDIRECT_URI"),
            bot_token=os.environ.get("BOT_TOKEN", ""),
            guild_id=os.environ.get("GUILD_ID", ""),
            api_base_url=os.environ.get("API_BASE_URL", "https://discord.com/api/v10"),
            secret_key=os.environ.get("SECRET_KEY", os.environ.get("OAUTH2_CLIENT_SECRET", "")),
            environment=os.environ.get("NRWEB_ENVIRONMENT", "prod").lower(),
            debug=os.environ.get("DEBUG", "").lower() in ("1", "true", "yes"),
        )

    @property
    def authorization_url(self) -> str:
        return f"{self.api_base_url}/oauth2/authorize"

    @property
    def token_url(self) -> str:
        return f"{self.api_base_url}/oauth2/token"


# Global settings instance
settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get settings, initializing from env if needed."""
    global settings
    if settings is None:
        settings = Settings.from_env()
    return settings
