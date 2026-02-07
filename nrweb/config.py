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


# Global settings instance (initialized in main.py)
settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get settings, initializing from env if needed."""
    global settings
    if settings is None:
        settings = Settings.from_env()
    return settings
