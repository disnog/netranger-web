#!/usr/bin/env python3

# nrweb - config.py
# Copyright (C) 2020  Networking Discord
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

import os
from urllib.parse import quote_plus

OAUTH2_REDIRECT_URI = os.environ.get(
    "OAUTH2_REDIRECT_URI", False
)
NRWEB_ENVIRONMENT = os.environ.get("NRWEB_ENVIRONMENT", "prod").lower()
if "http://" in str(OAUTH2_REDIRECT_URI) and NRWEB_ENVIRONMENT == "dev":
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "true"
elif (not OAUTH2_REDIRECT_URI or "https://" in str(OAUTH2_REDIRECT_URI)) and NRWEB_ENVIRONMENT == "prod":
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "true"

OAUTH2_CLIENT_ID = os.environ["OAUTH2_CLIENT_ID"]
OAUTH2_CLIENT_SECRET = os.environ["OAUTH2_CLIENT_SECRET"]
SECRET_KEY = os.environ.get("SECRET_KEY", OAUTH2_CLIENT_SECRET)
GUILD_ID = os.environ.get("GUILD_ID")
BOT_TOKEN = quote_plus(os.environ.get("BOT_TOKEN"))
API_BASE_URL = os.environ.get("API_BASE_URL", "https://discordapp.com/api")
AUTHORIZATION_BASE_URL = API_BASE_URL + "/oauth2/authorize"
TOKEN_URL = API_BASE_URL + "/oauth2/token"
MONGO_USER = quote_plus(os.environ.get("MONGO_USER"))
MONGO_PASS = quote_plus(os.environ.get("MONGO_PASS"))
MONGO_HOST = os.environ.get("MONGO_HOST", "localhost:27017")
MONGO_DB = os.environ.get("MONGO_DB", "network_ranger")
MONGO_AUTHSOURCE = os.environ.get("MONGO_AUTHSOURCE", "admin")
MONGO_URI = f"mongodb://{MONGO_USER}:{MONGO_PASS}@{MONGO_HOST}/{MONGO_DB}?authSource={MONGO_AUTHSOURCE}"
