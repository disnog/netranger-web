#!/usr/bin/env python3

# netranger-web - app.py
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

from flask import Flask, redirect, url_for, render_template, request, session, g
import os
from requests_oauthlib import OAuth2Session
import urllib.parse
import json
from flask_pymongo import PyMongo
import uuid
from functools import wraps

NRWEB_ENVIRONMENT = os.environ.get("NRWEB_ENVIRONMENT", "prod").lower()
if NRWEB_ENVIRONMENT in ["dev"]:
    DEBUG = True
else:
    DEBUG = False

OAUTH2_CLIENT_ID = os.environ["OAUTH2_CLIENT_ID"]
OAUTH2_CLIENT_SECRET = os.environ["OAUTH2_CLIENT_SECRET"]
APP_SECRET = os.environ.get("APP_SECRET", OAUTH2_CLIENT_SECRET)
OAUTH2_REDIRECT_URI = os.environ.get(
    "OAUTH2_REDIRECT_URI", "http://localhost:5000/login_callback"
)
API_BASE_URL = os.environ.get("API_BASE_URL", "https://discordapp.com/api")
AUTHORIZATION_BASE_URL = API_BASE_URL + "/oauth2/authorize"
TOKEN_URL = API_BASE_URL + "/oauth2/token"
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/NRWEB")

if "http://" in OAUTH2_REDIRECT_URI and NRWEB_ENVIRONMENT == "dev":
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "true"


def token_updater(token):
    session["oauth2_token"] = token


def make_session(token=None, state=None, scope=None):
    return OAuth2Session(
        client_id=OAUTH2_CLIENT_ID,
        token=token,
        state=state,
        scope=scope,
        redirect_uri=OAUTH2_REDIRECT_URI,
        auto_refresh_kwargs={
            "client_id": OAUTH2_CLIENT_ID,
            "client_secret": OAUTH2_CLIENT_SECRET,
        },
        auto_refresh_url=TOKEN_URL,
        token_updater=token_updater,
    )


app = Flask(__name__)
app.config["SECRET_KEY"] = APP_SECRET
app.config["MONGO_URI"] = MONGO_URI
# mongo = PyMongo(app)


@app.before_request
def do_before_request():
    if "oauth2_token" in session:
        g.discord = make_session(token=session.get("oauth2_token"))
        g.user = g.discord.get(API_BASE_URL + "/users/@me").json()


def is_member(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        # Check if user is logged in
        if "user" in g:
            return f(*args, **kwargs)
        else:
            return redirect(url_for("login"))

    return decorator


@app.route("/")
@app.route("/home")
def home():
    return render_template("home.html")


@app.route("/members")
@is_member
def members():
    return render_template("members.html")


@app.route("/profile")
@is_member
def myprofile():
    return redirect(url_for("profile", userid=g.user["id"]))


@app.route("/profile/<userid>")
@is_member
def profile(userid):
    return render_template("profile.html", userid=userid)


@app.route("/login")
@app.route("/login/<postlogin>")
def login(postlogin=None):
    scope = request.args.get("scope", "identify")
    discord = make_session(scope=scope.split(" "))
    authorization_url, state = discord.authorization_url(AUTHORIZATION_BASE_URL)
    if postlogin:
        session["postlogin"] = json.loads(urllib.parse.unquote(postlogin))
    else:
        session["postlogin"] = {"endpoint": "home"}
    session["oauth2_state"] = state
    return redirect(authorization_url)


@app.route("/login_callback")
def login_callback():
    if request.values.get("error"):
        return request.values["error"]
    discord = make_session(state=session.get("oauth2_state"))
    token = discord.fetch_token(
        TOKEN_URL,
        client_secret=OAUTH2_CLIENT_SECRET,
        authorization_response=request.url,
    )
    session["oauth2_token"] = token
    if session.get("postlogin"):
        postlogin = session["postlogin"]
        del session["postlogin"]
        redirect_target = url_for(**postlogin)
    else:
        redirect_target = url_for("home")
    return redirect(redirect_target)


@app.route("/logout")
def logout():
    if request.values.get("error"):
        return request.values["error"]
    session.clear()
    redirect_target = url_for("home")
    return redirect(redirect_target)



if __name__ == "__main__":
    app.run(debug=DEBUG)
