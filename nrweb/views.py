#!/usr/bin/env python3

# nrweb - views.py
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

from flask import redirect, url_for, render_template, request, session, g, abort
from flask_breadcrumbs import register_breadcrumb
from nrweb import app
from requests_oauthlib import OAuth2Session
import urllib.parse
import json
from flask_pymongo import PyMongo
import uuid
from functools import wraps
from datetime import datetime
import requests


def token_updater(token):
    session["oauth2_token"] = token


def make_session(token=None, state=None, scope=None):
    return OAuth2Session(
        client_id=app.config["OAUTH2_CLIENT_ID"],
        token=token,
        state=state,
        scope=scope,
        redirect_uri=app.config["OAUTH2_REDIRECT_URI"],
        auto_refresh_kwargs={
            "client_id": app.config["OAUTH2_CLIENT_ID"],
            "client_secret": app.config["OAUTH2_CLIENT_SECRET"],
        },
        auto_refresh_url=app.config["TOKEN_URL"],
        token_updater=token_updater,
    )


@app.before_request
def do_before_request():
    g.db = PyMongo(app)
    if "oauth2_token" in session:
        g.discord = make_session(token=session.get("oauth2_token"))
        g.user = g.discord.get(app.config["API_BASE_URL"] + "/users/@me").json()
        g.user.update(
            g.db.db.users.find_one(
                {"_id": int(g.user["id"])}, {"permanent_roles": True}
            )
        )
        g.guild = g.db.db.guilds.find_one({"_id": app.config["GUILD_ID"]})


def has_role(role_cn="members", fail_action="auto"):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Check if user is logged in
            if "user" in g:
                g.user = enrich_member(g.user)
                if "roles" in g.user:
                    # The user is currently on the server
                    members_roleid = next(
                        x for x in g.guild["known_roles"] if x["significance"] == role_cn
                    )["id"]
                    if members_roleid in g.user['roles']:
                        # The user has the role
                        return f(*args, **kwargs)
                    else:
                        if fail_action.lower() not in ['auto','401','entry']:
                            fail_action = 'auto'
                        if fail_action.lower() == 'auto':
                            # Set unauthorized action to entry if the role common name is members.
                            # Otherwise, return 401.
                            if role_cn == 'members':
                                fail_action = 'entry'
                            else:
                                fail_action = '401'
                        if fail_action.lower() == 'entry':
                            redirect(url_for("entry"))
                        elif fail_action.lower() == '401':
                            abort(401)
                else:
                    # The user is not currently on the server
                    return redirect(url_for("join", postlogin=postlogin))
            else:
                postlogin = urllib.parse.quote(
                    json.dumps({"endpoint": request.endpoint, **request.view_args})
                )
                return redirect(url_for("login", postlogin=postlogin))
        return wrapper
    return decorator


def enrich_member(user):
    r = requests.get(
        app.config["API_BASE_URL"]
        + "/guilds/"
        + str(app.config["GUILD_ID"])
        + "/members/"
        + str(user["_id"]),
        headers={"Authorization": "Bot " + app.config["BOT_TOKEN"]},
    )
    # Only enrich if the user actually is in the guild.
    if r.ok:
        discord_member = r.json()
        discord_member.update(discord_member.pop("user"))
        user.update({"nick": discord_member["nick"], "roles": discord_member["roles"]})
    return user


def enrich_user(user):
    r = requests.get(
        app.config["API_BASE_URL"] + "/users/" + str(user["_id"]),
        headers={"Authorization": "Bot " + app.config["BOT_TOKEN"]},
    )
    # Only enrich if the user actually exists.
    if r.ok:
        discord_user = r.json()
        user.update(discord_user)
    return user


@app.template_filter("utctime")
def utctime(s):
    return datetime.utcfromtimestamp(s).strftime("%Y-%b-%d %H:%M:%S UTC")


@app.route("/")
@app.route("/home")
@register_breadcrumb(app, ".", "Home")
def home():
    registered_members = g.db.db.users.count({"member_number": {"$exists": True}})
    unaccepted_members = g.db.db.users.count({"member_number": {"$exists": False}})
    return render_template(
        "home.html",
        registered_members=registered_members,
        unaccepted_members=unaccepted_members,
    )


@app.route("/members")
@has_role(role_cn='members')
@register_breadcrumb(app, ".home", "Members")
def members():
    memberlist = g.db.db.users.find({"member_number": {"$exists": True}})
    return render_template("members.html", memberlist=memberlist)


@app.route("/myprofile")
@has_role(role_cn='members')
def myprofile():
    return redirect(url_for("profile", userid=int(g.user["id"])))


def userid_breadcrumb_constructor(*args, **kwargs):
    user = g.db.db.users.find_one(
        {"_id": request.view_args["userid"]}, {"name": True, "discriminator": True}
    )
    return [
        {
            "text": user["name"] + "#" + user["discriminator"],
            "url": url_for(request.endpoint, userid=request.view_args["userid"]),
        }
    ]


@app.route("/members/<int:userid>")
@has_role(role_cn='members')
@register_breadcrumb(
    app, ".home.members", "", dynamic_list_constructor=userid_breadcrumb_constructor
)
def profile(userid):
    user = g.db.db.users.find_one({"_id": request.view_args["userid"]})
    user = enrich_user(user)
    return render_template("profile.html", user=user)


@app.route("/login")
@app.route("/login/<postlogin>")
def login(postlogin=None):
    scope = request.args.get("scope", "identify")
    discord = make_session(scope=scope.split(" "))
    authorization_url, state = discord.authorization_url(
        app.config["AUTHORIZATION_BASE_URL"]
    )
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
        app.config["TOKEN_URL"],
        client_secret=app.config["OAUTH2_CLIENT_SECRET"],
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
