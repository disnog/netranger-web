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

from flask import (
    redirect,
    url_for,
    render_template,
    request,
    session,
    g,
    abort,
    flash,
    Markup,
)
from flask_breadcrumbs import register_breadcrumb
from nrweb import app, nrdb
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
        g.guild = nrdb.get_guild(app.config["GUILD_ID"])


def has_role(role_significance="Member", fail_action="auto"):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, fail_action=fail_action, **kwargs):
            # Check if user is logged in
            if "user" in g:
                g.user = enrich_member(g.user)
                if "roles" in g.user:
                    # The user is currently on the server
                    members_roleid = next(
                        x
                        for x in g.guild["known_roles"]
                        if role_significance in x["significance"]
                    )["id"]
                    if members_roleid in g.user["roles"]:
                        # The user has the role
                        return f(*args, **kwargs)
                    else:
                        if fail_action.lower() not in ["auto", "401", "join"]:
                            fail_action = "auto"
                        if fail_action.lower() == "auto":
                            # Set unauthorized action to join if the role significance is members.
                            # Otherwise, return 401.
                            if role_significance == "Member":
                                fail_action = "join"
                            else:
                                fail_action = "401"
                        if fail_action.lower() == "join":
                            # TODO: Add postlogin
                            return redirect(url_for("join"))
                        elif fail_action.lower() == "401":
                            abort(401)
                else:
                    # The user is not currently on the server
                    postlogin = urllib.parse.quote(
                        json.dumps({"endpoint": request.endpoint, **request.view_args})
                    )
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


def join_user_to_guild(guildid, access_token, userid):
    r = requests.put(
        app.config["API_BASE_URL"] + "/guilds/" + guildid + "/members/" + userid,
        headers={"Authorization": "Bot " + app.config["BOT_TOKEN"]},
        json={"access_token": access_token},
    )
    return r

def send_to_known_channel(significance,json_payload):
    channel=nrdb.get_channel_by_significance(app.config["GUILD_ID"],significance)
    r = requests.post(
        app.config["API_BASE_URL"] + "/channels/" + channel["id"] + "/webhooks",
        headers={"Authorization": "Bot " + app.config["BOT_TOKEN"]},
        json={"name": "https://neteng.xyz"},
    )
    r.raise_for_status()
    webhook=r.json()
    r = requests.post(
        app.config["API_BASE_URL"] + "/webhooks/" + webhook["id"] + "/" + webhook["token"],
        json=json_payload
    )
    r.raise_for_status()
    r = requests.delete(
        app.config["API_BASE_URL"] + "/webhooks/" + webhook["id"] + "/" + webhook["token"]
    )
    r.raise_for_status()

def assign_role(significance,member_id):
    role=nrdb.get_role_by_significance(app.config["GUILD_ID"],significance)
    r = requests.put(
        app.config["API_BASE_URL"] + "/guilds/" + app.config["GUILD_ID"] + "/members/" + member_id + "/roles/" + role['id'],
        headers={"Authorization": "Bot " + app.config["BOT_TOKEN"]},
    )
    r.raise_for_status()

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
@has_role(role_significance="Member",fail_action="join")
@register_breadcrumb(app, ".home", "Members")
def members():
    memberlist = g.db.db.users.find({"member_number": {"$exists": True}})
    return render_template("members.html", memberlist=memberlist)


@app.route("/myprofile")
@has_role(role_significance="Member")
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
@has_role(role_significance="Member",fail_action="join")
@register_breadcrumb(
    app, ".home.members", "", dynamic_list_constructor=userid_breadcrumb_constructor
)
def profile(userid):
    user = g.db.db.users.find_one({"_id": userid})
    user = enrich_user(user)
    return render_template("profile.html", user=user)


@app.route("/login")
@app.route("/login/<postlogin>")
def login(postlogin=None, scope="identify"):
    scope = request.args.get("scope", scope)
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
        flash(
            Markup(
                "You need to grant permissions to authenticate. <a href='{loginurl}'>Try again</a>?".format(
                    loginurl=url_for("login")
                )
            ),
            category="danger",
        )
        return redirect(url_for("home"))
    g.discord = make_session(state=session.get("oauth2_state"))
    token = g.discord.fetch_token(
        app.config["TOKEN_URL"],
        client_secret=app.config["OAUTH2_CLIENT_SECRET"],
        authorization_response=request.url,
    )
    session["oauth2_token"] = token
    if "guilds.join" in token.scopes:
        redirect_target = url_for("join")
    elif session.get("postlogin"):
        postlogin = session["postlogin"]
        del session["postlogin"]
        redirect_target = url_for(**postlogin)
    else:
        redirect_target = url_for("home")
    flash("Logged in successfully.", category="success")
    return redirect(redirect_target)


@app.route("/join")
@app.route("/join/<postlogin>")
def join(postlogin=None):
    if "user" not in g:
        return login(postlogin=postlogin, scope="identify guilds.join")
    # Check if the user is already an accepted member.
    elif "Member" in g.user["permanent_roles"]:
        # Join the user to the guild since we have permission and the user is an accepted member.
        r = join_user_to_guild(
            app.config["GUILD_ID"],
            session["oauth2_token"]["access_token"],
            g.user["id"],
        )
        if r.status_code == 204:
            # User is already in the guild.
            flash("You're already in the Discord server!", "warning")
            # TODO: Only do this if they're not yet in Members
            assign_role("Member",g.user['id'])
            flash(
                "You've been added as a full Member on the Discord server! Please check your Discord client to find your new channels.",
                category="success",
            )
        elif r.status_code == 201:
            # User was joined to the guild.
            user = nrdb.get_user(g.user['id'])
            member_number = user["member_number"]
            json_payload = {"content": f"Welcome <@{g.user['id']}>, member #{member_number}! We're happy to have you. Please feel free to take a moment to introduce yourself!"}
            send_to_known_channel("greeting",json_payload)
            flash(
                "You've joined the Discord server! Please check your Discord client to find it added to your server list.",
                category="success",
            )
        else:
            flash(
                f"Error: Unknown status code {r.status_code} from {r.url}",
                category="danger",
            )
        if postlogin:
            session["postlogin"] = json.loads(urllib.parse.unquote(postlogin))
            redirect_target = url_for(**session["postlogin"])
        elif session.get("postlogin"):
            redirect_target = url_for(**session["postlogin"])
        else:
            redirect_target = url_for("home")
        if "postlogin" in session:
            del session["postlogin"]
        return redirect(redirect_target)
    else:
        # Perform the test
        return render_template("join.html")


@app.route("/logout")
def logout():
    if request.values.get("error"):
        return request.values["error"]
    session.clear()
    redirect_target = url_for("home")
    flash("Logged out successfully.", category="info")
    return redirect(redirect_target)
