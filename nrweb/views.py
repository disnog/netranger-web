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

import json
import urllib.parse
from datetime import datetime
from functools import wraps
from os import sys

import requests
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
from flask_pymongo import PyMongo
from flask_wtf import FlaskForm
from oauthlib.oauth2.rfc6749.errors import InvalidClientError
from requests_oauthlib import OAuth2Session
from wtforms import BooleanField
from wtforms import SelectField
from wtforms.validators import InputRequired

from nrweb import app, nrdb


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
        g.guild = nrdb.get_guild(app.config["GUILD_ID"])
        user_db_info = g.db.db.users.find_one(
            {"_id": int(g.user["id"])}, {"permanent_roles": True, "member_number": True, "first_joined_at": True}
        )
        if user_db_info:
            # The user exists in the database.
            g.user.update(user_db_info)
            g.user = enrich_member(g.user)
            if request.endpoint in ["join", "login_callback"]:
                pass
            elif "roles" in g.user:
                # The user is currently on the server. Make sure they have a known role, or redirect to join.
                known_role_ids = {kr['id'] for kr in g.guild["known_roles"]}
                if set(g.user["roles"]).isdisjoint(known_role_ids):
                    # The user is either assigned to any known roles, and we're not checking for a specific role.
                    postlogin = urllib.parse.quote(
                        json.dumps({"endpoint": request.endpoint, **request.view_args})
                    )
                    return redirect(url_for("join", postlogin=postlogin))
            else:
                # Redirect to join as the user is not on the server even though they're logged in.
                postlogin = urllib.parse.quote(
                    json.dumps({"endpoint": request.endpoint, **request.view_args})
                )
                return redirect(url_for("join", postlogin=postlogin))
        else:
            g.user.update({"permanent_roles": list()})
            if request.endpoint not in ["join", "login_callback"]:
                # Redirect the user to join as they are not in the database.
                postlogin = urllib.parse.quote(
                    json.dumps({"endpoint": request.endpoint, **request.view_args})
                )
                return redirect(url_for("join", postlogin=postlogin))


def has_role(role_significance=None, fail_action="auto"):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, fail_action=fail_action, **kwargs):
            # Check if user is logged in
            if "user" in g:
                if "roles" in g.user:
                    # The user is currently on the server
                    if not role_significance:
                        known_role_ids = {kr['id'] for kr in g.guild["known_roles"]}
                        if not set(g.user["roles"]).isdisjoint(known_role_ids):
                            # The user is either assigned to any known roles, and we're not checking for a specific role.
                            return f(*args, **kwargs)
                    else:
                        members_roleid = next(
                            x
                            for x in g.guild["known_roles"]
                            if role_significance in x["significance"]
                        )["id"]
                        if members_roleid in g.user["roles"]:
                            # The user has the role
                            return f(*args, **kwargs)
                        else:
                            if fail_action.lower() not in ["auto", "401", "403", "join"]:
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
                            elif fail_action.lower() == "403":
                                abort(403)
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
    if "_id" not in user.keys() and "id" in user.keys():
        user['_id'] = user['id']
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
    if r.status_code == 201:
        app.logger.info('join_user_to_guild - SUCCESS - join %s to %s (%s) via endpoint %s', request.endpoint,
                        userid, guildid, r.status_code, request.endpoint)
    else:
        app.logger.error('join_user_to_guild - FAILURE - join %s to %s (%s) via endpoint %s', request.endpoint,
                         userid, guildid, r.status_code, request.endpoint)
    return r


def send_to_known_channel(significance, json_payload):
    channel = nrdb.get_channel_by_significance(app.config["GUILD_ID"], significance)
    r = requests.post(
        app.config["API_BASE_URL"] + "/channels/" + channel["id"] + "/webhooks",
        headers={"Authorization": "Bot " + app.config["BOT_TOKEN"]},
        json={"name": "https://neteng.xyz"},
    )
    r.raise_for_status()
    webhook = r.json()
    r = requests.post(
        app.config["API_BASE_URL"]
        + "/webhooks/"
        + webhook["id"]
        + "/"
        + webhook["token"],
        json=json_payload,
    )
    r.raise_for_status()
    r = requests.delete(
        app.config["API_BASE_URL"]
        + "/webhooks/"
        + webhook["id"]
        + "/"
        + webhook["token"]
    )
    r.raise_for_status()


def assign_role(significance, member):
    user = enrich_member(member)
    role = nrdb.get_role_by_significance(app.config["GUILD_ID"], significance)
    if role['id'] in user['roles']:
        return False
    else:
        member_id = user['id']
        r = requests.put(
            app.config["API_BASE_URL"]
            + "/guilds/"
            + app.config["GUILD_ID"]
            + "/members/"
            + member_id
            + "/roles/"
            + role["id"],
            headers={"Authorization": "Bot " + app.config["BOT_TOKEN"]},
        )
        r.raise_for_status()
        return True


@app.template_filter("utctime")
def utctime(s):
    return datetime.utcfromtimestamp(s).strftime("%Y-%b-%d %H:%M:%S UTC")


@app.route("/")
@app.route("/home")
@register_breadcrumb(app, ".", "Home")
def home():
    general_members = g.db.db.users.count({"permanent_roles": {"$all": ["Member"]}})
    periphery_members = g.db.db.users.count({"permanent_roles": {"$all": ["periphery"]}})
    unaccepted_members = g.db.db.users.count() - periphery_members - general_members
    return render_template(
        "home.html",
        general_members=general_members,
        periphery_members=periphery_members,
        unaccepted_members=unaccepted_members,
    )


@app.route("/rules")
@register_breadcrumb(app, ".rules", "Rules")
def rules():
    return render_template(
        "rules.html"
    )


@app.route("/members")
@has_role(role_significance="Member", fail_action="403")
@register_breadcrumb(app, ".members", "Members")
def members():
    memberlist = g.db.db.users.find({"member_number": {"$exists": True}})
    return render_template("members.html", memberlist=memberlist)


def userid_breadcrumb_constructor(*args, **kwargs):
    if "userid" in request.view_args:
        userid = request.view_args["userid"]
    else:
        userid = int(g.user["id"])
    user = g.db.db.users.find_one(
        {"_id": userid}, {"name": True, "discriminator": True}
    )
    return [
        {
            "text": user["name"] + "#" + user["discriminator"],
            "url": url_for(request.endpoint, userid=userid),
        }
    ]


@app.route("/myprofile")
@has_role()
@register_breadcrumb(
    app, ".members.user_id", "", dynamic_list_constructor=userid_breadcrumb_constructor
)
def myprofile():
    user = g.db.db.users.find_one({"_id": int(g.user["id"])})
    user = enrich_user(user)
    return render_template("profile.html", user=user)


@app.route("/members/<int:userid>")
@has_role(role_significance="Member", fail_action="join")
@register_breadcrumb(
    app, ".members.user_id", "", dynamic_list_constructor=userid_breadcrumb_constructor
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
    try:
        token = g.discord.fetch_token(
            app.config["TOKEN_URL"],
            client_secret=app.config["OAUTH2_CLIENT_SECRET"],
            authorization_response=request.url,
            headers={'Content-Type': "application/x-www-form-urlencoded"},
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


@app.route("/join", methods=["GET", "POST"])
@app.route("/join/<postlogin>", methods=["GET", "POST"])
@register_breadcrumb(app, ".join", "Join")
def join(postlogin=None):
    class JoinForm(FlaskForm):

        accept_general_rules = BooleanField(
            "I have read and accept the general rules.",
            validators=[InputRequired()],
            id="accept-general-rules",
        )
        accept_member_rules = BooleanField(
            "I have read and accept the additional full membership rules.",
            validators=[InputRequired()],
            id="accept-member-rules",
        )
        choices = [
            ("", ""),
            ("Member", "Enterprise networking, enterprise wifi, and VOIP"),
            ("periphery", "Home routers, wifi, servers, computers, and peripherals"),
            ("Member", "Network automation and DevOps"),
            (
                "periphery",
                "General business or enterprise information technology, server administration, or coding",
            ),
            ("Member", "Service provider networking, BGP, and MPLS"),
            (
                "Member",
                "I'm a student studying for enterprise or service provider networking",
            ),
        ]
        userclass = SelectField(
            "What would you like to talk about on the server?",
            choices=choices,
            validators=[InputRequired()],
            id="userclass",
        )

    def set_userclass_role():
        if "Member" in g.user["permanent_roles"]:
            userclass = "Member"
            announcechannel = "greeting"
        elif "periphery" in g.user["permanent_roles"]:
            userclass = "periphery"
            announcechannel = "periphery_greeting"
        if assign_role(userclass, g.user):
            flash(
                "Your userclass role has been synchronized on Discord. Please check your Discord client to find your new channels.",
                category="success",
            )
            user = nrdb.get_user(g.user["id"])
            member_number = user["member_number"]
            json_payload = {
                "content": f"Welcome <@{g.user['id']}>, member #{member_number}! We're happy to have you. Please feel free to take a moment to introduce yourself!"
            }
            send_to_known_channel(announcechannel, json_payload)
        else:
            flash("You're already joined to the server with a synchronized role.", category="warning")

    if "user" not in g:
        return login(postlogin=postlogin, scope="identify guilds.join")
    # Check if the user is already a Member or periphery.
    elif {"Member", "periphery"}.intersection(g.user["permanent_roles"]):
        # Join the user to the guild since we have permission and the user is an accepted member.
        r = join_user_to_guild(
            app.config["GUILD_ID"],
            session["oauth2_token"]["access_token"],
            g.user["id"],
        )
        if r.status_code == 204:
            # User is already in the guild.
            set_userclass_role()
        elif r.status_code == 201:
            # User was joined to the guild.
            set_userclass_role()
            flash(
                "You've joined the Discord server! Please check your Discord client to find it in your server list.",
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
        form = JoinForm()
        if form.userclass.data != 'Member':
            form.accept_member_rules.validators = []
        if form.validate_on_submit():
            # The user has completed the form successfully. Now we need to add them to the appropriate role in the DB.
            if form.userclass.data in ['Member', 'periphery']:
                nrdb.upsert_member(g.user, [form.userclass.data])
                return redirect(url_for("join", postlogin=postlogin))
        # Ask where they want to join
        return render_template("join.html", form=form)


@app.route("/logout")
def logout():
    if request.values.get("error"):
        return request.values["error"]
    session.clear()
    redirect_target = url_for("home")
    flash("Logged out successfully.", category="info")
    return redirect(redirect_target)
