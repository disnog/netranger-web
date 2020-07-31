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

from flask import redirect, url_for, render_template, request, session, g
from flask_breadcrumbs import register_breadcrumb
from nrweb import app
from requests_oauthlib import OAuth2Session
import urllib.parse
import json
from flask_pymongo import PyMongo
import uuid
from functools import wraps
from datetime import datetime


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


def is_member(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        # Check if user is logged in
        if "user" in g:
            return f(*args, **kwargs)
        else:
            return redirect(url_for("login"))

    return decorator

@app.template_filter('utctime')
def utctime(s):
    return datetime.utcfromtimestamp(s).strftime(
                "%Y-%b-%d %H:%M:%S UTC"
            )


@app.route("/")
@app.route("/home")
@register_breadcrumb(app,'.',"Home")
def home():
    registered_members = g.db.db.users.count({"member_number": {"$exists": True}})
    unaccepted_members = g.db.db.users.count({"member_number": {"$exists": False}})
    print()
    return render_template("home.html",registered_members=registered_members,unaccepted_members=unaccepted_members)


@app.route("/members")
@is_member
@register_breadcrumb(app,'.home',"Members")
def members():
    memberlist = g.db.db.users.find({ "member_number": { "$exists": True } })
    return render_template("members.html",memberlist=memberlist)


@app.route("/myprofile")
@is_member
def myprofile():
    return redirect(url_for("members", userid=g.user["id"]))

def userid_breadcrumb_constructor(*args, **kwargs):
    user = g.db.db.users.find_one({"_id": request.view_args['userid']},{ 'name':True,'discriminator':True })
    return [{'text': user['name']+'#'+user['discriminator'], 'url': url_for(request.endpoint,userid=request.view_args['userid'])}]

@app.route("/members/<int:userid>")
@is_member
@register_breadcrumb(app,'.home.myprofile','Profile',dynamic_list_constructor=userid_breadcrumb_constructor)
def profile(userid):
    return render_template("profile.html", userid=userid)


@app.route("/login")
@app.route("/login/<postlogin>")
def login(postlogin=None):
    scope = request.args.get("scope", "identify")
    discord = make_session(scope=scope.split(" "))
    authorization_url, state = discord.authorization_url(app.config["AUTHORIZATION_BASE_URL"])
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
