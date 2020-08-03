# nrweb - nrdb.py
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

from flask import g


def get_guild(guild_id):
    return g.db.db.guilds.find_one({"_id": guild_id})


def get_role_by_common_name(guild_id, role_cn):
    r = g.db.db.guilds.find_one({"_id": guild_id, "known_roles.significance": role_cn})
    return r["known_roles"][0]
