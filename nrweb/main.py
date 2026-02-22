# main.py
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

"""Entry point for the nrweb Flask application."""

from nrweb import app
from nrweb.config import get_settings


def main():
    settings = get_settings()
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=settings.debug,
    )


if __name__ == "__main__":
    main()
