###############################################################################
#
#   Copyright 2023 @ Félix Brezo (@febrezo)
#
#   Email Hunter is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program. If not, see <http://www.gnu.org/licenses/>.
#
###############################################################################

import random

MESSAGES = [
    "-- Emailing never gets old. --",
    "-- I tend to confuse my inbox with the recycle bin. --",
    "-- I'll kepp the email there just in case I can read it… Later. --",
    "-- Productivity is inversely related to the emails received. --",
]

def get_fortune():
    """Get a fortune

    Returns:
        str.
    """
    return random.choice(MESSAGES)
