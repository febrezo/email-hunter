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


import colorama


def colorize(text, messageType=None):
    """Function that colorizes a message.

    Args:
        text: The string to be colorized.
        messageType: Possible options include "ERROR", "WARNING", "SUCCESS",
            "INFO" or "BOLD".

    Returns:
        string: Colorized if the option is correct, including a tag at the end
            to reset the formatting.
    """
    formattedText = str(text)
    # Set colors
    if "ERROR" in messageType:
        formattedText = colorama.Fore.RED + formattedText
    elif "WARNING" in messageType:
        formattedText = colorama.Fore.YELLOW + formattedText
    elif "SUCCESS" in messageType:
        formattedText = colorama.Fore.GREEN + formattedText
    elif "INFO" in messageType:
        formattedText = colorama.Fore.BLUE + formattedText

    # Set emphashis mode
    if "BOLD" in messageType:
        formattedText = colorama.Style.BRIGHT + formattedText

    return formattedText + colorama.Style.RESET_ALL
