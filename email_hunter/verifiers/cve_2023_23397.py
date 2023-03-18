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


import logging
import json
import re
import compoundfiles

from outlook_msg import Message
from extract_msg import openMsg
from dateutil.parser import parse
from  email_hunter.utils.colors import colorize


class CVE_2023_23397Verifier:
    """A verifier for CVE-2023-23397"""
    def __init__(self):
        """Constructor
        """

    def verify(file_path):
        """Verifies CVE-2023-23397 exploitation attempts

        Args:
            file_path (str): The file path to a MSG file.

        Returns:
            dict. A dict representing the result:
                {
                    "file_path": "<FILE_PATH>",
                    "status": "(clean|unknown|infected)",
                    "name": "CVE-2023-23397",
                    "description": "Description message for the verification performed",
                    "indicators": [
                        "1.1.1.1"
                    ]
                }
        """
        logging.debug(f"Extracting metadata from '{colorize(file_path, 'BOLD')}'…")
        result = {
            "file_path": file_path,
            "status": "unknown",
            "name": "CVE-2023-23397",
            "description": "Verification of a potential exploiting attempt of CVE-2023-23397.",
            "indicators": [],
            "metadata": {}
        }
    
        try:
            # TODO: Improve parsing only using one of the libraries either outlook_msg or extract_msg. extract_msg seems not to have fully implemented the 
            #   extraction of elements from properties in VariableLengthProp.
            with open (file_path) as msg_file:
                msg = Message(msg_file)
        except compoundfiles.errors.CompoundFileInvalidMagicError as _:
            logging.warning(colorize(f"The file '{file_path}' could not be opened as a MSG file.", "WARNING"))
            return result

        # TODO: Improve parsing only using one of the libraries either outlook_msg or extract_msg. office_msg has a worse API for parsing the email
        parsed_msg = openMsg(file_path)
        result["metadata"] = json.loads(parsed_msg.getJson())
        result["metadata"]["date"] = parse(result["metadata"]["date"]).isoformat()
        result["metadata"]["attachments"] = parsed_msg.attachments

        try: 
            # Grabbing Property: prop_id='Unk: 0x8015', prop_type='PtypeString', full_tag='0x8015001F'
            for i, e in enumerate(msg.mfs.storage):
                try:
                    value = msg.mfs.read_storage(e.name).decode("utf-16")
                    unc_paths = re.findall(r"^\\{2}.+$", value)
                    if unc_paths:
                        logging.info(colorize(f"Potential exploitation of CVE-2023-23397 identified in '{file_path}'. Indicator found: '{value}'.", "ERROR BOLD"))
                        result["indicators"].append(value)
                        #result["indicators"] += re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', value)
                        result["status"] = "infected"
                except (compoundfiles.errors.CompoundFileNotStreamError, UnicodeDecodeError) as _:
                    logging.debug(f"{e.name} seems not to be a string property.")
        except KeyError as _:
            logging.info(colorize(f"No signs of explotation of CVE-2023-23397 in '{file_path}'.", "SUCCESS"))
            result["status"] = "clean"
        return result

