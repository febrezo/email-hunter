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


import argparse
import csv
import glob
from importlib.metadata import version
import json
import logging
import os

from prettytable import PrettyTable

from email_hunter.utils.colors import colorize
from email_hunter.utils.fortunes import get_fortune
from email_hunter.verifiers.cve_2023_23397 import CVE_2023_23397Verifier

def main():
    """Main function that starts the loop"""
    banner = """
         _____                 _ _   _   _             _            
        | ____|_ __ ___   __ _(_) | | | | |_   _ _ __ | |_ ___ _ __ 
        |  _| | '_ ` _ \ / _` | | | | |_| | | | | '_ \| __/ _ \ '__|
        | |___| | | | | | (_| | | | |  _  | |_| | | | | ||  __/ |   
        |_____|_| |_| |_|\__,_|_|_| |_| |_|\__,_|_| |_|\__\___|_|   
                                                        
    """

    welcome = f"""

{colorize(banner, "INFO BOLD")}

                        Coded with {colorize("♥", "ERROR")} by """
    welcome += f"""{colorize("Félix Brezo", "SUCCESS BOLD")}


Email Hunter CLI is a command line interface to analyse emails and locate
potential security risks.

To get additional information about the available commands type """
    welcome += f"""'{colorize("help", "BOLD")}'.

{colorize(get_fortune().center(80), "WARNING BOLD")}

"""

    parser = argparse.ArgumentParser(
        description='Launch Email Hunter CLI.',
        add_help=False
    )
    parser.add_argument(
        '-i', '--input',
        metavar='LOCAL_PATH',
        required=True,
        nargs="+",
        help='The files or folders to analyse. If the location is a folder, all the files in the folder will be processed. Note that several paths can be provided.'
    )
    parser.add_argument(
        '-o', '--output',
        metavar='LOCAL_PATH',
        required=False,
        help='If present, an output file will be generated with the results. Note that thif the extension is ".csv", the output will be created as a CSV file. Otherwise, the output will be a JSON file. If no value is provided, the output will be displayed as in the console.'
    )
    parser.add_argument(
        '-l', '--log-level',
        metavar='LOG_LEVEL',
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help='It sets the log level for the application. Possible options: DEBUG, INFO, WARNING, ERROR. Default: "INFO".'
    )

    # About options
    # -------------
    groupAbout = parser.add_argument_group(
        'About this package',
        'Get additional information about this package.'
    )
    groupAbout.add_argument(
        '-h', '--help',
        action='help',
        help='shows this help and exits.'
    )
    groupAbout.add_argument(
        '--version',
        action='version',
        version='%(prog)s ' + version('email_hunter'),
        help='shows the version of this package and exits.'
    )

    args = parser.parse_args()

    print(welcome)

    logging.basicConfig(
        level=args.log_level,
        format=f"[%(levelname)s] %(asctime)s | %(message)s",
        handlers=[
            #logging.FileHandler(f'./email-hunter.log'),
            logging.StreamHandler()
        ]
    )

    results = []

    counter = 0
    for file_path in args.input:
        if os.path.isfile(file_path):
            counter += 1
            logging.info(f"File #{counter}: Starting analysis of '{colorize(file_path, 'BOLD')}'…")
            results.append(CVE_2023_23397Verifier.verify(file_path))
        else:
            file_paths = glob.glob(f"{file_path}/*", recursive=True)
            for file_path in file_paths:
                if os.path.isfile(file_path):
                    counter += 1
                    logging.info(f"File #{counter}: Starting analysis of '{colorize(file_path, 'BOLD')}'…")
                    results.append(CVE_2023_23397Verifier.verify(file_path))

    if args.output:
        logging.info(f"Storing results in '{args.output}'…")
        if not args.output.endswith(".csv"):
            with open(args.output, "w")  as json_file:
                json.dump(json_file, results, indent=2)
        else:
            with open(args.output, 'w') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow(results[0].keys())  # header row
                for row in results:
                    writer.writerow(row.values())
    else:
        results_table = PrettyTable()
        results_table.field_names = [
            "File", 
            "Analysis", 
            "Status", 
            "Indicators",
            "Date",
            "Recipients",
        ]

        for r in results:
            status = r.get("status").title()
            results_table.add_row([
                r.get("file_path"), 
                r.get("name"), 
                colorize(status, "SUCCESS BOLD") if status == "Clean" else colorize(status, "ERROR BOLD") if status == "Infected" else status, 
                r.get("indicators"), 
                r.get("metadata", {}).get("date"), 
                r.get("metadata", {}).get("to")
            ])
        logging.info(f"Listing results:\n{results_table}")


if __name__ == '__main__':
    main()
