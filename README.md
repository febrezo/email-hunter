# Enail Hunter

Copyright (C) 2023  F. Brezo ([@febrezo](https://mastodon.social/@febrezo))

[![License](https://img.shields.io/badge/license-GNU%20General%20Public%20License%20Version%203%20or%20Later-blue.svg)]()

![Welcome screen](img/hi.png)

## Description

Another package to analyse emails to find potential threats.
It has been originally developed as a PoC for fun to do some work on MSG parsing and identify potential indicators of compromise of [CVE-2023-23397](https://msrc.microsoft.com/update-guide/en-EN/vulnerability/CVE-2023-23397) in those files.

Note that if you are looking for fast detection you might be interested on trying [specific Yara Rules](https://github.com/Neo23x0/signature-base/search?q=cve-2023-23397&type=commits).

## License: GNU GPLv3+


This is free software, and you are welcome to redistribute it under certain conditions.

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.


For more details on this issue, check the [COPYING](COPYING) file.

## Installation

This package can be installed from [PyPI](https://pypi.org).

```
$ pip3 install email-hunter
```

For local development, you can clone the repository and install it manually on your system:

```
$ git clone https://github.com/febrezo/email-hunter
$ cd email-hunter
$ pip3 install -e .
```

## Usage

The Python package will install a CLI tool to interact with locally downloaded files or folders.

```
usage: email-hunter -i LOCAL_PATH [LOCAL_PATH ...] [-o LOCAL_PATH] [-l LOG_LEVEL] [-h] [--version]

Launch Email Hunter CLI.

options:
  -i LOCAL_PATH [LOCAL_PATH ...], --input LOCAL_PATH [LOCAL_PATH ...]
                        The files or folders to analyse. If the location is a folder, all the files in the folder will be processed. Note that several paths can be provided.
  -o LOCAL_PATH, --output LOCAL_PATH
                        If present, an output file will be generated with the results. Note that thif the extension is ".csv", the output will be created as a CSV file. Otherwise, the output will be a JSON
                        file. If no value is provided, the output will be displayed as in the console.
  -l LOG_LEVEL, --log-level LOG_LEVEL
                        It sets the log level for the application. Possible options: DEBUG, INFO, WARNING, ERROR. Default: "INFO".

About this package:
  Get additional information about this package.

  -h, --help            shows this help and exits.
  --version             shows the version of this package and exits.

```

Thus, you can run the application against the files in a folder:

```
$ email-hunter -i examples
```

![Demo output](img/output.png)

# How does it suggest the detection of a potential threat?

Basically, the util parses the MSG files to search any property that contains a Universal Naming Convention (UNC) Path. 
These paths are exploited in the wild as a result of how Microsoft Outlook deals with a special property in email appointments, `[PidLidReminderFileParameter`](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/b1d6170c-3824-4167-987e-8626cc396664).
Basically, this property lets Microsoft Outlook locate a sound file in a shared location to be reproduced whenever the appointment is reached.
Knowing that (and updating the [PidLidReminderOverride](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/d00d3723-be29-464d-adc9-25378ad8e1d5.) property too, an attacker can redirect the NTLM authentication process started automatically by Microsoft Outlook to their own infrastructure and have access to the NTLM hash of the victim, resulting in a potential Privilege Elevation issue.
The CVE was released on March 14th and PoC were soon proving that it could be exploited such as [this](https://www.mdsec.co.uk/2023/03/exploiting-cve-2023-23397-microsoft-outlook-elevation-of-privilege-vulnerability/).

## Examples

In the [`./examples`](./examples) folder there are some email files which have been grabbed from VirusTotal matching different retrohunting Yara rules.
Note that some of the files can be tracked back to May 2022 (such as [`7fb7a2394e03cc4a9186237428a87b16f6bf1b66f2724aea1ec6a56904e5bfad`](https://www.virustotal.com/gui/file/7fb7a2394e03cc4a9186237428a87b16f6bf1b66f2724aea1ec6a56904e5bfad)).