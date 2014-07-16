pyjuice
=======

## Description

pyJuice is a GPLv3 open source tool for interacting with JuiceSSH CloudSync. JuiceSSH for Android can be found at https://sonelli.com .

It can also be used to keep track of all your server credentials and let you use the data you have entered in JuiceSSH directly in your shell. Works for SSH connections, other types will come.

pyJuice does everything I personally have need for already, if you want any particular functionality implemented add a new issue as a "question" in order to motivate me. It's much more fun to develop something if you know there are people using it.

In order to have any use of this script you need to have the PRO version of JuiceSSH (https://sonelli.com/) and have CloudSync turned ON and include Identities.

* Obtains an OAUTH2 authentication token from Google API
* Authenticates with the JuiceSSH API
* Retrieves your latest encrypted CloudSync backup in JSON format
* Decrypts the backup using a user provided passphrase
* Saves the private keys in ~/.ssh with permission 0600

This tool is used as part of daily work, if and when bugs are discovered they are fixed, but no thourough testing has been performed nor any unit testing implemented. 
With this said, the tool works and is a great way of handling multiple server credentials in a secure way.

##NOTE

It is not great having everything in one file, but for the sake of easily copying the file between systems, this is how I want it. 
In the future I might split it and create an auto-merged version, but for now, this will have to do.

## TODO

* Better error-handling
* Only update files if timestamp has changed for entry.
* Handle deleted identities(?)
* Full READ support for everything in the backup except EC2-related entries.
* Don't update com.sonelli.juicessh.models.ConnectionCounter, at least for now
* Encrypt and upload changes. Need full READ support of everything I use first.
* Come up with more features to implement
* ~~Fix issues with password-only login over ssh. The whole terminal can't be used when pexpect controls the session.~~
* Try different methods of authentication in succession if one fails, lastly fall back to asking the user for manual authentication, if possible.
* Handle incorrect json data gracefully instead of crashing.
* Make sure the daemon does NOT crash/hang when sent garbage. This should be the case now, but tests need to be written.
* Add logging facilities to the daemon?
* Fork each connection to the daemon to handle simultaneous connections. Is this really needed?
* Write tests (any volunters?)
* Full READ support for the remaining data, including EC2-related entries. I won't implement support for that though since I don't use it.
* ~~Scramble the passphrase in memory when not in direct use by the daemon? How necessary is this?~~Not feasibly achieved in Python, can be done, but "shouldn't" be done...

## Install

First download and install Python 2.7 and pip. 
On Ubuntu this is as easy as:

```bash
$ sudo apt-get update && sudo apt-get install python2.7 python-pip python2.7-dev python-requests-oauthlib python-pbkdf2 python-passlib
```

For other platforms use your packet manager (if any) or download an installer from http://www.python.org/getit/.

```bash
# Fetch the source
$ cd ~
$ git clone https://github.com/markus-li/pyjuice.git pyjuice

# Get required modules (use virtualenv if you want/need)
$ sudo pip install requests argparse requests-oauthlib passlib pycrypto setproctitle texttable pexpect
```

## Usage

```bash
# Run it!
$ ~/pyjuice/pyjuice.py sync

# For help, run this:
$ ~/pyjuice/pyjuice.py -h
```

## Additional notes regarding the json-data

All IDs are Version 4 UUIDs

com.sonelli.juicessh.models.Connection[]["type"]:
0 = ssh
1 = mosh
2 = local device
3 = telnet

com.sonelli.juicessh.models.Team:
What is encryptionTest?

com.sonelli.juicessh.models.TeamEncryption:
How is data encrypted here?
What is encrypted here?

## Bugs, Features & Pull requests

Please reports bugs through the Issues section at GitHub (https://github.com/markus-li/pyjuice/issues). Feature requests are also very welcome. 

If you want to fix or add something yourself, please do so and send me a pull request.

## Credits and License

Markus Liljergren created this small piece of software, but the main software behind CloudSync is JuiceSSH for Android from Sonelli Ltd (https://sonelli.com/). 

Neither me nor this script has any affiliation with Sonelli Ltd, but if you like this piece of software, get the Pro version of JuiceSSH and support Sonelli Ltd.

Lots of thanks to Paul Maddox for providing me with the information needed in order to interact with the CloudSync API.

pyJuice is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

pyJuice is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
