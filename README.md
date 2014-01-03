pyjuice
=======

## Description

pyJuice is an open source tool for retrieving and decrypting your latest JuiceSSH CloudSync 
backup and extracting the private keys into ~/.ssh.

In order to have any use of this script you need to have the PRO version of JuiceSSH (https://sonelli.com/) and have CloudSync turned ON.

* Obtains an OAUTH2 authentication token from Google API
* Authenticates with the JuiceSSH API
* Retrieves your latest encrypted CloudSync backup in JSON format
* Decrypts the backup using a user provided passphrase
* Saves the private keys in ~/.ssh with permission 0600

## TODO

* Better error-handling
* Only update files if timestamp has changed for entry.
* Handle deleted identities(?)
* Come up with more features to implement
* Allow forcing update of the encrypted json file and not just every 30 minutes.
* Remove unneeded output and add actual debug output instead.
* Write tests (any volunters?)

## Install

First download and install Python 2.7. 
On Ubuntu this is as easy as:

```bash
$ sudo apt-get install python2.7 python-pip
```

For other platforms use your packet manager (if any) or download from an installer from http://www.python.org/getit/.

```bash
# Fetch the source
$ cd ~
$ git clone https://github.com/markus-li/pyjuice.git pyjuice

# Get required modules (use virtualenv if you want/need)
# 
$ sudo pip install requests argparse requests-oauthlib passlib pycrypto
```

## Usage

```bash
# Run it!
$ ~/pyjuice/pyjuice.py
```

## Credits and License

Markus Liljergren created this small piece of software, but the main software behind CloudSync is JuiceSSH for Android from Sonelli Ltd (https://sonelli.com/). 

Neither me nor this script has any affiliation with Sonelli Ltd, but if you like this piece of software, get the Pro version of JuiceSSH and support Sonelli Ltd.

Lots of thanks to Paul Maddox for providing me with the information needed in order to interact with the CloudSync API.

pyJuice is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

pyJuice is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
