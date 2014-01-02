#!/usr/bin/env python
#
# pyJuice is an open source tool for recieving and decrypting your latest JuiceSSH CloudSync 
# backup and extracting the private keys into ~/.ssh.
#
# 
#    This file is part of pyJuice.
#
#    Foobar is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    pyJuice is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with pyJuice.  If not, see <http://www.gnu.org/licenses/>.
#
#

# Settings
token_file = '~/.pyjuice.token'
encrypted_data_file = '~/.pyjuice.encrypted_data'
client_id = '384598528408-g6urjkc21c6u9kv1gchu4b6rl0il7p0l.apps.googleusercontent.com'
client_secret = 'cka5jVJHSS49e6_8PyntUgXx'

# Libraries
import requests
import json
import argparse
import os
import stat
import datetime, time
from pprint import pprint
from requests_oauthlib import OAuth2Session
import base64
# http://pythonhosted.org/passlib/lib/passlib.utils.pbkdf2.html
from passlib.utils.pbkdf2 import pbkdf2
# http://stackoverflow.com/questions/12562021/aes-decryption-padding-with-pkcs5-python
from Crypto.Cipher import AES
from Crypto import Random


# Constants
ITERATION_COUNT = 1000
SALT_LENGTH = 8
KEY_LENGTH = 32 # 32bytes = 256bits = AES256
BS = 16



pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[0:-ord(s[-1])]

# Class for encrypting/decrypting using AES
class AESCipher:
  def __init__( self, passphrase ):
    """
    Requires a plain text passphrase
    """
    self.passphrase = passphrase

  def encrypt( self, raw ):
    """
    Returns encrypted value encoded in b64 with salt, iv and cipher text
    separated by #.
    """
    raw = pad(raw)
    iv = Random.new().read(AES.block_size);
    cipher = AES.new( self.key, AES.MODE_CBC, iv )
    return ( iv + cipher.encrypt( raw ) )

  def decrypt( self, b64_data ):
    """
    Requires b64 data separated by # to decrypt
    """
    # TODO: Verify the data and add a try statement
    salt, iv, cipher_text = b64_data.split('#', 3)
    salt = base64.standard_b64decode(salt)
    iv = base64.standard_b64decode(iv)
    cipher_text = base64.standard_b64decode(cipher_text)
    key = pbkdf2(self.passphrase, salt, ITERATION_COUNT, keylen=KEY_LENGTH)
    cipher = AES.new(key, AES.MODE_CBC, iv )
    return unpad(cipher.decrypt( cipher_text ))
  
class OldData(Exception):
  pass

# Variables used by the script
redirect_uri = 'urn:ietf:wg:oauth:2.0:oob'
authorization_base_url = 'https://accounts.google.com/o/oauth2/auth'
token_url = 'https://accounts.google.com/o/oauth2/token'
scope = ['https://www.googleapis.com/auth/userinfo.profile',
         'https://www.googleapis.com/auth/userinfo.email']

# Any and all files we create should be restricted to the current user ONLY!
os.umask(077)

parser = argparse.ArgumentParser(prog='pyjuice', description='pyJuice is an open source tool for recieving and decrypting your ' +
         'latest JuiceSSH CloudSync backup and extracting the private keys into ~/.ssh.')
parser.add_argument('-p', '--passphrase', type=str, required=False, help='Set the passphrase (INSECURE!). Do NOT use this unless ' +
         'you KNOW that noone can list your process and get your argument. Clean your history after using this!')

args = parser.parse_args()

if args.passphrase != None:
  passphrase = args.passphrase
else:
  # We need the passphrase before continuing...
  passphrase = raw_input("Please enter your PASSPHRASE: ")

# Make sure we have a token using Google oauth2
token_updated = False
try:
  token = json.load(open(os.path.expanduser(token_file)))
  print "Retrieved previously stored token..."
  oauth = OAuth2Session(client_id, token=token)
  
  if time.time() - token['timestamp'] >= token['expires_in']:
    print "Refreshing token..."
    extra = {'client_id': client_id,
             'client_secret': client_secret,}
    token = oauth.refresh_token(token_url, **extra)
    token_updated = True
except (ValueError, IOError) as e:
  print 'No refresh_token saved, user need to provide authorization...'
  
  oauth = OAuth2Session(client_id, scope=scope, redirect_uri=redirect_uri)
  
  authorization_url, state = oauth.authorization_url(authorization_base_url, access_type='offline', approval_prompt='force')
  
  print "Follow this URL to authorize access for pyJuice:"
  print authorization_url
    
  user_code = raw_input('Paste the user code here:')
  
  token = oauth.fetch_token(token_url, client_secret=client_secret, code=user_code)
  token_updated = True

# In case the token was updated, write it to file with a new timestamp.
if token_updated:
  print "Token updated, saving to %s..." % token_file
  token['timestamp'] = time.time()
  json.dump(token, open(os.path.expanduser(token_file), 'w'))

try:
  cloudsync = json.load(open(os.path.expanduser(encrypted_data_file)))
  if datetime.datetime.now() - datetime.datetime.fromtimestamp(cloudsync[u'date']) >= datetime.timedelta(minutes=30):
    print "Time to update the data from CloudSync..."
    raise OldData
  print "Retrieved previously stored encrypted data..."
  
except (ValueError, IOError, OldData) as e:
  print "No up-to-date encrypted data found locally, retreiving it from Sonelli CloudSync..."
  print('---------------')
  r = requests.get("https://api.sonelli.com/authenticate/%s" % (token['access_token']))
  authenticate = r.json()
  cookies = dict(session=authenticate[u'session'][u'identifier'])
  print('---------------')
  
  #curl -XPOST -d '{}' -H "Cookie: session=s%3ASeyAwfSd8zdfA9CceY8KI4zP.5rSCoj%2BVty1jCsEFUygprwBIFsqOhcj9sLegOqHzZJI" https://api.sonelli.com/cloudsync
  
  r = requests.post('https://api.sonelli.com/cloudsync', cookies=cookies)
  cloudsync = r.json()
  json.dump(cloudsync, open(os.path.expanduser(encrypted_data_file), 'w'))


#pprint(cloudsync)
#print datetime.datetime.fromtimestamp(cloudsync[u'date']).strftime('%Y-%m-%d %H:%M:%S')




identities = cloudsync[u'objects'][u'com.sonelli.juicessh.models.Identity']

pprint(identities)
i=0
for identity in identities:
  if identity[u'_encrypted']:
    # https://github.com/Sonelli/gojuice/blob/master/crypto/aes/aes.go
    print "The data is encrypted!"
    data = identity[u'data']
    
    decryptor = AESCipher(passphrase)
    text = decryptor.decrypt(data)
    json_data = json.loads(text)
    print "1----------------------------"
    pprint(json_data)
    
    print "2----------------------------"
    try:
      json_data[u'password'] = decryptor.decrypt(json_data[u'password'])
    except (KeyError, ValueError) as e:
      json_data[u'password'] = ''
      pass
    try:
      json_data[u'privatekey'] = decryptor.decrypt(json_data[u'privatekey'])
    except (KeyError, ValueError) as e:
      json_data[u'privatekey'] = ''
      pass
    try:
      json_data[u'privatekeyPassword'] = decryptor.decrypt(json_data[u'privatekeyPassword'])
    except (KeyError, ValueError) as e:
      json_data[u'privatekeyPassword'] = ''
      pass
    pprint(json_data)
    
    if json_data[u'privatekey'] != '':
      private_key_filename = "~/.ssh/juice_" + json_data[u'nickname'] + "_" + str(i)
      private_key_file = open(os.path.expanduser(private_key_filename), "w")
      private_key_file.write(json_data[u'privatekey'])
      private_key_file.close()
      print "Created/updated %r..." % str(private_key_filename)
    
  i+=1  
  print "----------------------------"



  

