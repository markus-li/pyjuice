#!/usr/bin/env python
#
# pyJuice is an open source tool for retrieving and decrypting your latest JuiceSSH CloudSync 
# backup and extracting the private keys into ~/.ssh.
#
# 
#    This file is part of pyJuice.
#
#    pyJuice is free software: you can redistribute it and/or modify
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
unix_socket = '~/.pyjuice.socket'
daemon_pid_file = '~/.pyjuice.daemon_pid'
daemon_stdout_file = '~/.pyjuice.daemon_stdout'
daemon_stderr_file = '~/.pyjuice.daemon_stderr'
client_id = '384598528408-g6urjkc21c6u9kv1gchu4b6rl0il7p0l.apps.googleusercontent.com'
client_secret = 'cka5jVJHSS49e6_8PyntUgXx'

# Libraries
import requests
import json
import argparse
import socket
import os
import sys
import pwd
import stat
import signal
import setproctitle
import resource
import datetime, time
from pprint import pprint
import getpass
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


class AESCipherClient:
  def __init__( self, unix_socket ):
    """
    Requires a unix socket
    """
    self.unix_socket = unix_socket
  
  def check_safe_socket( self ):
    """
    Checks the permissions of the daemon socket and exits
    if it not owned by the same user as the process id as
    well as only is read/writable by the owner.
    """
    
    safe = False
    permission = oct(os.stat(self.unix_socket)[stat.ST_MODE])
    stat_info = os.stat(self.unix_socket)
    if (permission == '0140700' or
       permission == '0140600'):
      if stat_info.st_uid == os.geteuid():
        safe = True
    
    if safe:
      return True
    else:
      print 'Unsafe socket %r (%s, user=%s), exiting... Restarting the daemon should fix this.' % (self.unix_socket, permission, pwd.getpwuid(stat_info.st_uid)[0])
      exit(1)
  
  def _send( self, action, b64_data ):
    """
    Sends action+data through socket and expects a reply.
    """
    if len(action) != 7:
      # This can only happen if there is something wrong in the code...
      print >>sys.stderr, 'action has to have a length of 7 characters!'
      exit(1)
      
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    #print >>sys.stderr, 'connecting to %s' % self.unix_socket
    try:
      sock.connect(self.unix_socket)
    except socket.error, msg:
      if action == 'HELLO::':
        return False
      else:
        print >>sys.stderr, msg
        exit(1)
    
    try:
      # Send b64_data
      #print >>sys.stderr, 'sending "%s::%s"' % (action, b64_data)
      sock.send( '--START--' )
      sock.sendall(action + '::' + b64_data)
      sock.send( '--DONE---' )
          
      save_data = False
      data_buf = ''
      while True:
        data = sock.recv(16)
        #print >>sys.stderr, 'received "%s"' % data
        if data:
          if save_data:
            data_buf += data
          if '--START--' == data[:9]:
            save_data = True
            data_buf = data[9:]
          elif '--DONE---' == data_buf[-9:]:
            save_data = False
            data_buf = data_buf[:-9]
            #print >>sys.stderr, 'Got this back from the server:\n%r' % data_buf
            if action == 'HELLO::' and data_buf == 'HELLO::::':
              return True
            elif action == 'HELLO::' and data_buf != 'HELLO::::':
              return False
            
            return base64.standard_b64decode(data_buf)
        else:
          if action == 'HELLO::':
            return False
          else:
            print >>sys.stderr, 'ERROR! No more data from', client_address
            exit(1)
    finally:
      #print >>sys.stderr, 'closing socket'
      sock.close()
    exit(1)
    
  def encrypt( self, raw ):
    """
    Returns encrypted value encoded in b64 with salt, iv and cipher text
    separated by #.
    """
    self.check_safe_socket()
    if b64_data == '':
      raise ValueError
    return self._send("ENCRYPT", raw)

  def decrypt( self, b64_data ):
    """
    Requires b64 data separated by # to decrypt
    """
    self.check_safe_socket()
    if b64_data == '':
      raise ValueError
    return self._send("DECRYPT", b64_data)
  
  def test( self, skip_safety_check=False ):
    """
    Tests the connection to the daemon.
    """
    if not skip_safety_check:
      self.check_safe_socket()
    return self._send('HELLO::', '')
  
class OldData(Exception):
  pass

# Variables used by the script
redirect_uri = 'urn:ietf:wg:oauth:2.0:oob'
authorization_base_url = 'https://accounts.google.com/o/oauth2/auth'
token_url = 'https://accounts.google.com/o/oauth2/token'
scope = ['https://www.googleapis.com/auth/userinfo.profile',
         'https://www.googleapis.com/auth/userinfo.email']

# Expand variables where needed
unix_socket_expanded = os.path.expanduser(unix_socket)

# Any and all files we create should be restricted to the current user ONLY!
os.umask(077)

parser = argparse.ArgumentParser(prog='pyjuice', description='pyJuice is an open source tool for retrieving and decrypting your ' +
         'latest JuiceSSH CloudSync backup and extracting the private keys into ~/.ssh.')
parser.add_argument('-p', '--passphrase', type=str, required=False, help='Set the passphrase (INSECURE!). Do NOT use this unless ' +
         'you KNOW that noone can list your process and get your argument. Clean your history after using this!')
parser.add_argument('-n', '--no_daemon', action="store_true", required=False, help='If set, no daemon will be used, even if present. ' +
         'Ignored if -d/--daemon is set.')
parser.add_argument('-d', '--daemon', action="store_true", required=False, help='Runs pyJuice as a daemon and creates a UNIX domain ' +
         'socket listening for connections from other instances of pyJuice. pyJuice clients can ask for encryption/decryption of data ' +
         'without knowing the passphrase. Only one daemon per user is possible. The socket is owned by the user running the daemon ' +
         'and only read/writable by the owner.')
parser.add_argument('-c', '--console', action="store_true", required=False, help=argparse.SUPPRESS) # Keeps the daemon from forking
parser.add_argument('-t', '--testclient', action="store_true", required=False, help=argparse.SUPPRESS)
parser.add_argument('-e', '--testdecrypt', action="store_true", required=False, help=argparse.SUPPRESS)

args = parser.parse_args()

# TODO: Check to see if there is a live decryption/encryption daemon available to us
live_daemon = False
if args.daemon:
  args.no_daemon = False
  
if not args.no_daemon:
  print "Checking for a live daemon..."
  decryptor_test = AESCipherClient(unix_socket_expanded)
  live_daemon=decryptor_test.test(skip_safety_check=args.daemon)

  if args.daemon and live_daemon:
    print 'Only ONE live daemon can exist per user!'
    print 'You will have to manually kill it with "kill `cat ~/.pyjuice.daemon_pid`" in order to run a new one. Exiting...'
    # TODO: Maybe add option to kill the old daemon and start a new one?
    exit(10)

if live_daemon:
  print 'Live daemon found!'
else:
  if not args.no_daemon:
    print 'No live daemon found!'
  if args.passphrase != None and args.passphrase != '':
    passphrase = args.passphrase
  else:
    # We need the passphrase before continuing...
    passphrase = ''
    while passphrase == '':
      try:
        passphrase = getpass.getpass(prompt='Please enter your PASSPHRASE: ')
      except KeyboardInterrupt:
        print 'Exiting...'
        exit(0)

# If we are to daemonize, we don't need any connection to the API.
if args.daemon:
  print 'Spawning pyJuice daemon...'
  setproctitle.setproctitle('pyjuice --daemon')
  if not args.console:
    try:
      pid = os.fork()
    except OSError, e:
      raise Exception, "%s [%d]" % (e.strerror, e.errno)
  
    if (pid == 0):
      os.setsid()
      signal.signal(signal.SIGHUP, signal.SIG_IGN)
      
      try:
        pid = os.fork()
      except OSError, e:
        raise Exception, "%s [%d]" % (e.strerror, e.errno)
        
      if (pid == 0):
        maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
        if (maxfd == resource.RLIM_INFINITY):
          maxfd = MAXFD
        # Iterate through and close all file descriptors.
        for fd in range(0, maxfd):
          try:
            os.close(fd)
          except OSError:	# ERROR, fd wasn't open to begin with (ignored)
            pass
        
        sys.stdout.flush()
        sys.stderr.flush()
        out_log = file(os.path.expanduser(daemon_stdout_file), 'a+')
        err_log = file(os.path.expanduser(daemon_stderr_file), 'a+', 0)
        dev_null = file('/dev/null', 'r')
        os.dup2(out_log.fileno(), sys.stdout.fileno())
        os.dup2(err_log.fileno(), sys.stderr.fileno())
        os.dup2(dev_null.fileno(), sys.stdin.fileno())
        
      else:
        #print 'First child exiting and leaving second child %d...' % pid
        f = open(os.path.expanduser(daemon_pid_file),'w')
        f.write(str(pid))
        f.close()
        os._exit(0)
        
    else:
      #print 'Parent exiting and leaving child %d...' % pid
      os._exit(0)
  else:
    print 'Not forking into daemon...'
    
  # Now we are ready to run the daemon, we only get here in the second child...
  try:
    os.unlink(unix_socket_expanded)
  except OSError:
    if os.path.exists(unix_socket_expanded):
      raise
  socket.setdefaulttimeout(3)
  sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
  sock.settimeout(None)
  print >>sys.stderr, 'Starting up on %s' % unix_socket
  sock.bind(unix_socket_expanded)
  
  sock.listen(1)
  
  while True:
    try:
      # Wait for a connection
      print >>sys.stderr, 'Waiting for a connection'
      decryptor = AESCipher(passphrase)
      
      connection, client_address = sock.accept()
    except socket.timeout:
      pass
    except KeyboardInterrupt:
      print 'Exiting...'
      exit(0)
    try:
      print >>sys.stderr, 'Connection from client'

      save_data = False
      data_buf = ''
      while True:
        #ready = select.select([connection], [], [], 5)
        #if ready[0]:
        if True:
          data = connection.recv(16)
          #print >>sys.stderr, 'received "%s"' % data
          if data:
            if save_data:
              data_buf += data
            if '--START--' == data[:9]:
              save_data = True
              data_buf = data[9:]
            elif '--DONE---' == data_buf[-9:]:
              save_data = False
              data_buf = data_buf[:-9]
              action = data_buf[:9]
              b64_data = data_buf[9:]
              text = ''
              try:
                if 'DECRYPT::' == action:
                  text = decryptor.decrypt(b64_data)
                elif 'ENCRYPT::' == action:
                  text = decryptor.encrypt(b64_data)
                elif 'HELLO::::' == action:
                  text = action
              except (ValueError, TypeError) as e:
                text = ''
              print >>sys.stderr, 'sending data back to the client'
              connection.send( '--START--' )
              if 'HELLO::::' == action:
                connection.sendall(text)
              else:
                connection.sendall(base64.standard_b64encode(text))
              connection.send( '--DONE---' )
              
          else:
            print >>sys.stderr, 'No more data from client'
            break
    except KeyboardInterrupt:
      print 'Exiting...'
      exit(0)
    except socket.error:
      pass
    except NameError:
      pass
    finally:
      # Clean up the connection
      print "Closing connection to client..."
      try:
        connection.close()
      except NameError:
        pass
  exit()

if args.testdecrypt:
  decryptor = AESCipher(passphrase)
  print "testdecrypt with %r" % passphrase
  print "%r" % decryptor.decrypt('')
  exit()
  
if args.testclient:
  # This is a hidden function used only for debugging the daemon...
  print "Testclient..."
  sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
  print >>sys.stderr, 'connecting to %s' % unix_socket
  try:
    sock.connect(unix_socket_expanded)
  except socket.error, msg:
    print >>sys.stderr, msg
    exit(1)
  
  try:
    # Send data
    message = 'DECRYPT::asd'
    print >>sys.stderr, 'sending "%s"' % message
    sock.send( '--START--' )
    sock.sendall(message)
    sock.send( '--DONE---' )
        
    save_data = False
    data_buf = ''
    while True:
      data = sock.recv(16)
      print >>sys.stderr, 'received "%s"' % data
      if data:
        if save_data:
          data_buf += data
        if '--START--' == data[:9]:
          save_data = True
          data_buf = data[9:]
        elif '--DONE---' == data_buf[-9:]:
          save_data = False
          data_buf = data_buf[:-9]
          print >>sys.stderr, 'Got this back from the server:\n%r' % base64.standard_b64decode(data_buf)
          break
      else:
        print >>sys.stderr, 'no more data from server'
        break
  except NameError:
    pass        
  finally:
    print >>sys.stderr, 'closing socket'
    sock.close()
  exit()

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
  #print('---------------')
  r = requests.get("https://api.sonelli.com/authenticate/%s" % (token['access_token']))
  authenticate = r.json()
  cookies = dict(session=authenticate[u'session'][u'identifier'])
  #print('---------------')
  
  r = requests.post('https://api.sonelli.com/cloudsync', cookies=cookies)
  cloudsync = r.json()
  json.dump(cloudsync, open(os.path.expanduser(encrypted_data_file), 'w'))


#pprint(cloudsync)
#print datetime.datetime.fromtimestamp(cloudsync[u'date']).strftime('%Y-%m-%d %H:%M:%S')

identities = cloudsync[u'objects'][u'com.sonelli.juicessh.models.Identity']

#pprint(identities)
i=0
for identity in identities:
  if identity[u'_encrypted']:
    # https://github.com/Sonelli/gojuice/blob/master/crypto/aes/aes.go
    print '============================'
    print 'The data is encrypted!'
    data = identity[u'data']
    
    if live_daemon:
      print 'Using pyJuice daemon for decryption...'
      decryptor = AESCipherClient(unix_socket_expanded)
    else:  
      print 'Using locally available passphrase for decryption...'
      decryptor = AESCipher(passphrase)
    text = decryptor.decrypt(data)
    try:
      json_data = json.loads(text)
    except ValueError:
      print 'The decryption FAILED! Either the data is corrupt or the passphrase is incorrect...'
      exit(5)
    #print '----------------------'
    #pprint(json_data)
    
    print '----------------------'
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
    print 'The data was successfully decrypted!'
    #pprint(json_data)
    print "----------------------"
    private_key_filename = '~/.ssh/' + 'juice_' + json_data[u'nickname'] + '_' + str(i)
    if json_data[u'privatekey'] != '':
      private_key_file = open(os.path.expanduser(private_key_filename), "w")
      private_key_file.write(json_data[u'privatekey'])
      private_key_file.close()
      print "Created/updated %r..." % str(private_key_filename)
    else:
      print "No data for %r available, skipping..." % str(private_key_filename)
    
  i+=1  
