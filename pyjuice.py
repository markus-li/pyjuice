#!/usr/bin/env python
#
# pyJuice is a GPLv3 open source tool for interacting with JuiceSSH CloudSync. 
# JuiceSSH for Android can be found at https://sonelli.com
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
encrypted_data_file = '~/.pyjuice.encrypted.raw'
unix_socket = '~/.pyjuice.socket'
encrypted_json_file = '~/.pyjuice.encrypted.json'
decrypted_json_file = '~/.pyjuice.decrypted.json'
daemon_pid_file = '~/.pyjuice.daemon_pid'
daemon_stdout_file = '~/.pyjuice.daemon_stdout'
daemon_stderr_file = '~/.pyjuice.daemon_stderr'
client_id = '384598528408-g6urjkc21c6u9kv1gchu4b6rl0il7p0l.apps.googleusercontent.com'
client_secret = 'cka5jVJHSS49e6_8PyntUgXx'
prog_version = '0.1'

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
import struct, fcntl, termios
import setproctitle
import resource
import datetime, time
from pprint import pprint
from texttable import Texttable
import getpass
import uuid
from requests_oauthlib import OAuth2Session
import base64
# http://pythonhosted.org/passlib/lib/passlib.utils.pbkdf2.html
from passlib.utils.pbkdf2 import pbkdf2
# http://stackoverflow.com/questions/12562021/aes-decryption-padding-with-pkcs5-python
from Crypto.Cipher import AES
from Crypto import Random
from subprocess import call
import pexpect

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
    Returns the encrypted value encoded in b64 with salt, 
    iv and cipher text separated by #.
    """
    raw = pad(raw)
    salt = Random.new().read(SALT_LENGTH)
    iv = Random.new().read(BS)
    key = pbkdf2(self.passphrase, salt, ITERATION_COUNT, keylen=KEY_LENGTH)
    cipher = AES.new( key, AES.MODE_CBC, iv )
    cipher_text = cipher.encrypt( raw )
    return ( '#'.join([base64.standard_b64encode(salt)+'\n', base64.standard_b64encode(iv)+'\n', base64.standard_b64encode(cipher_text)+'\n']) )

  def decrypt( self, b64_data ):
    """
    Requires b64 data separated by # to decrypt
    """
    # TODO: Verify the data and add a try statement?
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
    if (b64_data == '' or
       not isinstance(b64_data, (unicode, str))):
      raise ValueError
    return self._send("DECRYPT", b64_data)
  
  def test( self, skip_safety_check=False ):
    """
    Tests the connection to the daemon.
    """
    try:
      if not skip_safety_check:
        self.check_safe_socket()
      return self._send('HELLO::', '')
    except OSError:
      return False
  
class OldData(Exception):
  pass

def get_local_encrypted():
  try:
    cloudsync = json.load(open(os.path.expanduser(encrypted_data_file)))
    print "Retrieved previously stored encrypted data..."
    print 'Last sync %s, local system time.' % datetime.datetime.fromtimestamp(cloudsync[u'date']).strftime('%Y-%m-%d %H:%M:%S')
    return cloudsync
  except (ValueError, IOError) as e:
    print "No valid encrypted data found locally, run '%s sync' to update..." % parser.prog
    exit(1)

def num_unique_id_in_dict(d, key):
  try:
    a = d[key]
  except KeyError:
    return 0
  unique = {}
  for v in a:
    if '_id' in v:
      unique[v['_id']] = True
    elif 'id' in v:
      unique[v['id']] = True
  return len(unique)

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

parser = argparse.ArgumentParser(description='pyJuice is a GPLv3 open source tool for interacting with JuiceSSH CloudSync. JuiceSSH for Android can be found at https://sonelli.com')

parser.add_argument('-v', '--version', action='version', version='%(prog)s v' + prog_version)

general_group = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,add_help=False)
general_group.add_argument('-p', '--passphrase', type=str, required=False, help='Set the passphrase (INSECURE!) used for encryption/decryption. ' +
         'Do NOT use this unless you KNOW that noone can list your process and get your argument. Clean your history after using this!')
extra_group = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,add_help=False)
extra_group.add_argument('-n', '--no_daemon', action="store_true", required=False, help='If set, no daemon will be used for ' +
         'encryption/decryption, even if present.')


subparsers = parser.add_subparsers(title="Commands", dest='command', metavar='{daemon, sync, connections, identities, port_forwards, snippets}' )

daemon_help = ('Runs pyJuice as a daemon and creates a UNIX domain socket listening for connections from other instances ' +
         'of pyJuice. pyJuice clients can ask for encryption/decryption of data without knowing the passphrase. Only one ' +
         'daemon per user is possible. The socket is owned by the user running the daemon and only read/writable by the owner.')
parser_daemon = subparsers.add_parser('daemon', description=daemon_help, help=daemon_help, parents=[general_group])
parser_daemon.add_argument('-c', '--console', action='store_true', required=False, help='Prevents the daemon from forking and keeps it in the calling console.')

sync_help = ('Used for syncing against JuiceSSH CloudSync. An encrypted copy of the json data is saved in %r, the raw copy is saved in %r.' % (encrypted_json_file, encrypted_data_file))
parser_sync = subparsers.add_parser('sync', description=sync_help, help=sync_help, parents=[general_group,extra_group])
parser_sync.add_argument('-a', '--decryptall', action="store_true", required=False, help='Decrypts ALL data, including passwords(!), ' +
         'into %r. (DANGEROUS!)' % decrypted_json_file)
parser_sync.add_argument('-k', '--privatekeys', action="store_true", required=False, help='If set, all private keys available from ' +
         'CloudSync will be decrypted and extracted to \'~/.ssh/\'. This could be potentially DANGEROUS, make sure all your private keys are ' + 
         'protected by a passphrase.')
parser_sync.add_argument('-f', '--force', action="store_true", required=False, help='If set, a new copy of the backup will be retrieved ' +
         'from CloudSync, even if the last update occured less than 30 minutes ago.')
parser_sync.add_argument('-s', '--status', action="store_true", required=False, help='Show statistics about locally available data (if any) and then exits immediately.')

connections_help = 'Manage and display Connections.'
parser_connections = subparsers.add_parser('connections', description=connections_help, help=connections_help, parents=[general_group,extra_group])
parser_connections.add_argument('-l', '--list', action="store_true", required=False, help='Decrypt and list all available Connections.')
parser_connections.add_argument('-c', '--connect', type=str, required=False, help='Connect to host by Nickname.')

identities_help = 'Manage and display Identities.'
parser_identities = subparsers.add_parser('identities', description=identities_help, help=identities_help, parents=[general_group,extra_group])
parser_identities.add_argument('-l', '--list', action="store_true", required=False, help='Decrypt and list all available Identities.')

port_forwards_help = 'Manage and use Port Forwards.'
parser_port_forwards = subparsers.add_parser('port_forwards', description=port_forwards_help, help=port_forwards_help, parents=[general_group,extra_group])
parser_port_forwards.add_argument('-l', '--list', action="store_true", required=False, help='Decrypt and list all available Port Forwards.')

snippets_help = 'Manage and display Snippets.'
parser_snippets = subparsers.add_parser('snippets', description=snippets_help, help=snippets_help, parents=[general_group,extra_group])
parser_snippets.add_argument('-l', '--list', action="store_true", required=False, help='Decrypt and list all available Snippets.')
parser_snippets.add_argument('-g', '--get', type=str, required=False, help='Get the snippet by name.')

parser_debug = subparsers.add_parser('debug', description='Hidden command used for debugging and testing only.', parents=[general_group,extra_group])
parser_debug.add_argument('-t', '--testclient', action="store_true", required=False, help='testclient')
parser_debug.add_argument('-y', '--testcrypt', action="store_true", required=False, help='testcrypt')

args = parser.parse_args()
#pprint(args)

# Change the process title to hide potentially private data.
setproctitle.setproctitle('%s %s' % (parser.prog, args.command))

# If sync status is all we want, return that
if args.command == 'sync' and args.status:
  cloudsync = get_local_encrypted()
  connections = 0; connection_groups = 0; identities = 0
  snippets = 0; port_forwards = 0; amazon_ec2 = 0; config_items = 0
  try:
    objects = cloudsync[u'objects']
    connections = num_unique_id_in_dict(objects, u'com.sonelli.juicessh.models.Connection')
    connection_groups = num_unique_id_in_dict(objects, u'com.sonelli.juicessh.models.ConnectionGroup')
    identities = num_unique_id_in_dict(objects, u'com.sonelli.juicessh.models.Identity')
    snippets = num_unique_id_in_dict(objects, u'com.sonelli.juicessh.models.Snippet')
    port_forwards = num_unique_id_in_dict(objects, u'com.sonelli.juicessh.models.PortForward')
  except KeyError:
    pass
  config_items = num_unique_id_in_dict(cloudsync, u'configs')
  
  table = Texttable()
  table.set_deco(Texttable.HEADER)
  table.set_cols_dtype(['t','i'])
  table.set_cols_align(['l', 'c'])
  print
  print 'Remote Backups'
  print '############################'
  print 'Items currently in Cloudsync'
  print
  table.add_rows([['Type', 'Amount'],
                  ['Connections', connections],
                  ['Connection Groups', connection_groups],
                  ['Identities', identities],
                  ['Snippets', snippets],
                  ['Port Forwards', port_forwards],
                  ['Amazon EC2 Link Profiles*', amazon_ec2],
                  ['Config Items', config_items]])
  print table.draw()
  print '* not implemented'
  exit()

live_daemon = False
if args.command == 'daemon':
  no_daemon = False
else:
  no_daemon = args.no_daemon
 
if (args.command == 'daemon' or
    not no_daemon):
  print "Checking for a live daemon..."
  decryptor_test = AESCipherClient(unix_socket_expanded)
  live_daemon=decryptor_test.test(skip_safety_check=(args.command == 'daemon'))

  if args.command == 'daemon' and live_daemon:
    print 'Only ONE live daemon can exist per user!'
    print 'You will have to manually kill it with "kill `cat ~/.pyjuice.daemon_pid`" in order to run a new one. Exiting...'
    # TODO: Maybe add option to kill the old daemon and start a new one?
    exit(10)

if live_daemon:
  print 'Live daemon found!'
  print 'Using pyJuice daemon for decryption...'
  decryptor = AESCipherClient(unix_socket_expanded)
else:
  if not no_daemon:
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
  print 'Using locally available passphrase for decryption...'
  decryptor = AESCipher(passphrase)

def itterate_dict_decrypt( data ):
  new_data = {}
  for key, value in data.iteritems():
    if isinstance(value, list):
      #print "%r is an array" % key
      new_data[key] = itterate_array( value )
    elif isinstance(value, dict):
      #print "%r is a dict" % key
      new_data[key] = itterate_dict_decrypt( value )
    elif isinstance(value, (unicode, str)):
      if value != '':
        try:
          new_value = decryptor.decrypt(value)
        except (ValueError, AttributeError) as e:
          new_value = u''
        if new_value != '':
          value = new_value
      if key == u'data':
        json_data = None
        try:
          json_data = json.loads(value)
        except ValueError:
          pass
        if isinstance(json_data, dict):
          for subkey, subvalue in json_data.iteritems():
            if subvalue != '':
              try:
                new_subvalue = decryptor.decrypt(subvalue)
              except (ValueError, AttributeError) as e:
                new_subvalue = u''
              if new_subvalue != '':
                subvalue = new_subvalue
            new_data[subkey] = subvalue
        else:
          new_data[key] = value
      else:
        new_data[key] = value
    else:
      #print "%r is something else" % key
      new_data[key] = value
  return new_data

def itterate_array( data ):
  new_data = []
  unique = {}
  for value in data:
    if isinstance(value, list):
      #print "this is an array"
      new_data.append(itterate_array( value ))
    elif isinstance(value, dict):
      # There are parts where you could end up with duplicates, let's get rid of them :)
      c_id = None
      if '_id' in value:
        c_id = value['_id']
      elif 'id' in value:
        c_id = value['id']
      if (c_id != None and (not c_id in unique)):
        unique[c_id] = True
        #print "this is a dict"
        new_data.append(itterate_dict_decrypt( value ))
    else:
      #print "this is something else"
      new_data.append(value)
  return new_data

def decrypt_cloudsync(cloudsync):
  # This decrypts everything into a dict (except team data currently).
  print 'Decrypting everything...'
  #print uuid.uuid4()

  if isinstance(cloudsync, dict):
    cloudsync_decrypted = itterate_dict_decrypt(cloudsync)
    #pprint(cloudsync_decrypted)
    print 'Decryption of all data completed!'
    return cloudsync_decrypted
  else:
    print 'The CloudSync data is faulty! It should be a dict!'
    exit(1)

# If we are to daemonize, we don't need any connection to the API.
if args.command == 'daemon':
  print 'Spawning pyJuice daemon...'
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
    
  # Now we are ready to run the daemon, we only get here in the second child
  # or when in console mode...
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
elif args.command == 'debug':
  ############################ DEBUG TOOLS ONLY ############################
  if args.testcrypt:
    # This is a hidden function used only for debugging/testing the decryption & encryption...
    decryptor = AESCipher(passphrase)
    plain_1 = '{"count":0,"content":"content snip 2","isEncrypted":false,"name":"snip2"}'
    print "plain_1: %r" % plain_1
    encrypt_1 = decryptor.encrypt(plain_1)
    print "encrypt_1: %r" % encrypt_1
    plain_2 = decryptor.decrypt(encrypt_1)
    print "plain_2: %r" % plain_2
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
  ############################ END DEBUG TOOLS #############################
elif args.command == 'sync':
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
    elif args.force:
      print "Forcing update of the data from JuiceSSH CloudSync..."
      raise OldData
    print "Retrieved previously stored encrypted data..."
    
  except (ValueError, IOError, OldData) as e:
    if not args.force:
      print "No up-to-date encrypted data found locally, retreiving it from JuiceSSH CloudSync..."
    #print('---------------')
    r = requests.get("https://api.sonelli.com/authenticate/%s" % (token['access_token']))
    authenticate = r.json()
    cookies = dict(session=authenticate[u'session'][u'identifier'])
    #print('---------------')
    
    r = requests.post('https://api.sonelli.com/cloudsync', cookies=cookies)
    cloudsync = r.json()
    json.dump(cloudsync, open(os.path.expanduser(encrypted_data_file), 'w'))
    # Save the encrypted version in a pretty format as well
    pprint(cloudsync, open(os.path.expanduser(encrypted_json_file), 'w'))
  
  #pprint(cloudsync)
  #print datetime.datetime.fromtimestamp(cloudsync[u'date']).strftime('%Y-%m-%d %H:%M:%S')
  
  if (args.privatekeys or args.decryptall):
    cloudsync_decrypted = decrypt_cloudsync(cloudsync)
  
  if args.privatekeys:
    # TODO: Add error-handling
    identities = cloudsync_decrypted[u'objects'][u'com.sonelli.juicessh.models.Identity']
    #pprint(identities)
    i=0
    for identity in identities:
      private_key_filename = '~/.ssh/' + 'juice_' + identity[u'_id']
      try:
        if identity[u'privatekey'] != '':
          private_key_file = open(os.path.expanduser(private_key_filename), "w")
          private_key_file.write(identity[u'privatekey'])
          private_key_file.close()
          print "Created/updated %r..." % str(private_key_filename)
        else:
          raise KeyError # Make my own error
      except KeyError:
        print "No data for %r available, skipping..." % str(private_key_filename)
      i+=1
      
  if args.decryptall:
    # This saves all decrypted data into a json-file (except team data currently).
    pprint(cloudsync_decrypted, open(os.path.expanduser(decrypted_json_file), 'w'))
    print 'Decrypted data saved to %r.' % decrypted_json_file

else:
  cloudsync = get_local_encrypted()
  cloudsync_decrypted = decrypt_cloudsync(cloudsync)
  try:
    objects = cloudsync_decrypted[u'objects']
  except KeyError:
    print 'There are no entries in the CloudSync Backup'
    exit()
  
  def get_entries_by_field_data(object_name, field, field_data):
    try:
      result = []
      a = objects[object_name]
      for d in a:
        if (field in d and d[field] == field_data):
          result.append(d)
    except KeyError:
      pass
    finally:
      return result
  
  if args.command == 'connections':
    # The information is spread over multipleplaces, let's make it easier to use.
    try:
      connections = objects[u'com.sonelli.juicessh.models.Connection']
    except KeyError:
      print 'No connections are available!'
      exit()
    typenames = ['ssh', 'mosh', 'local', 'telnet']
    connections_expanded = []
    for v in connections:
      c = {}
      c['id'] = v[u'_id']
      c['address'] = v[u'address']
      c['modified'] = v[u'modified']
      c['nickname'] = v[u'nickname']
      c['port'] = v[u'port']
      c['type'] = v[u'type']
      identity_mapping = get_entries_by_field_data('com.sonelli.juicessh.models.ConnectionIdentity', 'connection', c['id'])
      # Even though this looks like a many:many mapping, we only expect maximum one entry per host here.
      c['identity'] = None
      if (len(identity_mapping) >= 1 and 'identity' in identity_mapping[0]):
        identity = get_entries_by_field_data('com.sonelli.juicessh.models.Identity', '_id', identity_mapping[0]['identity'])
        if len(identity) >= 1:
          c['identity'] = identity[0]
      c['connect_via'] = None
      if 'via' in v:
        connect_via = get_entries_by_field_data('com.sonelli.juicessh.models.Connection', '_id', v['via'])
        if len(connect_via) >= 1:
          c['connect_via'] = connect_via[0]
      group_mapping = get_entries_by_field_data('com.sonelli.juicessh.models.ConnectionGroupMembership', 'connection', c['id'])
      c['groups'] = []
      c['group_names'] = []
      if len(group_mapping) >= 1:
        for g in group_mapping:
          #ConnectionGroup
          connectionGroup = get_entries_by_field_data('com.sonelli.juicessh.models.ConnectionGroup', '_id', g['group'])
          # If this is anything but one entry, we can just crash here for now since that means faulty json data :P...
          c['groups'].append(connectionGroup[0])
          c['group_names'].append(connectionGroup[0]['name'])
      connections_expanded.append(c)
    def get_connection(nickname):
      # TODO: Handle multiple entries with the same nickname.
      for c in connections_expanded:
        if c['nickname'] == nickname:
          return c
      return None
    def sigwinch_passthrough (sig, data):
      # Used to make pexpect interactive terminals handle resize of the terminal window.
      s = struct.pack("HHHH", 0, 0, 0, 0)
      a = struct.unpack('hhhh', fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ , s))
      global child
      child.setwinsize(a[0],a[1])    
    if args.list:
      # Nickname, Type, Address, Port, Connect Via, Identity, Groups (many:many)
      #pprint(connections_expanded)
      result = [['Nickname', 'Type', 'Address', 'Port', 'Connect Via', 'Identity', 'Groups']]
      for v in connections_expanded:
        connect_via = 'Not Set'
        identity = 'Not Set'
        groups = 'Not Set'
        if ('connect_via' in v and v['connect_via'] != None):
          connect_via = v[u'connect_via'][u'nickname']
        if ('identity' in v and v['identity'] != None):
          identity = v[u'identity'][u'nickname']
        if ('group_names' in v and len(v['group_names']) > 0 ):
          groups = ', '.join(v['group_names'])
        if v[u'type'] == 2: # is local device
          v[u'address'] = 'N/A'
          v[u'port'] = 0
        result.append([v['nickname'],typenames[v['type']], v['address'], v['port'], connect_via, identity, groups])
      table = Texttable()
      table.set_deco(Texttable.HEADER | Texttable.HLINES)
      table.set_cols_dtype(['t','t', 't', 'i', 't', 't', 't'])
      table.set_cols_align(['l', 'l', 'l', 'c', 'l', 'l', 'l'])
      table.set_cols_width([12, 7, 25, 5, 12, 12, 35])
      print '############################'
      print '#       Connections        #'
      print '############################'
      table.add_rows(result)
      print table.draw()
    if args.connect != None:
      c = get_connection(args.connect)
      if c == None:
        print 'No connection with the name \'%s\' could be found. Exiting...' % args.connect
        exit()
      if c['type'] != 0:
        print 'Can\'t connect to \'%s\'. No support for \'%s\' is implemented yet, only SSH is supported at this time.' % (args.connect, typenames[c['type']])
        exit()
      # TODO: Add support for Connect Via
      if ('connect_via' in c and c['connect_via'] != None):
        print 'There is currently no support for \'Connect Via\' implemented, trying the connection anyway...'
      print 'Connecting to \'%s\'...' % args.connect
      ssh_command = ' '.join(['ssh', '-p %d' % c['port'], '%s' % c['address']])
      if ('identity' in c and c['identity'] != None):
        #print "identity"
        ssh_command = ' '.join(['ssh', '-p %d' % c['port'], '%s@%s' % (c['identity'][u'username'], c['address'])])
        if ('privatekey' in c['identity'] and c['identity']['privatekey'] != ''):
          #print "privatekey"
          private_key_filename = os.path.expanduser('~/.ssh/' + 'juice_' + c['identity'][u'_id'])
          if not os.path.exists(private_key_filename):
            print 'Private key specified but not present, run \'%s sync -k\' and then try again...' % parser.prog
            exit(1)
          if ('privatekeyPassword' in c['identity'] and c['identity']['privatekeyPassword'] != ''):
            print "Using private key with specified passphrase..."
            # This could be done with only pexpect, but this was my first approach and it works so I won't change it.
            child = pexpect.spawn('bash -l -c "eval `ssh-agent` && echo \'<begin>\'$SSH_AUTH_SOCK\'#\'$SSH_AGENT_PID\'<end>\' && ssh-add %s"' % private_key_filename)
            child.expect("<begin>(.*)#(.*)<end>")
            ssh_auth_sock = child.match.group(1)
            ssh_agent_pid = child.match.group(2)
            child.expect('Enter passphrase for .*')
            child.sendline(c['identity']['privatekeyPassword'])
            ssh_command = ('SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK; SSH_AGENT_PID=%s; export SSH_AGENT_PID; ' % (ssh_auth_sock, ssh_agent_pid) + 
                           '%s ; kill $SSH_AGENT_PID' % ' '.join(['ssh', '-p %d' % c['port'], '%s@%s' % (c['identity'][u'username'], c['address'])]))
          else:
            print "Using private key, no passphrase specified..."
            ssh_command = ('eval `ssh-agent` && ssh-add %s && ' % private_key_filename + 
                           '%s ; kill $SSH_AGENT_PID' % ' '.join(['ssh', '-p %d' % c['port'], '%s@%s' % (c['identity'][u'username'], c['address'])]))
        elif ('password' in c['identity'] and c['identity']['password'] != ''):
          print "Using password only..."
          child = pexpect.spawn('bash -l -c "%s"' % ssh_command)
          child.expect('.*password:.*')
          child.sendline(c['identity']['password'])
          # Enable support for resizing the terminal and set it to the current size.
          sigwinch_passthrough('','')
          signal.signal(signal.SIGWINCH, sigwinch_passthrough)
          child.interact()
          exit()
      #print ssh_command
      call(ssh_command, shell=True)
      exit()
      
  elif args.command == 'identities':
    try:
      identities = objects[u'com.sonelli.juicessh.models.Identity']
    except KeyError:
      print 'No identities are available'
      exit()
    if args.list:
      result = [['Nickname', 'Username', 'Password', 'Private Key', 'Private Key Password']]
      for v in identities:
        password = 'Not Set'
        privatekey = 'Not Set'
        privatekeyPassword = 'Not Set'
        if ('password' in v and v[u'password'] != ''):
          password = 'Set'
        if ('privatekey' in v and v[u'privatekey'] != ''):
          privatekey = 'Set'
        if ('privatekeyPassword' in v and v[u'privatekeyPassword'] != ''):
          privatekeyPassword = 'Set'
        result.append([v[u'nickname'],v[u'username'], password, privatekey, privatekeyPassword])
      table = Texttable()
      table.set_deco(Texttable.HEADER)
      table.set_cols_dtype(['t','t', 't', 't', 't'])
      table.set_cols_align(['l', 'l', 'l', 'l', 'l'])
      print '############################'
      print '#        Identities        #'
      print '############################'
      table.add_rows(result)
      print table.draw()      
  
  elif args.command == 'port_forwards':
    if args.list:
      print 'NOT YET IMPLEMENTED: List port forwards'
  
  elif args.command == 'snippets':
    try:
      snippets = objects[u'com.sonelli.juicessh.models.Snippet']
    except KeyError:
      print 'No snippets are available'
      exit()
    if args.list:
      print '############################'
      print '#         Snippets         #'
      print '############################'
      for v in snippets:
        print '"%s"' % v[u'name']
        print '-' * (len(v[u'name'])+2)
        print v[u'content']
        print '=' * 25
    elif args.get != None:
      for v in snippets:
        if v[u'name'] == args.get:
          print 'Snippet content:'
          print '################'
          print v[u'content']
          exit()
      print 'No snippet with that name is available.'
      exit()
