pyjuice
=======

## Description

pyJuice is an open source tool for recieving and decrypting your latest JuiceSSH CloudSync 
backup and extracting the private keys into ~/.ssh.

* Obtains an OAUTH2 authentication token from Google API
* Authenticates with the JuiceSSH API
* Retrieves your latest encrypted CloudSync backup in JSON format
* Decrypts the backup using a user provided passphrase
* Saves the private keys in ~/.ssh with permissions 0600

## TODO

* Better error-handling
* Document requirements
* Write installation details
* Handle deleted identities
* Come up with more features to implement
* Allow forcing update of the encrypted json file and not just every 30 minutes.
* Write tests (any volunters?)


## Additional information which needs editing.

1. Authenticate with Google
Obtain a Google OAUTH2 token with the following scope:

    SCOPE: "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email"


2. Authenticate with JuiceSSH API
Use the token acquired to authenticate with the JuiceSSH API via a HTTP GET request

    curl https://api.sonelli.com/authenticate/<token>

This will return a JSON user object that includes a session identifier such as:

{
  "name": "Your Name",
  "email": "your.email@gmail.com",
  "purchases": [
    {
      "time": 1374584431000,
      "order": "12994763169054705758.1359473553152469",
      "product": "com.sonelli.juicessh.propack",
      "state": 0,
      "_id": "520d0311076393665f0013fb"
    }
  ],
  "disabled": false,
  "session": {
    "expires": 1388514020,
    "identifier": "s%3ASeyAwfSd8zdfA9CceY8KI4zP.5rSCoj%2BVty1jCsEFUygprwBIFsqOhcj9sLegOqHzZJI"
  },
  "signature": "b42f3ff4c41fd77bfcaf5d8aa5cbdc1809727de67051f0a7e876701637f65ccc244ce674eea037d286817be6f69874fbc6904a4474cb79e985d4eb52e2c685f8d0cf419cfa20875265ec0a6a3c0ca2c8354d898757fff7ec27698d2f5267363d6d87"
}


3. Request the latest CloudSync backup (in JSON format)

Using the previously obtained session identifier as a HTTP session cookie header we can get the latest CloudSync backup via a HTTP POST request.

curl -XPOST -d '{}' -H "Cookie: session=s%3ASeyAwfSd8zdfA9CceY8KI4zP.5rSCoj%2BVty1jCsEFUygprwBIFsqOhcj9sLegOqHzZJI" https://api.sonelli.com/cloudsync

Normally the JuiceSSH app would send a full JSON manifest of all of it's encrypted records, but since all we're interested in doing is pulling down the cloudsync backup then we can just send a blank one with '{}'.

The JSON manifest returned contains an array of each type of record, sorted by record type.

4. Decrypt the data

As the JuiceSSH servers only store encrypted data, that's all you'll have so far.
Each record in the JSON CloudSync manifest received will have an '_id', 'modified' and 'data' field.

The data field is the record, converted to JSON and then encrypted.

To decrypt it, first split it into three parts on the '#' character.
The first part is the salt, the second is the IV, the third is the cipherText.

Before decryption, the required AES decryption key has to be derived from your JuiceSSH decryption passphrase using PBKDF2 with HMAC-SHA1 using the salt and 1000 iterations.

Once you have the AES key, the data is decrypted using AES-256 with PKCS#7 padding in CBC mode.