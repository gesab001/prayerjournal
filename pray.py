import json
from getpass import getpass
import string
import cryptography
from cryptography.fernet import Fernet
import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
#key = Fernet.generate_key()


def createKey():
  password_provided = getpass() # This is input in the form of a string
  password = password_provided.encode() # Convert to type bytes
  salt = os.urandom(16) # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
  kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
  )
  key = base64.urlsafe_b64encode(kdf.derive(password)) # Can only use kdf once
  json_file = open("password.json")
  json_data = json.load(json_file)
  json_data[password_provided] = key.decode('utf8').replace("'", '"')
  json_file.close()
  outfile = open("password.json", "w")
  json.dump(json_data, outfile)
  outfile.close()

#createKey()
  
def getKey():
  password = getpass()
  json_file = open("password.json")
  json_data = json.load(json_file)
  key = json_data[password]
  json_file.close() 
  return key
  
key = getKey()  
f = Fernet(key)

def encrypt(message):
  message = message.encode()
  encrypted = f.encrypt(message)
  return encrypted.decode('utf8').replace("'", '"')
  
   
def getPrayerList(): 
 json_file = open("encrypted_prayers.json")
 data = json.load(json_file)
 json_file.close()
 list = data["prayers"]
 return list
 
def addPrayer(json_data): 
 json_file = open("encrypted_prayers.json", "w")
 json.dump(json_data, json_file)
 json_file.close()
 
def decrypt(): 
  list = getPrayerList()
  count = 1
  for x in list:
    message = x.encode('utf-8')
    decrypted = f.decrypt(message)
    print(str(count) + ". " +decrypted.decode('utf8').replace("'", '"'))
    count = count + 1


while True:
  text = input("Dear Lord Jesus,  " )
  if text=="exit":
     break
  elif text=="read":
     decrypt()	  
  elif text=="createpassword":
     createKey() 
     key = getKey()	 
  else:
    list = getPrayerList()
    message = "Dear Lord Jesus, " + text + " in Jesus' name amen"
    encryptedMessage = encrypt(message)
    #print(encryptedMessage)
    list.append(encryptedMessage)
    json_data = {}
    json_data["prayers"] = list
    addPrayer(json_data)
  #for x in range(0, len(list)):
  #  print(str(x + 1) + ". " + list[x])
  

  