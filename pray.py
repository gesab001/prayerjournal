import json
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
  password_provided = input("password: " ) # This is input in the form of a string
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
  json_file = open("password.json", "w")
  json_data = {}
  json_data[password_provided] = key.decode('utf8').replace("'", '"')
  json.dump(json_data, json_file)
  json_file.close()

#createKey()
  
def getKey():
  password = input("password : ")
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
 json_file = open("prayers.json")
 data = json.load(json_file)
 json_file.close()
 list = data["prayers"]
 return list
 
def addPrayer(json_data): 
 json_file = open("prayers.json", "w")
 json.dump(json_data, json_file)
 json_file.close()
 
def decrypt(): 
  list = getPrayerList()
  for x in list:
    message = x.encode('utf-8')
    decrypted = f.decrypt(message)
    print(decrypted)


while True:
  text = input("Dear Lord Jesus,  " )
  if text=="exit":
     break
  if text=="read":
     decrypt()	  
  if text=="createpassword":
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
  
  
  

def maskBadWord(word):
   letters = list(string.ascii_lowercase)
   wordList = list(word)
   for x in range(0, len(wordList)):
      letter = wordList[x]
      #print("letter:" + letter)
      letterindex = string.ascii_lowercase.index(letter.lower())
      nextletterIndex = letterindex + 1
      nextletter = letters[nextletterIndex]
      wordList[x] = nextletter

   newword = "".join(wordList)
   return newword

   
def unmaskBadWord(word):
   letters = list(string.ascii_lowercase)
   wordList = list(word)
   for x in range(0, len(wordList)):
      letter = wordList[x]
      #print("letter:" + letter)
      letterindex = string.ascii_lowercase.index(letter.lower())
      nextletterIndex = letterindex - 1
      nextletter = letters[nextletterIndex]
      wordList[x] = nextletter
       
   badword = "".join(wordList)
   return badword

  