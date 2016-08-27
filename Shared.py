import sys
import linecache
import random
import string
import pyotp
import time
import hashlib
import base64
import copy

from Crypto.Cipher import AES
from OpenSSL import SSL, crypto
import binascii

import scrypt

currentSeed = ''

# Unique marker placed at the end of the data
endMarker = "!!!!----]]]]]]]]"
startMarker = "[[[[----!!!!!!!!"
encryptType = "CBC"


# Required function for the outter OpenSSL connection
def verify_cert(conn, cert, errnum, depth, ok):
    certsubject = crypto.X509Name(cert.get_subject())
    commonname = certsubject.commonName
    # print 'S> GOT CERT: %s' % cert.get_subject()
    return ok



def decryptString(string, key, previousKey, beforePreviousKey):
    remainder = len(string) % 16
    if remainder != 0:
        print "--Decrypt Error--"
        return "-ERROR-"
    else:
        if encryptType == "CBC":
            return decryptCBC(string, key, previousKey, beforePreviousKey)
        else:
            try:
                decrypt = scrypt.decrypt(string,previousKey)
                if decrypt[16:18] == "NW":
                    print "Reseed + " + decrypt[16:32]
                    generateNewSeed(convertSeedBase32(decrypt[16:32]))
                print "vvvv Decrypted with PREVIOUS " + previousKey + " vvvv"
                return decrypt[32:]
            except:
                try:
                    decrypt = scrypt.decrypt(string,beforePreviousKey)
                    if decrypt[16:18] == "NW":
                        print "Reseed + " + decrypt[16:32]
                        generateNewSeed(convertSeedBase32(decrypt[16:32]))
                    print "vvvv Decrypted with Before PREVIOUS " + beforePreviousKey + " vvvv"
                    return decrypt[32:]
                except:
                    try:
                        decrypt = scrypt.decrypt(string,key)
                        if decrypt[16:18] == "NW":
                            print "Reseed + " + decrypt[16:32]
                            generateNewSeed(convertSeedBase32(decrypt[16:32]))
                        print "vvvv Decrypted with Current " + key + " vvvv"
                        return decrypt[32:]
                    except:
                        return "-ERROR-"



def decryptCBC(string, key, previousKey, beforePreviousKey):
    code = [previousKey, beforePreviousKey, key]
    for c in code:
        decryptedString = AES.new(c, AES.MODE_CBC, id_generator())
        decrypt = decryptedString.decrypt(string).rstrip("-")
        if startMarker in decrypt:
            print "vvvv Decrypted With: " + c[:12] + " vvvv"
            if decrypt[16:22] == "ReSeed":
                generateNewSeed(convertSeedBase32(decrypt[16:32]))

                clientpass_file = "client_password_database.txt"

                addPassToDatabase = open(clientpass_file, 'w+')
                currPass = getCurrentSeed()

                addPassToDatabase.write(currPass + "\n")
                addPassToDatabase.close()
            return decrypt[32:]
    return "-ERROR-"



def encryptString(string, key):

    if "ReSeed" in string:
        ids = id_generator(16) + "ReSeed" + id_generator(10)
        string = ids + string
        generateNewSeed(convertSeedBase32(ids[16:32]))
    else:
        string = id_generator(32) + string

    # Pad if the length is not divisible by 16
    remainderCheck = len(string) % 16
    padAmount = 16 - remainderCheck
    for i in range(padAmount):
        string += str(" ")

    if encryptType == "CBC":
        encryptedString = AES.new(key, AES.MODE_CBC, id_generator())
        return encryptedString.encrypt(string)
    else:
        return scrypt.encrypt(string,key)



#This 16 diget is padded to the front of all messages. This is so that CBC can
#be used. Since each block is 16 long this will stop statistical analysis. 
#Since some messages where only 1 block long they where coming out as the same
#message.
def id_generator(size=16, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))



# Prints exception. Created to report on errors of individual threads (this is usually a client disconnect)
def PrintException(errorReporting):
    if errorReporting == 1:
        exc_type, exc_obj, tb = sys.exc_info()
        f = tb.tb_frame
        lineno = tb.tb_lineno
        filename = f.f_code.co_filename
        linecache.checkcache(filename)
        line = linecache.getline(filename, lineno, f.f_globals)
        print 'S> EXCEPTION IN ({}, LINE {} "{}"): {}'.format(filename, lineno, line.strip(), exc_obj)



def timedPassword(seed):
    totp = pyotp.TOTP(seed)
    timedcode = str(hashlib.sha256(totp.now()).hexdigest())[6:18]
    return "{: <32}".format(timedcode).encode("utf-8")



def generateNewSeed(previousseed, printIt=1):


    if previousseed == "NOPE":
        return "NOPE"

    global currentSeed

    oldSeed = currentSeed
    random.seed(previousseed)
    newseed = hashlib.sha256(str(random.random())).hexdigest()
    newseed = convertSeedBase32(newseed)
    currentSeed = newseed
    if printIt == 1:
        if oldSeed != "" and currentSeed != "":
            print "S> -Reseed- Old: " + oldSeed[:8] + " New: " + currentSeed[:8]

    return newseed




# ----Helper Functions----

def convertSeedBase32(seed):
    seed = base64.b32encode(seed)
    return seed

def getCurrentOTP():
    return timedPassword(currentSeed)

def getCurrentSeed():
    return currentSeed

def setCurrentSeed(seed):
    global currentSeed
    currentSeed = seed

def addStartAndEndMarkers(command):
    return startMarker+command+endMarker

def removeStartAndEndMarkers(command):
    command = command.replace(startMarker, "")
    command = command.replace(endMarker, "")
    return command
    
def setEncryptType(Type):
    encryptType = Type