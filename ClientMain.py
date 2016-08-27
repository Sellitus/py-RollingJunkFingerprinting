import socket
import time
import threading
import os

#import pickle
#import PySide

from Shared import *


# Enable/Disable debug
debugMode = 1
fileDirectory = "files_client/"

clientpass_file = "client_password_database.txt"

endMarker = "!!!!----]]]]"
startMarker = "[[[[----!!!!"
uniqueKey = "1A4F428BB6AA987E075C92A4"
previousKey = ''
beforePreviousKey = ''
# Converts key to 32 bytes for AES encryption
uniqueKey = "{: <32}".format(uniqueKey).encode("utf-8")
# Generate IV for AES encryption
ivKey = '#%F--?PstR71'
#ivKey = "{: <16}".format(ivKey).encode("utf-8")

new = 0


def receiverThread(connection, numBytesPerRequest):
    # Seed the RNG
    random.seed(time.time())
    
    command = ""

    try:

        # Receive the data in small chunks and process it
        while True:
            try:
                encryptedString = connection.recv(numBytesPerRequest)
            except:
                break
            
            command = command + encryptedString
            tempDecrypt = decryptString(command, uniqueKey, previousKey, beforePreviousKey)
            tempDecrypt = removeStartAndEndMarkers(tempDecrypt)
            if tempDecrypt[0] == "/":
                command = tempDecrypt
                command = command.replace(endMarker, "")
                pieces = command.split(" ")
                requestType = pieces[0][1:].lower()
                
                data = ""
                
                if len(pieces) > 2:
                    for i in range(len(pieces)):
                        if i != 0:
                            data = data + " " + pieces[i]
                
                if requestType == "chat":
                    command = command[6:]
                    print command
                elif requestType == "download":
                    testDownloadFilename = fileDirectory + "test-down.txt"
                    
                    data = command[9:].strip(" ")
                    
                    downloaded_file = open(testDownloadFilename, 'w+')
                    downloaded_file.write(data)
                    downloaded_file.close()
                elif requestType == "/ls":
                    data = command[11:]
                    print data
                
                    
            

                # Clear out command after full function executes
                command = ""
            else:
                command = ""
    except:
        PrintException(debugMode)
        connection.shutdown()
        connection.close()


# Checks password file and returns password if file exists and has something in it.
# If the file does not exist or have anything in it, it prompts the user to enter the password.
# NOTE: Hashes every password
def checkPasswordFile(nameoffile):
    password = ""
    try:
        passwordfile = open(nameoffile, "r+")
        password = str(passwordfile.readline().strip())
        print password
        passwordfile.close()
    except:
        password = ""

    if password == "":
        print "C> No password in file. Enter password:"
        enteredpassword = raw_input("").strip()
        enteredpassword = hashlib.sha256(enteredpassword).hexdigest()

        passwordfile = open(nameoffile, 'w+')
        passwordfile.write(enteredpassword + "\n")
        passwordfile.close()

        return enteredpassword
    return password


# Thread to check and update IV used for the AES encryption
def updateKey(interval, one):
    global uniqueKey
    global previousKey
    global beforePreviousKey

    while True:
        newKey = getCurrentOTP()

        if newKey != uniqueKey:
            beforePreviousKey = previousKey
            previousKey = uniqueKey
            uniqueKey = newKey

        time.sleep(interval)

def main(argv):
    try:
        numBytesPerRequest = 8192
        serverAddress = "localhost"
        username = ""

        if argv.__len__() < 1 or argv.__len__() > 3:
            print "C> -----------------------------"
            print "C> USAGE: <script>.py [<username>] [<port>]"
            print "C> USAGE: ClientMain.py Clownfat 9001"
            print "C> -----------------------------"
            sys.exit()

        if argv.__len__() == 1:
            if username == "":
                username = id_generator(10)
            portTCP = 9001
        elif argv.__len__() == 2:
            username = argv[1]
            portTCP = 9001
        elif argv.__len__() == 3:
            username = argv[1]
            portTCP = argv[2]


        # Seed the RNG
        random.seed(time.time())
        
        dir = os.path.dirname(sys.argv[0])
        if dir == "":
            dir = os.curdir
            
        
        # Initialize context
        ctx = SSL.Context(SSL.TLSv1_METHOD)
        ctx.set_verify(SSL.VERIFY_PEER, verify_cert) # Demand a certificate
        ctx.use_privatekey_file (os.path.join(dir, 'keys/client/client.pkey'))
        ctx.use_certificate_file(os.path.join(dir, 'keys/client/client.cert'))
        ctx.load_verify_locations(os.path.join(dir, 'keys/client/CA.cert'))

        # Create a TCP/IP socket
        connection = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))

        sock_server_address = (serverAddress, portTCP)
        print >>sys.stderr, "C> CONNECTING TO: " + str(sock_server_address)
        # Connect the socket to the port where the server is listening
        connection.connect((serverAddress, portTCP))

        global uniqueKey
        global previousKey
        global beforePreviousKey

        passCode = checkPasswordFile(clientpass_file).strip()
        print "Hash " + hashlib.sha256(passCode).hexdigest()
        currKey = generateNewSeed(hashlib.sha256(passCode).hexdigest())
        
        timedpass = timedPassword(currKey)
        generateNewSeed(timedpass)
        timedpass = timedPassword(getCurrentSeed())
        uniqueKey = timedpass
        previousKey = uniqueKey
        beforePreviousKey = previousKey




        # Send your username to the server
        connection.sendall(encryptString(addStartAndEndMarkers(username), previousKey))

        # Send the password or ask for user input if no password file exists or if it is blank
        # NOTE: Hashed a second time, meaning the server will need to hash the password twice to
        #    compare to the stored password on its end. This is to store the password using a hash
        #    and then hash it again for safer transmission over the line.
        ppp = hashlib.sha256(checkPasswordFile(clientpass_file)).hexdigest()
        hashtosend = ppp
        print "Pass Sent " + ppp
        connection.sendall(encryptString(addStartAndEndMarkers(hashtosend), previousKey))

        # Get the response, decrypt it and remove the start/end markers
        decryptedResponse = decryptString(connection.recv(numBytesPerRequest), uniqueKey, previousKey, beforePreviousKey).strip()
        decryptedResponse = removeStartAndEndMarkers(decryptedResponse)

        if decryptedResponse != "CONFIRMED":
            print "C> Incorrect password! Delete the " + clientpass_file + " file to input new password."
            return

        junk = id_generator(256)
        connection.sendall(encryptString(addStartAndEndMarkers(junk), previousKey))

        # Offline data + junk to generate the new seed
        generateNewSeed(junk+uniqueKey)

        beforePreviousKey = previousKey
        previousKey = uniqueKey
        uniqueKey = timedPassword(getCurrentSeed())


        # -----
        # START: Listener Thread
        t = threading.Thread(target=receiverThread, args=(connection, numBytesPerRequest))
        t.daemon = True
        t.start()
        # q.put(t)
        # END:   Listener Thread


        # -----
        # START: updateKey Update Thread
        t = threading.Thread(target=updateKey, args=(1, 1))
        t.daemon = True
        t.start()


        print "C> Connected to: " + str(serverAddress) + " - port: " + str(portTCP) + " - name: " + username

        while True:
            # Send data
            message = raw_input("")
            pieces = message.split(" ")
            
            # If the message is a function, prepare the message format before sending
            if message != "" and pieces != "" and pieces[0][0] == "/" :
                requestType = pieces[0][1:].lower()
                
                # Catch a quit request using multiple synonyms
                if requestType == "q" or requestType == "quit" or requestType == "exit" or requestType == "close":
                    raise ValueError("C> '/q' or '/quitZ', entered, closing inner client loop...")
                # Handle multiple request types to list directories
                elif requestType == "ls" or requestType == "dir":
                    message = "/ls"
                elif requestType == "download":
                    if len(pieces) > 1:
                        placeholder = ""
                    else:
                        message = ""
            elif message != "":
                message = "/chat " + message
            
            # If the fully prepared message is not blank, send the message to the server
            if message != "":
                message = encryptString(addStartAndEndMarkers(message), previousKey)
                connection.sendall(message)

            #time.sleep(0.5)
                

    except:
        PrintException(debugMode)
        connection.shutdown()
        connection.close()


#
# Main Process
#

if __name__ == "__main__":
    try:
        main(sys.argv)
    except:
        PrintException(debugMode)
    finally:
        print "C> Goodbye!"