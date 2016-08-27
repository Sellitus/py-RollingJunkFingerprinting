#!/usr/bin/python

import Queue
import socket
import threading
import os
import select
import time

from Shared import *


#----------------------USER SETTINGS----------------------

# Number of bytes of data per request (synched with client)
numBytesPerRequest = 8192
# Listen port
port = 9001

add_passwords_filename = "server_add_listen_passwords.txt"
password_database = "server_password_database.txt"

# Stores all messages sent to the server along with metadata
messageStorage = []
# Hashmap that stores the name of the user along with the connection itself in a matching hashmap
connectionArray = {}
connectionNames = {}
connectionVerified = {}

# Stores the passwords the server is currently listening for
listenPasswords = {}
# Amount of time in minutes the password is valid for.
passwordDuration = 5

fileDirectory = "files_server/"

# Enable/Disable debug mode
debugMode = 0

# Key: NOTE-Must be changed in production environment
uniqueKey = "1A4F428BB6AA987E075C92A4"
previousKey = ''
beforePreviousKey = ''
# Converts key to 32 bytes in UTF-8 for AES encryption
uniqueKey = "{: <32}".format(uniqueKey).encode("utf-8")
# IV: NOTE-Must be changed in production environment
ivKey = "#%F--?PstR71"
# Converts IV to 16 bytes in UTF-8 for AES encryption
# NOT NEEDED NOW THAT FUNCTIONS ACCOUNT FOR FORMAT
#ivKey = "{: <16}".format(ivKey).encode("utf-8")

#---------END----------USER SETTINGS----------------------



#----------------------REGULAR FUNCTIONS----------------------

# Same as the client version except it only reads from the file at startup.
# Look at the addListenToPasswords() function for adding passwords with IPs to the file
# NOTE: Stores all passwords double hashed
def checkPasswordFile(nameoffile):
    try:
        included_extenstions = ['pass']
        file_names = [fn for fn in os.listdir(os.getcwd())
            if any(fn.endswith(ext) for ext in included_extenstions)]
                  
        for f in file_names:
            databaselines = open(f, "r+")
            for line in databaselines:
                ipandpass = line.strip().split(" ")
                ip = ipandpass[0]
                password = ipandpass[1]
    
                listenPasswords[ip] = password
    except:
        PrintException(debugMode)





#---------END----------REGULAR FUNCTIONS----------------------



#----------------------HANDSHAKE FUNCTIONS----------------------

# Simply checks to see if the passed fingerprint is valid (in listenFingerprints)
def checkPasswordValid(ip, password):
    if (listenPasswords.has_key(ip) and listenPasswords[ip] == password):
        return True
    return False
    
def getPassFile(ip):
    try:
        databaselines = open(ip + ".pass", "r+")
        for line in databaselines:
            return line.strip().split(" ")[1]
    except:
        return "NOPE"

# Adds a password into the listening array. Checks for duplicates.
def addListenPassword(ip, password):
    # Checks to make sure listenFingerprint is not already in the array
    if listenPasswords.has_key(ip) and listenPasswords[ip] == password:
        print "S> Password " + str(listenPasswords[ip]) + " already exists for IP: " + str(ip)
        return
    # If the password does not exist in the listenPasswords array, add it
    listenPasswords[ip] = password
    print "S> Now listening for password: " + str(password) + " from IP: " + str(ip)
    return

#---------END----------HANDSHAKE FUNCTIONS----------------------



#----------------------THREAD FUNCTIONS----------------------

# Background thread that examines the passwords file every so often to check for recently added passwords
# Clears the file every time any amount of passwords are added to it and adds them to the listenPasswords array
# This allows a client to initiate a connection by entering the first password

# The threadID variable is a placeholder

# USAGE  : add_listen_passwords.txt
# FORMAT : <ip address> <password to associate with ip>
# EXAMPLE: 127.0.0.1 password123

def listenToPasswordsFile (add_passwords_filename, threadID, interval=1):
    while True:
        try:
            passwordsToAdd =  open(add_passwords_filename, "r+")
            # Add ips and passwords line by line. Whitespace at front and back will be trimmed.
            firstLine = passwordsToAdd.readline().strip()
            if firstLine != "":
                # Split the line into the IP and password
                # NOTE: In this case, the IP represents the port, which is associated with the password.
                firstLine = firstLine.split(" ")

                ip = firstLine[0]
                password = firstLine[1].strip()
                print password
                password = hashlib.sha256(hashlib.sha256(password).hexdigest()).hexdigest()
                print password
                # Clear unhashed password memory
                firstLine = ""

                addListenPassword(ip, password)
                passwordsToAdd.close()
                # After the file has been written to, erase it
                passwordsToAdd = open(add_passwords_filename, "w+")
                passwordsToAdd.write("")
                passwordsToAdd.close()

                addPassToDatabase = open(ip + ".pass", 'a+')
                addPassToDatabase.write(ip + " " + password + "\n")
                addPassToDatabase.close()
        except:
            PrintException(debugMode)

        time.sleep(interval)



# TODO: Need thread to check for expiration of passwords




# Thread to check and update IV used for the AES encryption
def updateKey(q, interval):
    while True:
        global uniqueKey
        global previousKey
        global beforePreviousKey
        currKey = getCurrentOTP()

        if currKey != uniqueKey:
            if q.empty():
                beforePreviousKey = previousKey
                previousKey = uniqueKey
                uniqueKey = currKey
            else:
                q.get()
                return

#            print "Server IV = " + uniqueKey
#            print "Server IV Previous = " + previousIV
#            print "Server IV Before Previous = " + beforePreviousKey

        time.sleep(interval)
    
def updateSeed(q, client_ip):
    while True:
        #time.sleep(random.randrange(30,31))
        time.sleep(10)
        if q.empty():
            connection.sendall(encryptString(addStartAndEndMarkers("ReSeed" + id_generator(random.randrange(50,200))), previousKey))

            newKey = hashlib.sha256(getCurrentSeed()).hexdigest()

            listenPasswords[client_ip] = newKey

            addPassToDatabase = open(client_ip + ".pass", 'w+')
            addPassToDatabase.write(client_ip + " " + newKey + "\n")
            addPassToDatabase.close()
        else:
            q.get()
            return

        


# The client connection setup for threading (as a function)
def clientThread (connection, client_ip, numBytesPerRequest):

    print "S> Client from " + client_ip + " connected. Authenticating..."

    global uniqueKey
    global previousKey
    global beforePreviousKey

    currKey = generateNewSeed(getPassFile(client_ip).strip(), 0)

    if currKey == "NOPE":
        print "----ERROR----"
        print "Not listening for connection from: " + client_ip
        return

    timedpass = timedPassword(currKey)
    generateNewSeed(timedpass)
    timedpass = timedPassword(getCurrentSeed())

    uniqueKey = timedpass
    previousKey = uniqueKey
    beforePreviousKey = previousKey


    q = Queue.Queue()
    # Start updateKey thread
    thread1 = threading.Thread(target=updateKey, args=(q, 1))
    thread1.daemon = True
    thread1.start()
    
    #Start updateSeed
    thread2 = threading.Thread(target=updateSeed, args=(q, client_ip))
    thread2.daemon = True
    thread2.start()

    # Get the username from the next packet sent
    username = decryptString(connection.recv(numBytesPerRequest), uniqueKey, previousKey, beforePreviousKey).strip()
    username = removeStartAndEndMarkers(username)

    # Perform check/handshake
    # NOTE: Hashed a second time. Client stores pass as a single hash, then hashes it before for safer
    #    transmission.
    password = decryptString(connection.recv(numBytesPerRequest), uniqueKey, previousKey, beforePreviousKey).strip()
    password = removeStartAndEndMarkers(password)


    # Simple sleep for X seconds as a simple brute force prevention mechanism
    time.sleep(1)


    # Allows or denies the client access
    approved = checkPasswordValid(client_ip, password)

    if approved == True:
        # Add the connection and username to corresponding hashmaps
        connectionArray[client_ip] = connection
        connectionNames[client_ip] = username
        connection.sendall(encryptString(addStartAndEndMarkers("CONFIRMED"), previousKey))
    else:
        print "S> Client: " + str(client_ip) + " provided invalid password: " + str(password)
        connection.sendall(encryptString(addStartAndEndMarkers("DENIED"), previousKey))
        connection.close()
        return

    junk = decryptString(connection.recv(numBytesPerRequest), uniqueKey, previousKey, beforePreviousKey).strip()
    junk = removeStartAndEndMarkers(junk)
    generateNewSeed(junk+uniqueKey)

    beforePreviousKey = previousKey
    previousKey = uniqueKey
    uniqueKey = timedPassword(getCurrentSeed())



    # Finish performing check/handshake

    
    # Placed outside loop for scope
    command = ""
    encryptedString = ""

    # Inside try for easy debugging
    try:
        print "S> Client from " + str(client_ip) + " has fully authenticated: " + str(username)

        # Receive the data in chunks set by numBytesPerRequest, keep looping until no data is being sent.
        while True:
            encryptedString = connection.recv(numBytesPerRequest)

            command = command + encryptedString
            tempDecrypt = decryptString(command, uniqueKey, previousKey, beforePreviousKey)

            if tempDecrypt != "-ERROR-":
                if len(tempDecrypt) > 0 and startMarker in tempDecrypt and endMarker in tempDecrypt:
                    command = tempDecrypt
                    # Remove unique start and end markers
                    command = removeStartAndEndMarkers(command)

                    pieces = command.split(" ")
                    request_type = pieces[0][1:].lower()

                    # The client's perspective is what upload and download stand for
                    # Ex: Upload = ClientToSrvr , Download = SrvrToClient
                    if request_type == "upload":
                        print "S> " + str(client_ip) + " - " + username + ": " + command[0:29].replace("\n", "")
                        # Construct file dir + name
                        file_name = pieces[1]
                        test_file_name = fileDirectory + "s-up.txt"
                        # Open a file in write mode
                        test_file = open(test_file_name, "w+")
                        # Grab actual data
                        data = command[12:]
                        test_file.write(data)
                        test_file.close()
                    elif request_type == "download":
                        print "S> " + str(client_ip) + " - " + username + ": " + command
                        # Construct file dir + name
                        file_name = pieces[1]
                        transfer_file = open(fileDirectory + str(file_name), "rb")
                        transfer_file = transfer_file.read()
                        # Construct full command
                        commandRequest = pieces[0] + " " + transfer_file + endMarker
                        # Grab client making the request and send the encrypted data
                        connectionArray[client_ip].sendall(encryptString(addStartAndEndMarkers(commandRequest), previousKey))
                        print "S> " + file_name + " transferred to " + str(client_ip) + " successfully!"
                    elif request_type == "ls":
                        print "S> " + str(client_ip) + " - " + username + ": " + command
                        # Grab file list within server storage dir
                        files = os.listdir(fileDirectory)
                        command = pieces[0] + " Files: " + str(files) + endMarker
                        connectionArray[client_ip].sendall(encryptString(addStartAndEndMarkers(command), previousKey))
                    elif request_type == "chat":
                        print "S> " + str(client_ip) + " - " + username + ": " + command
                        # Store the chat message in the messageStorage
                        messageStorage.append(command)
                        if(command.split(" ")[1] == "quit"):
                            print "Quit"
                        # Send message to all active connections if there is a non-blank message
                        if command:
                            for key in connectionArray.keys():
                                if connectionArray[key] != connection:
                                    try:
                                        connectionArray[key].sendall(encryptString(addStartAndEndMarkers(pieces[0] + " " + username + ": " +
                                                                                   command), previousKey))
                                    except:
                                        connectionArray.pop(key, None)
                                        connectionNames.pop(key, None)
                    else:
                        # Or: INVALID COMMAND!!!!!!!
                        print "S> INVALID COMMAND " + str(client_ip) + " - " + username + ": " + \
                              command[0:29].replace("\n", "")
                # Clear out command after full function executes
                command = ""
            else:
                print 'S> INVALID COMMAND SENT FROM: ' + client_ip + " (" + username + "): " + tempDecrypt
                # Invalid command = clear it out of buffer
                command = ""

    except:
        pass

                # time.sleep(X) a tiny amount of time to prevent resource hogging/attacks
                #time.sleep(0.5)
    finally:
        try:
            # Put 2 ones in the Queue so the subthreads do not save if the client is disconnected
            q.put(1)
            q.put(1)
            # Clean up the connection
            connection.shutdown()
            connection.close()
            connectionArray.pop(client_ip)
        except:
            # Only clear the connection, since it is definitely done and the connection itself will timeout
            connectionArray.pop(client_ip)

        PrintException(debugMode)
        print "S> DISCONNECTED " + str(client_ip) + " - " + username

#---------END----------THREAD FUNCTIONS----------------------



#----------------------MAIN----------------------

if __name__ == "__main__":

    checkPasswordFile(password_database)

    q = Queue.Queue()
    
    try:
        rundir = os.path.dirname(sys.argv[0])
        if rundir == "":
            rundir = os.curdir

        # Initiate fingerprint file listener
        t = threading.Thread(target=listenToPasswordsFile, args=(add_passwords_filename, 1))
        t.daemon = True
        t.start()
        q.put(t)
    
        # Initialize context
        ctx = SSL.Context(SSL.TLSv1_METHOD)
        ctx.set_verify(SSL.VERIFY_PEER|SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_cert) # Demand a certificate
        ctx.use_privatekey_file (os.path.join(rundir, 'keys/server/server.pkey'))
        ctx.use_certificate_file(os.path.join(rundir, 'keys/server/server.cert'))
        ctx.load_verify_locations(os.path.join(rundir, 'keys/server/CA.cert'))

        # Create a TCP/IP socket
        sock = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        sock.bind(('', port))
        # Listen for incoming connections
        sock.listen(3)
        sock.setblocking(0)

        # Client connection counter
        i = 0
        
        clients = {}
        writers = {}
        
        print >>sys.stderr, "S> LISTENING ON: " + str(port)
        print 'S> Waiting for a client to connect...'
        
        # Repeat indefinitely to handle an indefinite number of connection
        while True:
            # Wait for a connection
            r, w, _ = select.select([sock]+clients.keys(), writers.keys(), [])
            
            # Accept the new connection
            connection, client_ip = sock.accept()
            client_ip = client_ip[0]

            threadID = i + 1

            t = threading.Thread(target=clientThread, args=(connection, client_ip, numBytesPerRequest))
            t.daemon = True
            t.start()
            q.put(t)

            i = threadID
    finally:
        for tempConnection in connectionArray:
            try:
                tempConnection.close()
            except:
                nothing = "done"
        print "S> Goodbye!"

#---------END----------MAIN----------------------
