#!/usr/bin/python

# --- Documentation --- #
### DassPass
##  Portable Edition
#   By Nickolas Iaquinta - NLiaquin - nliaquin.xyz

## Description:
# DassPass Portable is my usb edition of DassPass which runs as
# a terminal application rather than a CLI or a GUI application.
# The biggest difference between this version and the CLI version
# is that the CLI version runs a parser that looks for arguments,
# or flags, that come after the program is called in the commandline.
# eg) dasspass --getpass facebook
# returns) your facebook password copied to the clipboard

# This version of DassPass runs as a terminal program, and
# the interpreter is just a string parser I wrote to derive commands
# from the user input. This version is ideal for saving on a usb
# device, whereas the other versions belong on the OS locally.


# --- Source Code --- #
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from objects import clsService
from getpass import getpass
import pyperclip
import readline
import pathlib
import base64
import os


## - Global Data - ##
# The standard seperation character.
SEPCHAR = " ; "

# This string is the location of the user's profile.
fileProfile = ''

# This dictionary stores a key of the service by name and a value of the service object.
services = {}

# This boolean determines whether printed service information is censored or plaintext.
blnIncognito = True


## - Cryptography Routines - ##

## initCrypto
# Initializes our cryptography backend for encrypting and decrypting data.
##
def initCrypto(passphrase):
    if not passphrase:
        print('Passphrase cannot be nothing')
        exit()
    else:
        passphrase = passphrase.encode()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt = getSalt(),
        iterations = 100000,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(passphrase))
    global crypto_service
    crypto_service = Fernet(key)

## encrypt
# Encrypts unencrypted information.
##
def encrypt(unencryptedData):
    encryptedData = crypto_service.encrypt(unencryptedData.encode())
    return encryptedData

## decrypt
# Decrypts encrypted information.
##
def decrypt(encryptedData):
    decryptedData = crypto_service.decrypt(encryptedData)
    return decryptedData.decode()

## testKey
# Tests to see if the given passphrase for an existing profile was correct.
##
def testKey():
    global fileProfile
    if os.path.exists(fileProfile):
        byteFile = open(fileProfile, 'rb')

        try:
            test = decrypt(byteFile.read())
        except:
            print('Incorrect passphrase used for existing profile.')
            exit()

import random, array

DIGITS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
LOCASE_CHARACTERS = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                     'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q',
                     'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
                     'z']
UPCASE_CHARACTERS = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                     'I', 'J', 'K', 'M', 'N', 'O', 'p', 'Q',
                     'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
                     'Z']
SYMBOLS = ['@', '#', '$', '%', '=', ':', '?', '.', '/', '|', '~', '>',
           '*', '(', ')', '<']

COMBINED_LIST = DIGITS + UPCASE_CHARACTERS + LOCASE_CHARACTERS + SYMBOLS

def genString():
    rand_digit = random.choice(DIGITS)
    rand_upper = random.choice(UPCASE_CHARACTERS)
    rand_lower = random.choice(LOCASE_CHARACTERS)
    rand_symbol = random.choice(SYMBOLS)

    temp_pass = rand_digit + rand_upper + rand_lower + rand_symbol

    for x in range(12 - 4):
        temp_pass = temp_pass + random.choice(COMBINED_LIST)
        temp_pass_list = array.array('u', temp_pass)
        random.shuffle(temp_pass_list)

    password = ''
    for y in temp_pass_list:
        password += y

    return password


## - File Routines - ##

## getProfileLocation
# Sets the global string, fileProfile, to the path of the user profile.
##
def getProfileLocation():
    global fileProfile
    progPath = pathlib.Path(__file__).parent.absolute()                 # The absolute location of dasspass.py
    strProfile = str(progPath) + '/profile'                             # Adds the profile file onto the path
    strProfile = strProfile.replace('\\', '/')                          # In case this program is running on Windows, we replace any backslashes with forward slashes.
    fileProfile = strProfile

## getSalt
# Either sets or gets the salt for each user.
# As an added layer of encryption, every profile comes with a salt.
# If a salt file is already found, the function just gets the salt from the file.
# If a salt file doesn't exist, this function creates a unique salt and writes it to a file.
# Regardless of the two scenarios, a salt is returned as a byte value
##
def getSalt():
    progPath = pathlib.Path(__file__).parent.absolute() # The absolute location of dasspass.py
    strSalt = str(progPath) + '/salt'
    strSalt = strSalt.replace('\\', '/')

    salt = b''                          # Instantiating a byte for the salt.

    if os.path.exists(strSalt):         # Scenario 1: We find the salt file.
        byteFile = open(strSalt, 'rb')  #  We prepare to read the salt in.
        salt = byteFile.read()          #  Stores the salt value in from the file.
        byteFile.close()                #  Closes the file.
    else:                               # Scenario 2: We couldn't find the salt file.
        salt = os.urandom(16)           #  We generate a new salt.
        byteFile = open(strSalt, 'wb')  #  Prepare to write the salt to a file.
        byteFile.write(salt)            #  Writes the salt to a file.

    return salt                         # Returns the salt value, whether new or old

## saveProfile
# This routine is called every time the program needs to save the changes made by the user.
##
def saveProfile():
    global fileProfile
    lines = ''                          # A reserved string for all the lines to be written to the profile file.

    # Python can sometimes mess up overwriting and automatically append instead of overwriting, so we're just going to remove the existing file instead.
    if os.path.exists(fileProfile):
        os.remove(fileProfile)

    # What I'm doing here is creating a line for each service that exists, storing the data in the given structure.
    for key in services:
        lines += services[key].getName() + SEPCHAR + services[key].getUser() + SEPCHAR + services[key].getPwd() + SEPCHAR + services[key].getNote() + SEPCHAR + ' \n'

    byteFile = open(fileProfile, 'wb')  # Gets the byte file ready for writing to.
    byteFile.write(encrypt(lines))      # Encrypts and writes the lines to the file.
    byteFile.close()                    # Closes the file out.

## loadProfile
# Reads in the services from the profile file, sets the services dictionary when finished.
##
def loadProfile():
    if os.path.exists(fileProfile):
        byteFile = open(fileProfile, 'rb')  # Getting ready to read in bytes from a byte file.
        lines = decrypt(byteFile.read())    # Reading in the bytes and decrypting them realtime.
        byteFile.close()

        print(lines)

        for line in lines.splitlines():     # Splits the file by linefeed.
            info = line.split(SEPCHAR)      # Splits each piece of information from a service by the special character.
            newService = clsService.service(info[0], info[1], info[2], info[3]) # Instantiating a new service object.
            services[info[0]] = newService  # Adds the name of the service as the key and the service object as the value in the services dictionary.


## - Service Manipulation Routines - ##

## addService
# Adds a given service to the services dictionary.
##
def addService(name, username, password, note):
    newService = clsService.service(name, username, password, note)
    services[name] = newService
    saveProfile()

## removeService
# Removes a given service from the services dictionary.
##
def removeService(service):
    services.pop(service)
    saveProfile()

## - Parser Routines - ##
## help
# Prints the commands available to the user.
##
def help(args):
    if len(args) == 1:
        print('Help Command')
    else:
        print('help does not take arguments')

## add
# Allows the user to add a service, including the username, password, and an optional note.
##
def add(args):
    if len(args) < 3:                           # Just checking to see the user entered 3 or more arguments when calling this command.
        print('Invalid number of arguments.')
    else:
        if args[1] in services.keys():      # args[1] holds the name of the service to be added.
            print('Service already exists. Please choose a different service name, or rename this service.')
        else:
            name = ''
            user = ''
            pwd = ''
            note = ''

            name = args[1]
            user = args[2]

            if len(args) == 3:                  # When the length of arguments is 3, this means the user wants to store a service and a username, but wants us to generate the password.
                pwd = genString()               # Generates a random password.
            elif len(args) == 4:                # When the length of arguments is 4, this means the user has set their own password, but chose not to give a note.
                pwd = args[3]
            else:                               # This just means that all arguments have been fulfilled. A note can take up several arguments due to everything being comma separated.
                pwd = args[3]
                for word in range(4, len(args)):
                    note += args[word] + ' '

            name = name.lower()

            addService(name, user, pwd, note) # All service names must be lowercase, that is my only formatting standard for clsServices
            print(f'Added {name}')
            saveProfile()

## remove
# Allows the user to remove a service completely.
##
def remove(args):
    if len(args) == 2:
        service = args[1]

        if service in services:
            if input(f'are you sure you want to remove {service}? (y/N)').lower() == 'y':
                removeService(service)
            else:
                print(f'canceled removing {service}')
        else:
            print('service not found')
    else:
        print('invalid number of arguments')

## get
# Contains all getter routines.
##
def get(args):
    if len(args) == 2:
        # Given that the length of args is 2, the user has not specified which piece
        # of information that want from a service, they just want the whole services
        # and its information displayed.
        service = args[1]

        if service in services:
            print(f'username: {services[service].getUser()}')

            global blnIncognito
            if blnIncognito:
                print("password:", '*' * (len(services[service].getPwd()) - 4) + services[service].getPwd()[len(services[service].getPwd()) - 4:])
            else:
                print(f'password: {services[service].getPwd()}')

            print(f'note: {services[service].getNote()}')
        else:
            print(f'{service} not found')
    elif len(args) == 3:
        service = args[1]
        option = args[2]
        # To explain what is happening here, the option is which piece of information
        # the user has specified. If this string turns out to be 'user', the username
        # of the service will be copied, if it is 'pwd', the password is copied, etc.
        if service in services:
            if option == 'user':
                pyperclip.copy(services[service].getUser())
                print(f'username from {service} copied to clipboard')
            elif option == 'pwd':
                pyperclip.copy(services[service].getPwd())
                print(f'password from {service} copied to clipboard')
            elif option == 'note':
                pyperclip.copy(services[service].getNote())
                print(f'note from {service} copied to clipboard')
            else:
                print(f'{option} not valid')
        else:
            print(f'note: {services[service].getNote()}')
    else:
        print('invalid number of arguments')

## set
# Contains all setter routines.
##
def set(args):
    if len(args) == 4:
        service = args[1]
        option = args[2]
        replacement = args[3]

        if service in services:
            if option == 'name':
                services[service].setName(replacement) # This changes the name in the object
                services[replacement] = services.pop(service) # This changes the key to the object
                print(f'{service} name changed')
            elif option == 'user':
                services[service].setUser(replacement)
                print(f'{service} username changed')
            elif option == 'pwd':
                services[service].setPwd(replacement)
                print(f'{service} password changed')
            elif option == 'note':
                services[service].setNote(replacement)
                print(f'{service} note changed')
            else:
                print(f'{option} not recognized')

            saveProfile()
        else:
            print(f'{service} not found')
    else:
        print('invalid number of arguments')

## genpass
# Sets a new password for a given service automatically.
##
def genpass(args):
    if len(args) == 2:
        service = args[1]

        if service in services:
            newPwd = genString()
            services[service].setPwd(newPwd)
            print(f'new password generated for {service} automatically')
        else:
            print(f'{service} not found')
    else:
        print('invalid number of arguments')

## incog
# Interprets whether the user wants incognito on or off
##
def incog(args):
    if len(args) == 2:
        switch = args[1]
        global blnIncognito

        if switch == 'off':
            blnIncognito = False
            print('incognito turned off')
        elif switch == 'on':
            blnIncognito = True
            print('incognito turned on')
        else:
            print(f'{switch} is not a valid option')
    else:
        print('incognito only takes on or off as an argument')

## list
# Lists all of the services the user has in DassPass.
##
def list(args):
    if len(args) == 1:
        if not services:
            print('No services found...')
        else:
            for service in sorted(services.keys()):
                print(service)
    else:
        print('list does not take arguments')

## clear
# Clears the terminal after determining which platform we're running on.
##
def clear(args):
    if len(args) == 1:
        if os.name == 'nt':         # We're running on Windows.
            _ = os.system('cls')
        else:                       # We're either running on Linux or Mac.
            _ = os.system('clear')
                                    # I might have to write something for Unix (BSD) later...
    else:
        print('clear does not take arguments')

## exit
# Gives the user a clean way to clean up and exit the program.
##
def exitDassPass(args):
    if len(args) == 1:
        services = None         # Clean our services out of memory.
        pyperclip.copy('')      # Clear the clipboard, which might be holding a password.
        clear([''])                 # Clear the screen in case anything private was printed beforehand.
        exit()                  # Shut down the program.
    else:
        print('exit does not take arguments')

## parseArgs
# Interprets the given argument/string from the user.
# This is a very minimalist string parsing technique that will be improved later.
# The idea is that we first split the words of the string given by the user into an array
# via the String.split() function. Then we determine what the command is by comparing the
# first element in the array against our supported list of commands. If the 0th
# element of the array is a recognized command, we send the array to the corresponding
# routine above to be analyzed. Else, we just tell the user that the given command
# is not supported.
##
def parseArgs(argString):
    args = argString.split(' ')     # I just want to take the individual words of the args string and throw them into an array.

    # We're now going to look at what the first element of the argument array is and interpet the user's desire from that.
    command = args[0]

    if command == 'help':
        help(args)
    elif command == 'add':
        add(args)
    elif command == 'remove':
        remove(args)
    elif command == 'get':
        get(args)
    elif command == 'set':
        set(args)
    elif command == 'genpass':
        genpass(args)
    elif command == 'incognito':
        incog(args)
    elif command == 'list':
        list(args)
    elif command == 'clear':
        clear(args)
    elif command == 'exit':
        exitDassPass(args)
    else:
        print('Command Unrecognized')

## main
# The following is an ordered list of what's happening here:
# 1. Get the location of the user profile.
# 2. Get the profile passphrase from the user.
# 3. Initialize the cryptography backend.
# 4. Test the user key and determine if they entered the correct passphrase.
# 5. Load the services from the profile.
# 6. Clear the screen and show that we're interpreting arguments now.
# 7. Keep the user in a argument parsing loop.
##
if __name__ == '__main__':
    try:
        getProfileLocation()
        passphrase = getpass('Enter your profile passphrase: ')
        initCrypto(passphrase)
        testKey()
        loadProfile()
        clear([''])

        while True:
            parseArgs(input('DassPass > '))

    except KeyboardInterrupt:
        exitDassPass([''])
    # I know throwing everything into a try-catch is bad practice, but the user can use a keyboard interrupt at any point during this program.
    # This use of try-catch is technically correct, and in python, it's not very costly when spoecifying the error to look out for.
    # This will be improved upon later.

