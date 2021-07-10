#!/usr/bin/python

# --- Documentation --- #
# DassPass
# Portable Edition
#   By Nickolas Iaquinta - NLiaquin - nliaquin.xyz

# Description:
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
import array
import random
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

# initCrypto
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
        salt=getSalt(),
        iterations=100000,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(passphrase))
    global crypto_service
    crypto_service = Fernet(key)

# encrypt
# Encrypts unencrypted information.
##


def encrypt(unencryptedData):
    encryptedData = crypto_service.encrypt(unencryptedData.encode())
    return encryptedData

# decrypt
# Decrypts encrypted information.
##


def decrypt(encryptedData):
    decryptedData = crypto_service.decrypt(encryptedData)
    return decryptedData.decode()

# testKey
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


def cleanseStrings(args):
    if len(args) == 1:
        for service in services.values():
            name = service.getName()
            user = service.getUser()
            pwd = service.getPwd()
            note = service.getNote()

            print(f'Cleansing {name}')

            if name[-1] == ' ':
               service.setName(name[:-1])

            if user[-1] == ' ':
                service.setUser(user[:-1])

            if pwd[-1] == ' ':
                service.setPwd(pwd[:-1])

            if len(note) != 0:
                if note[-1] == ' ':
                    service.setNote(note[:-1])
        saveProfile()
    else:
        print('cleanse does not take arguments')

## - File Routines - ##

# getProfileLocation
# Sets the global string, fileProfile, to the path of the user profile.
##
def getProfileLocation():
    global fileProfile
    # The absolute location of dasspass.py
    progPath = pathlib.Path(__file__).parent.absolute()
    # Adds the profile file onto the path
    strProfile = str(progPath) + '/profile'
    # In case this program is running on Windows, we replace any backslashes with forward slashes.
    strProfile = strProfile.replace('\\', '/')
    fileProfile = strProfile

# getSalt
# Either sets or gets the salt for each user.
# As an added layer of encryption, every profile comes with a salt.
# If a salt file is already found, the function just gets the salt from the file.
# If a salt file doesn't exist, this function creates a unique salt and writes it to a file.
# Regardless of the two scenarios, a salt is returned as a byte value
##


def getSalt():
    # The absolute location of dasspass.py
    progPath = pathlib.Path(__file__).parent.absolute()
    strSalt = str(progPath) + '/salt'
    strSalt = strSalt.replace('\\', '/')

    salt = b''                          # Instantiating a byte for the salt.

    if os.path.exists(strSalt):         # Scenario 1: We find the salt file.
        byteFile = open(strSalt, 'rb')  # We prepare to read the salt in.
        salt = byteFile.read()  # Stores the salt value in from the file.
        byteFile.close()  # Closes the file.
    else:                               # Scenario 2: We couldn't find the salt file.
        salt = os.urandom(16)  # We generate a new salt.
        byteFile = open(strSalt, 'wb')  # Prepare to write the salt to a file.
        byteFile.write(salt)  # Writes the salt to a file.

    return salt                         # Returns the salt value, whether new or old

# saveProfile
# This routine is called every time the program needs to save the changes made by the user.
##


def saveProfile():
    global fileProfile
    # A reserved string for all the lines to be written to the profile file.
    lines = ''

    # Python can sometimes mess up overwriting and automatically append instead of overwriting, so we're just going to remove the existing file instead.
    if os.path.exists(fileProfile):
        os.remove(fileProfile)

    # What I'm doing here is creating a line for each service that exists, storing the data in the given structure.
    for key in services:
        lines += services[key].getName() + SEPCHAR + services[key].getUser() + SEPCHAR + \
            services[key].getPwd() + SEPCHAR + \
            services[key].getNote() + SEPCHAR + '\n' ## removed a space before \n (7/5/21)

    # Gets the byte file ready for writing to.
    byteFile = open(fileProfile, 'wb')
    # Encrypts and writes the lines to the file.
    byteFile.write(encrypt(lines))
    byteFile.close()                    # Closes the file out.

# loadProfile
# Reads in the services from the profile file, sets the services dictionary when finished.
##


def loadProfile():
    if os.path.exists(fileProfile):
        # Getting ready to read in bytes from a byte file.
        byteFile = open(fileProfile, 'rb')
        # Reading in the bytes and decrypting them realtime.
        lines = decrypt(byteFile.read())
        byteFile.close()

        for line in lines.splitlines():     # Splits the file by linefeed.
            # Splits each piece of information from a service by the special character.
            info = line.split(SEPCHAR)
            # Instantiating a new service object.
            newService = clsService.service(info[0], info[1], info[2], info[3])
            # Adds the name of the service as the key and the service object as the value in the services dictionary.
            services[info[0]] = newService


## - Service Manipulation Routines - ##

# addService
# Adds a given service to the services dictionary.
##
def addService(name, username, password, note):
    newService = clsService.service(name, username, password, note)
    services[name] = newService
    saveProfile()

# removeService
# Removes a given service from the services dictionary.
##


def removeService(service):
    services.pop(service)
    saveProfile()

## - Parser Routines - ##
# help
# Prints the commands available to the user.
##


def help(args):
    if len(args) == 1:
        print("""
              DassPass is developed by Nickolas Iaquinta. NLiaquin.xyz

              Lexicon
              service or name - a website or application by its actual name, ie. steam, gmail, youtube, etc. Names can only be
              lowercase when stored in the database, duplicate entries not allowed at this time.
              user - the username to a service.
              pwd - the password to a service.


              Commands
              add: takes a minimum of 2 arguments, at least requiring a service name and a username. You may specify a password,
                but if you don't specify one, the program will automatically generate a strong password for you. If you specify a
                password, you may also specify a note after.
              usage - name user pwd(optinal) note(optional)
              example - add youtube johndoe NJFjldanbl03 this is a note, it can contain any spaces or chracters, it does not matter
              note - when using add, you must follow the order above in usage.

              remove: removes a given service by name.
              usage - remove name
              example - remove youtube
              note - remove gets rid of entire services, not just a data member of a service.

              set: allows you to change or add information to a service, including changing the name of a service, changing the
                user of a service, changing the pwd of a service, and adding or changing the note of a service.
              usage - set name user 'username'
              ex 2 - set name name 'service name'
              ex 3 - set name pwd 'password'
              ex 4 - set name note 'note'
              example - set youtube user bobby12 (changes the username to bobby12)
              example 2 - set youtube pwd GDFHKSBjfkjads233 (changes the password)
              example 3 - set youtube note this is a note
              note - setting new information overwrites old information.

              get: gets specific, or all, information from a service.
              usage - get name user
              ex 2 - get name pwd
              ex 3 - get name note
              example - get youtube pwd (copies the password to the clipboard)
              example 2 - get youtube note (copies the note to the clipboard)
              example 3 - get youtube (prints out all information about a service)
              note - the last example prints all info to the terminal instead of copying specific information to the clipboard like
                the first two examples do. When printing info rather than copying, the incognito var will determine whether info is
                printed partially censored or clear text. Learn more about toggling incognito below.

              genpass: generates a strong new password for a given service.
              usage - genpass name
              example - genpass youtube (generates a strong new password for youtube, overwriting the old one.)
              note - be sure to log into the service and get ready to change the password first before overwriting and losing your old password.

              cleanse: if you're noticing that you're pasting any items copied from the program with an extra space at the end, call this command to cleanse the end of every single service field.
              usage - cleanse
              example - cleanse
              note - all this does is removes the last character from your name, user, password, or note of each service if one is found.

              incognito: allows toggling of censorship when printing an entire service.
              usage - incognito off (turns off incognito)
              ex 2 - incognito on (turns on incognito)
              note: incognito only censors passwords partially, revealing last four digits.

              list: lists all service names in your profile.
              usage - list
              note - only the names of services next to an index (not hardcoded, just for counting services) of the service.

              clear: clears the interface of all information, works exactly like terminal clear.
              usage - clear
              note - clear is automatically called when using exit.

              exit: exits DassPass Portable, clearing out any data related to the program from immediate memory.
              usage - exit
              note - ctrl+c will call exit.
              """)
    else:
        print('help does not take arguments')

# add
# Allows the user to add a service, including the username, password, and an optional note.
##


def add(args):
    # Just checking to see the user entered 3 or more arguments when calling this command.
    if len(args) < 3:
        print('Invalid number of arguments.')
    else:
        # args[1] holds the name of the service to be added.
        if args[1] in services.keys():
            print(
                'Service already exists. Please choose a different service name, or rename this service.')
        else:
            name = ''
            user = ''
            pwd = ''
            note = ''

            name = args[1]
            user = args[2]

            # When the length of arguments is 3, this means the user wants to store a service and a username, but wants us to generate the password.
            if len(args) == 3:
                pwd = genString()               # Generates a random password.
            # When the length of arguments is 4, this means the user has set their own password, but chose not to give a note.
            elif len(args) == 4:
                pwd = args[3]
            # This just means that all arguments have been fulfilled. A note can take up several arguments due to everything being comma separated.
            else:
                pwd = args[3]
                for word in range(4, len(args)):
                    note += args[word] + ' '

            name = name.lower()

            # All service names must be lowercase, that is my only formatting standard for clsServices
            addService(name, user, pwd, note)
            print(f'Added {name}')
            saveProfile()

# remove
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

# get
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
                print("password:", '*' * (len(services[service].getPwd()) - 4) +
                      services[service].getPwd()[len(services[service].getPwd()) - 4:])
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
            print(f'{service} not found')
    else:
        print('invalid number of arguments')

# set
# Contains all setter routines.
##


def set(args):
    if len(args) >= 4:
        service = args[1]
        option = args[2]
        replacement = args[3]

        if service in services:
            if option == 'name':
                # This changes the name in the object
                services[service].setName(replacement)
                # This changes the key to the object
                services[replacement] = services.pop(service)
                print(f'{service} name changed')
            elif option == 'user':
                services[service].setUser(replacement)
                print(f'{service} username changed')
            elif option == 'pwd':
                services[service].setPwd(replacement)
                print(f'{service} password changed')
            elif option == 'note':
                note = ''

                for word in range(3, len(args)):
                    note += args[word] + ' '

                services[service].setNote(note)
                print(f'{service} note changed')
            else:
                print(f'{option} not recognized')

            saveProfile()
        else:
            print(f'{service} not found')
    else:
        print('invalid number of arguments')

# genpass
# Sets a new password for a given service automatically.
##


def genpass(args):
    if len(args) == 2:
        service = args[1]

        if service in services:
            newPwd = genString()
            services[service].setPwd(newPwd)
            saveProfile()
            print(f'new password generated for {service} automatically')
        else:
            print(f'{service} not found')
    else:
        print('invalid number of arguments')

# incog
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

# list
# Lists all of the services the user has in DassPass.
##


def list(args):
    if len(args) == 1:
        if not services:
            print('No services found...')
        else:
            i = 1

            for service in sorted(services.keys()):
                print(i, service)
                i += 1
    else:
        print('list does not take arguments')

# clear
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

# exit
# Gives the user a clean way to clean up and exit the program.
##


def exitDassPass(args):
    if len(args) == 1:
        services = None         # Clean our services out of memory.
        # Clear the clipboard, which might be holding a password.
        pyperclip.copy('')
        # Clear the screen in case anything private was printed beforehand.
        clear([''])
        exit()                  # Shut down the program.
    else:
        print('exit does not take arguments')

# parseArgs
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
    # I just want to take the individual words of the args string and throw them into an array.
    args = argString.split(' ')

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
    elif command == 'cleanse':
        cleanseStrings(args)
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


# main
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
