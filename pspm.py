import argparse
import getpass
import os
import argon2
import secrets
import string
import base64
import time
import pyperclip
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from zxcvbn import zxcvbn


def init(user):
    master_password = create_master_password(user)
    hashed_master = hash_password(master_password)
    write_config(user, hashed_master)
    menu(user)


def hash_password(password):
    # not sure if these parameters are optimal
    params = {"time_cost": 30, "memory_cost": 102400, "parallelism": 8, "hash_len": 256}
    return argon2.PasswordHasher(**params).hash(password.encode())
    

def create_master_password(user):
    #TODO check user does not already exist
    while True:
        print("create new pspm user \n")
        password = get_password()
        results = zxcvbn(password, user_inputs=user)
        # ensures that password has highest possible zxcvbn score
        if results['score'] != 4:
            print("password not strong enough ", results['feedback']['suggestions'])
        else:
            try:
                cwd = os.getcwd()
                os.mkdir(cwd + "/" + user + "_vault")
                print("pspm vault created for user", user)
                return password
            except FileExistsError:
                print("user already exists! try a new username")
                sys.exit()
                

def login(user):
    while True:
        provided_master = get_password()
        stored_master = get_master(user)
        if authenticate(stored_master, provided_master):
            menu(user)
            return
        else:
            print("incorrect password or username")


def authenticate(stored, provided):
    try:
        argon2.PasswordHasher().verify(stored, provided)
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False


def get_master(user):
    with open(".config_" + user) as config:
       return config.read() 

def menu(user):
    menu_options = '''\

Options:

l  : Show list of sites
g  : Generate new password
x  : Exit
rm : Remove site
'''
    while True:
        print(menu_options)
        arg = input("> ").lower()
        if arg == "l":
            show_password(user)
        elif arg == 'g':
            generate_password(user)
        elif arg == 'x':
            sys.exit()


# writes the master password to the users .config file and ensures only user has read and write permissions to it
def write_config(user, hashed_master):
    config_file = ".config_" + user
    with open(config_file, 'w') as config:
        config.write(hashed_master)
    os.chmod(config_file, 0o600)

def get_password():
    return getpass.getpass("Enter master password: ")

        
def generate_password(user):
    service = input('''enter the name of the service you want to generate a password for
> ''')
    charset = string.ascii_letters + string.punctuation + string.digits
    encryption_key = generate_encryption_key(user)
    s = secrets.SystemRandom()
    s.seed(encryption_key)
    password = ''.join(s.choice(charset) for _ in range(16))
    write_site(user, service, password)
    copy_to_clipboard(password)



def write_site(user, service, password):
    cwd = os.getcwd()
    path = cwd + "/" + user + "_vault/" + service
    with open(path, 'wb') as file:
        cipher = Fernet(base64.urlsafe_b64encode(generate_encryption_key(user)))
        encrypted_password = cipher.encrypt(password.encode())
        file.write(encrypted_password)
    os.chmod(path, 0o600)
    
def show_password(user):
    service = input("what site do you want the password for? \n > ")
    cwd = os.getcwd()
    path = cwd + "/" + user + "_vault/" + service
    try:
        cipher = Fernet(base64.urlsafe_b64encode(generate_encryption_key(user)))
        with open(path, 'rb') as file:
            encrypted_password = file.readline()
        decrypted_password = cipher.decrypt(encrypted_password).decode()
        copy_to_clipboard(decrypted_password)
    except IOError:
        print("site " + service + " not found")
 

def copy_to_clipboard(password):
    pyperclip.copy(password)
    print("Password copied to clipboard. It will be deleted in 15 sec")
    time.sleep(15)
    pyperclip.copy('')

def generate_encryption_key(user):
    #TODO create proper salt
    salt = 'salt'.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend
    )
    return kdf.derive(get_master(user).encode())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        "pspm (pretty secure password manager)")
    parser.add_argument("--init", "-i", metavar="user",
                        help="initialize new pspm vault for <user>")
    parser.add_argument("--login", "-l", metavar="user",
                        help="login as <user>")

    args = parser.parse_args()

    if args.init:
        init(args.init)
    elif args.login:
        login(args.login)
    else:
        parser.print_help()
