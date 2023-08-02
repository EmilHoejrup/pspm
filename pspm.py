import argparse
import getpass
import os
import argon2
import secrets
import string
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
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
    while True:
        password = get_password()
        results = zxcvbn(password, user_inputs=user)
        if results['score'] != 4:
            print("password not strong enough ", results['feedback']['suggestions'])
        else:
            print("pspm vault created for user", user)
            return password
    

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
            show_list(user)
        elif arg == 'g':
            generate_password(user)
        elif arg == 'x':
            return

  
def show_list(user):
    pass

# writes the master password to the users .config file and ensures only user has read and write permissions to it
def write_config(user, hashed_master):
    config_file = ".config_" + user
    with open(config_file, 'w') as config:
        config.write(hashed_master)
    os.chmod(config_file, 0o600)

def get_password():
    return getpass.getpass("Enter master password: ")


def show_password(service):
    if get_password() == "123":
        print("works")
        
def generate_password(user):
    service = input('''enter the name of the service you want to generate a password for
> ''')
    username = input('''enter your username for the service (enter if you do not want to store the username)
> ''')
    print(service, username)
    charset = string.ascii_letters + string.punctuation + string.digits
    encryption_key = generate_encryption_key(user)
    s = secrets.SystemRandom()
    s.seed(encryption_key)
    password = ''.join(s.choice(charset) for _ in range(16))
    print(password)


def generate_encryption_key(user):
    #TODO create proper salt
    salt = 'salt'.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=64,
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
