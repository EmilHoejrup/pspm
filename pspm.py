import argparse
import getpass
import os
from zxcvbn import zxcvbn
import argon2


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
    

def generate_encryption_key(master):
    pass

def login(user):
    while True:
        if get_password() == "123":
            menu(user)
        else:
            print("incorrect password or username")


def menu(user):
    menu_options = '''\
Options:

l : Show list of sites
g : Generate new password
x : Exit
rm: Remove site
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
        
def generate_password(service):
    pass


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
