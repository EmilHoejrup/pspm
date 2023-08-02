import argparse
import getpass
import os
from zxcvbn import zxcvbn


def init(user):
    master_password = create_master_password()
    generate_encryption_key(master_password)
    #TODO use user


def create_master_password():
    while True:
        password = get_password()
        results = zxcvbn(password)
        if results['score'] != 4:
            print("password not strong enough ", results['feedback']['suggestions'])
        else:
            print("pspm vault created")
            return password
    

def generate_encryption_key(master):
    pass


def write_config(hashed_master):
    with open(".config", 'w') as config:
        config.write(hashed_master)
    os.chmod(".config", 0o600)

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
                        help="initialize pspm vault")
    parser.add_argument("-s", "--show", metavar="service",
                        help="show password for a service")
    parser.add_argument("-g", "--generate",
                        metavar="service", help="generate password for a service")

    args = parser.parse_args()

    if args.init:
        init(args.init)
    elif args.show:
        show_password(args.show)
    elif args.generate:
        generate_password(args.generate)
    else:
        parser.print_help()
