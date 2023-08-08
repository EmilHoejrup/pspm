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
    return argon2.PasswordHasher().hash(password.encode())


def create_master_password(user):
    while True:
        print("create new pspm user \n")
        password = get_password()
        results = zxcvbn(password, user_inputs=user)
        # ensures that password has highest possible zxcvbn score
        if results["score"] != 4:
            print("password not strong enough ", results["feedback"]["suggestions"])
        else:
            try:
                cwd = os.getcwd()
                path = cwd + "/" + user + "_vault"
                os.mkdir(path)
                # ensure only user has access to vault
                os.chmod(path, 0o700)
                print("pspm vault created for user", user)
                return password
            except FileExistsError:
                print("user already exists! use another username")
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
    menu_options = """\

Options:

l  : Show list of services
s  : Get password for service
g  : Generate new password
x  : Exit
r  : Remove service
"""
    while True:
        print(menu_options)
        arg = input("> ").lower()
        if arg == "s":
            show_password(user)
        elif arg == "l":
            list_services(user)
        elif arg == "r":
            remove_password(user)
        elif arg == "g":
            generate_password(user)
        elif arg == "x":
            sys.exit()


def list_services(user):
    cwd = os.getcwd()
    path = cwd + "/" + user + "_vault/"
    print("your stored passwords are:")
    services = os.listdir(path)
    for s in services:
        print(s)


def remove_password(user):
    service = input("enter name of service to remove \n > ")
    cwd = os.getcwd()
    path = cwd + "/" + user + "_vault/" + service
    choice = input(f"removing password for {service} are you sure you want to proceed? [y/n] \n > ").lower()
    if choice != "y":
        return
    try:
        os.remove(path)
        print(f"password for service {service} deleted")
    except FileNotFoundError:
        print(f"no password exist for {service}")

# writes the master password to the users .config file and ensures only user has read and write permissions to it
def write_config(user, hashed_master):
    config_file = ".config_" + user
    with open(config_file, "w") as config:
        config.write(hashed_master)
    os.chmod(config_file, 0o600)


def get_password():
    return getpass.getpass("Enter master password: ")


def generate_password(user):
    service = input(
        """enter the name of the service you want to generate a password for
> """
    )
    charset = string.ascii_letters + string.punctuation + string.digits
    salt = os.urandom(16)
    encryption_key = generate_encryption_key(salt, user)
    s = secrets.SystemRandom()
    s.seed(encryption_key)
    password = "".join(s.choice(charset) for _ in range(16))
    # ensure that password is strong enough (avoid issue of randomly generated weak password)
    while zxcvbn(password, user)["score"] != 4:
        password = "".join(s.choice(charset) for _ in range(16))
    write_service(user, service, password)
    copy_to_clipboard(password)


def write_service(user, service, password):
    cwd = os.getcwd()
    path = cwd + "/" + user + "_vault/" + service
    salt = os.urandom(16)
    # to avoid bug with newline in file - temporary fix
    salt = salt.replace(b'\n',b'b')
    with open(path, "wb") as file:
        cipher = Fernet(base64.urlsafe_b64encode(generate_encryption_key(salt, user)))
        encrypted_password = cipher.encrypt(password.encode())
        file.writelines([salt + b"\n", encrypted_password])
    os.chmod(path, 0o600)


def show_password(user):
    service = input("what service do you want the password for? \n > ")
    cwd = os.getcwd()
    path = cwd + "/" + user + "_vault/" + service
    try:
        with open(path, "rb") as file:
            salt, encrypted_password = file.read().splitlines()
        cipher = Fernet(base64.urlsafe_b64encode(generate_encryption_key(salt, user)))
        decrypted_password = cipher.decrypt(encrypted_password).decode()
        copy_to_clipboard(decrypted_password)
    except IOError:
        print("service " + service + " not found")


def generate_encryption_key(salt, user):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend,
    )
    return kdf.derive(get_master(user).encode())


def copy_to_clipboard(password):
    pyperclip.copy(password)
    print("Password copied to clipboard. It will be deleted in 5 sec")
    time.sleep(5)
    pyperclip.copy("")


if __name__ == "__main__":
    parser = argparse.ArgumentParser("pspm (pretty secure password manager)")
    parser.add_argument(
        "--init", "-i", metavar="user", help="initialize new pspm vault for <user>"
    )
    parser.add_argument("--login", "-l", metavar="user", help="login as <user>")

    args = parser.parse_args()

    if args.init:
        init(args.init)
    elif args.login:
        login(args.login)
    else:
        parser.print_help()

#TODO implement edit function
#TODO implement cli-options
#TODO add option to specify length of password and chars allowed
#TODO exception handling
#TODO documentation
#TODO split methods into smaller components
