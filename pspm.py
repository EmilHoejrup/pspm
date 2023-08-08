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

(1) Show list of services
(2) Get password for service
(3) Generate new password
(4) Remove service
(5) Edit credentials
(6) Exit
"""
    while True:
        arg = get_choice(menu_options)
        if arg == "1":
            list_services(user)
        elif arg == "2":
            show_password(user)
        elif arg == "3":
            generate_password(user)
        elif arg == "4":
            remove_password(user)
        elif arg == "5":
            edit_options(user)
        elif arg == "6":
            sys.exit()

def edit_options(user):
    options = """\
Options:
        
(1) Add username to site
(2) Change password for site
(3) Cancel
        """
    while True:
        arg = get_choice(options)
        if arg == "1":
            add_username(user)
        elif arg == "2":
            change_password(user)
        elif arg == "3":
            return
        
def get_choice(options):
    return input(options + "\n > ").lower()

def list_services(user):
    cwd = os.getcwd()
    path = cwd + "/" + user + "_vault/"
    services = os.listdir(path)
    if services == []:
        print("Vault is empty!")
        return
    print("your stored passwords are:")
    for s in services:
        print(s)

def get_service():
    return input("Enter name of service \n > ")


def remove_password(user):
    service = get_service()
    path = get_path_to_service(user, service)
    choice = input(
        f"removing password for {service} are you sure you want to proceed? [y/n] \n > "
    ).lower()
    if choice != "y":
        return
    try:
        os.remove(path)
        print(f"password for service {service} deleted")
    except FileNotFoundError:
        print(f"no password exist for {service}")

def get_path_to_service(user, service):
    cwd = os.getcwd()
    return cwd + "/" + user + "_vault/" + service
    


# writes the master password to the users .config file and ensures only user has read and write permissions to it
def write_config(user, hashed_master):
    config_file = ".config_" + user
    with open(config_file, "w") as config:
        config.write(hashed_master)
    os.chmod(config_file, 0o600)


def get_password():
    return getpass.getpass("Enter master password: ")


def generate_password(user):
    safe_mode = True
    service = input(
        """Enter the name of the service you want to generate a password for or hit ENTER for advanced options
> """
    )
    if service == "":
        length, charset = advanced_options()
        safe_mode = False
    elif exists(user, service):
        print("Service alerady exists!")
        return
    else:
        length = 16
        charset = string.ascii_letters + string.punctuation + string.digits
    salt = os.urandom(16)
    encryption_key = generate_encryption_key(salt, user)
    s = secrets.SystemRandom()
    s.seed(encryption_key)
    password = "".join(s.choice(charset) for _ in range(length))
    
    # ensure that password is strong enough (avoid issue of randomly generated weak password)
    while safe_mode and zxcvbn(password, user)["score"] != 4:
        password = "".join(s.choice(charset) for _ in range(length))
    write_service(user, service, password)
    copy_to_clipboard(password)

def exists(user, service):
    path = os.getcwd() + "/" + user + "_vault/"
    return service in os.listdir(path)

def advanced_options():
    charset = ""
    while True:
        try:
            length = int(input("Enter the desired password length\n > "))
            if length < 12:
                print("Alert: password length is shorter than recommended!")
        except ValueError:
            print("ERROR: length should be an integer! \nDefalut length 16 chosen \n")
            length = 16   
        chars = input("Enter all the allowed character types (l)etters, (s)pecial characters, (d)igits \n \n (can be combined) \n > ").lower()
        if 'l' in chars:
            charset = charset + string.ascii_letters
        if 's' in chars:
            charset = charset + string.punctuation
        if 'd' in chars:
            charset = charset + string.digits
        if charset != "":
            return length, charset
        else:
            print("Invalid options!")


def write_service(user, service, password):
    service = get_service()
    path = get_path_to_service(user, service)
    salt = os.urandom(16)
    # to avoid bug with newline in file - temporary fix
    salt = salt.replace(b"\n", b"b")
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

# TODO implement edit function
# TODO implement cli-options
# TODO add option to specify length of password and chars allowed
# TODO exception handling
# TODO documentation
# TODO split methods into smaller components
