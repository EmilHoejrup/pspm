import argparse
import getpass
import os
import argon2
import secrets
import string
import base64
import pyperclip
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from zxcvbn import zxcvbn


def init(user):
    master_password = create_master_password(user)
    create_master_key(user, master_password)
    hashed_master = hash_password(master_password)
    write_config(user, hashed_master)
    menu(user)


def create_master_key(user, master_password):
    global m_key
    m_key = generate_encryption_key(user.encode(), master_password.encode())


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
    try:
        while True:
            provided_master = get_password()
            stored_master = get_master(user)
            if authenticate(stored_master, provided_master):
                create_master_key(user, provided_master)
                menu(user)
                return
            else:
                print("incorrect password or username")
    except FileNotFoundError:
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

Options (enter number):

(1) Show list of services
(2) Get password for service
(3) Generate new password
(4) Remove service
(5) Add username for service
(6) Show username for service
(7) Exit
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
            add_username(user)
        elif arg == "6":
            show_username(user)
        elif arg == "7":
            sys.exit()


def add_username(user):
    service = get_service()
    if not exists(user, service):
        print("Service does not exist! Generate a password first")
        return
    path = get_path_to_service(user, service)
    username = input("Enter username \n > ")
    encrypted_username = encrypt(username)
    with open(path, "ab") as file:
        file.write(encrypted_username)


def get_choice(options):
    return input(options + "\n > ").lower()


def list_services(user):
    cwd = os.getcwd()
    path = cwd + "/" + user + "_vault/"
    services = os.listdir(path)
    if services == []:
        print("Vault is empty!")
        return
    print("your stored passwords are: \n")
    for s in services:
        print(s)


def get_service():
    return input("Enter name of service \n > ")


def remove_password(user):
    service = get_service()
    path = get_path_to_service(user, service)
    choice = input(
        f'removing password for "{service}" are you sure you want to proceed? [y/n] \n > '
    ).lower()
    if choice != "y":
        print("Exiting to main menu \n")
        return
    try:
        os.remove(path)
        print(f'password for service "{service}" deleted')
    except FileNotFoundError:
        print(f'no password exist for "{service}"')


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
        """Enter the name of the service you want to generate a password for or hit ENTER for custom password options
> """
    )
    if service == "":
        service, length, charset = custom_options()
        # user might have chosen unsafe password options
        safe_mode = False
    elif exists(user, service):
        print("Service alerady exists!")
        return
    else:
        length = 16
        charset = string.ascii_letters + string.punctuation + string.digits
    s = secrets.SystemRandom()
    s.seed(m_key)
    password = "".join(s.choice(charset) for _ in range(length))

    # ensure that password is strong enough (avoid issue of randomly generated weak password)
    while safe_mode and zxcvbn(password, user)["score"] != 4:
        password = "".join(s.choice(charset) for _ in range(length))
    write_service(user, service, password)
    copy_to_clipboard(password, "password")


def exists(user, service):
    path = os.getcwd() + "/" + user + "_vault/"
    return service in os.listdir(path)


def custom_options():
    print("Creating custom type password")
    service = get_service()
    charset = ""
    while True:
        try:
            length = int(input("Enter the desired password length\n > "))
            if length < 12:
                print("Alert: password length is shorter than recommended!")
        except ValueError:
            print("ERROR: length should be an integer! \nDefalut length 16 chosen \n")
            length = 16
        chars = input(
            "Enter all the allowed character types (l)etters, (s)pecial characters, (d)igits \n \n (can be combined) \n > "
        ).lower()
        if "l" in chars:
            charset = charset + string.ascii_letters
        if "s" in chars:
            charset = charset + string.punctuation
        if "d" in chars:
            charset = charset + string.digits
        if charset != "":
            return service, length, charset
        else:
            print("Invalid options!")


def write_service(user, service, password):
    path = get_path_to_service(user, service)
    with open(path, "wb") as file:
        encrypted_password = encrypt(password)
        file.write(encrypted_password + b"\n")
    os.chmod(path, 0o600)


def encrypt(message):
    cipher = Fernet(base64.urlsafe_b64encode(m_key))
    return cipher.encrypt(message.encode())


def show_password(user):
    service = get_service()
    path = get_path_to_service(user, service)
    try:
        with open(path, "rb") as file:
            lines = file.read().splitlines()
            encrypted_password = lines[0]
        cipher = Fernet(base64.urlsafe_b64encode(m_key))
        decrypted_password = cipher.decrypt(encrypted_password).decode()
        copy_to_clipboard(decrypted_password, "password")
    except IOError or IndexError:
        print("service " + service + " not found")


def show_username(user):
    service = get_service()
    path = get_path_to_service(user, service)
    try:
        with open(path, "rb") as file:
            try:
                lines = file.read().splitlines()
                encrypted_username = lines[1]
            except IndexError:
                print(f'username for service "{service}" not found')
                return
        cipher = Fernet(base64.urlsafe_b64encode(m_key))
        decrypted_username = cipher.decrypt(encrypted_username).decode()
        copy_to_clipboard(decrypted_username, "username")
    except IOError:
        print(f'username for service "{service}" not found')


def generate_encryption_key(salt, key):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend,
    )
    return kdf.derive(key)


def copy_to_clipboard(password, text):
    pyperclip.copy(password)
    print(
        text
        + " copied to clipboard. \nPress ENTER to continue and empty clipboard \n > "
    )
    input()
    pyperclip.copy("")


if __name__ == "__main__":
    parser = argparse.ArgumentParser("pspm (pretty secure password manager)")
    parser.add_argument(
        "--init", "-i", metavar="user", help="initialize new pspm vault for <user>"
    )
    parser.add_argument("--login", "-l", metavar="user", help="login as <user>")

    args = parser.parse_args()
    m_key = ""

    if args.init:
        init(args.init)
    elif args.login:
        login(args.login)
    else:
        parser.print_help()

# TODO implement edit function
# TODO implement cli-options
# TODO exception handling
# TODO documentation
# TODO split methods into smaller components
