import argparse
import getpass


def get_password():
    return getpass.getpass("Enter master password: ")


def show_password(service):
    if get_password() == "123":
        print("works")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        "pspm (pretty secure password manager) is a simple cli-based password manager")
    parser.add_argument("--init", metavar="user",
                        help="initialize pspm vault for user")
    parser.add_argument("-s", "--show", metavar="service",
                        help="show password for a service")
    parser.add_argument("-g", "--generate",
                        metavar="service", help="generate password for a service")

    args = parser.parse_args()

    if args.show:
        show_password(args.show)
