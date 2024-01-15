import argparse
import os
from colorama import init, Fore
import json

from secret import Secret
from validator import Validator

"""
This script reads a Gitleaks json output file and validates secrets found in it.
@arguments:
- 'file': The path to the Gitleaks json output file.
- '--project': The project folder path (default is current directory).
"""

init(autoreset=True)
project_name_ascii = r"""
 ██      ██                 ██         
░██     ░██          █████ ░░          
░██     ░██ ██   ██ ██░░░██ ██ ███████ 
░██████████░██  ░██░██  ░██░██░░██░░░██
░██░░░░░░██░██  ░██░░██████░██ ░██  ░██
░██     ░██░██  ░██ ░░░░░██░██ ░██  ░██
░██     ░██░░██████  █████ ░██ ███  ░██
░░      ░░  ░░░░░░  ░░░░░  ░░ ░░░   ░░ 
"""
satty_text = "                                                                        by Satty.com.br"

if __name__ == "__main__":

    print(f"{Fore.GREEN}{project_name_ascii}")
    print(f"{Fore.BLUE}{satty_text}")
    print(f"{Fore.YELLOW}Starting...")

    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="Gitleaks json output file")
    parser.add_argument('--project', type=str, default="./", help='Project Folder.')
    args = parser.parse_args()
    if not os.path.isfile(args.file):
        print(f"{Fore.RED}O arquivo '{args.file}' não existe!")
        exit(-1)
    with open(args.file, "r") as file:
        data = json.loads(file.read())
        secrets = [Secret(**secret) for secret in data]
        for secret in secrets:
           if Validator(secret, args.project).test_is_valid():
                print(f"{Fore.GREEN}Secret '{secret.secret}' is valid!")
                secret.valid = True
        json.dumps(secrets,file="output.json", indent=4)