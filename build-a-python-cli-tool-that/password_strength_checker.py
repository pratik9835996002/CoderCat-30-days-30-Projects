import hashlib
import secrets
import string

import requests
from colorama import Fore, Style, init


COMMON_PASSWORDS = {
    "123456",
    "123456789",
    "12345678",
    "password",
    "password123",
    "admin",
    "admin123",
    "qwerty",
    "qwerty123",
    "letmein",
    "welcome",
    "welcome123",
    "iloveyou",
    "monkey",
    "dragon",
    "football",
    "baseball",
    "abc123",
    "111111",
    "123123",
}

SPECIAL_CHARACTERS = "!@#$%^&*"


def analyze_password(password):
    checks = {
        "uppercase": any(char.isupper() for char in password),
        "lowercase": any(char.islower() for char in password),
        "number": any(char.isdigit() for char in password),
        "special": any(char in SPECIAL_CHARACTERS for char in password),
        "not_common": password.lower() not in COMMON_PASSWORDS,
    }

    missing = []
    if len(password) < 8:
        missing.append("Make it longer")
    if not checks["uppercase"]:
        missing.append("Add uppercase letters")
    if not checks["lowercase"]:
        missing.append("Add lowercase letters")
    if not checks["number"]:
        missing.append("Add numbers")
    if not checks["special"]:
        missing.append("Add special characters")
    if not checks["not_common"]:
        missing.append("Avoid common passwords")

    if len(password) < 8:
        return "Weak", 0, missing

    score = sum(checks.values())

    if score <= 2:
        rating = "Weak"
    elif score == 3:
        rating = "Medium"
    elif score == 4:
        rating = "Strong"
    else:
        rating = "Very Strong"

    return rating, score, missing


def color_rating(rating):
    colors = {
        "Weak": Fore.RED,
        "Medium": Fore.YELLOW,
        "Strong": Fore.GREEN,
        "Very Strong": Style.BRIGHT + Fore.GREEN,
    }
    return f"{colors[rating]}{rating}{Style.RESET_ALL}"


def generate_strong_password(length=16):
    alphabet = string.ascii_letters + string.digits + SPECIAL_CHARACTERS

    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        rating, score, _ = analyze_password(password)
        if rating == "Very Strong" and score == 5:
            return password


def check_breach(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        response = requests.get(url)
    except requests.RequestException:
        return None

    if response.status_code != 200:
        return None

    hashes = response.text.splitlines()
    for line in hashes:
        h, count = line.split(":")
        if h == suffix:
            return int(count)
    return 0


def print_result(password):
    rating, score, missing = analyze_password(password)
    breach_count = check_breach(password)

    print(f"\nStrength: {color_rating(rating)}")
    print(f"Score: {score}/5")

    if missing:
        print("Missing:")
        for item in missing:
            print(f"- {item}")
    else:
        print("Missing: Nothing")

    if breach_count is None:
        print(f"{Fore.YELLOW}Pwned status: Unknown. Could not reach the API.{Style.RESET_ALL}")
    elif breach_count > 0:
        print(f"{Fore.RED}Pwned status: PWNED. This password was found in {breach_count} breaches.{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}Pwned status: Not pwned. This password was not found in known breaches.{Style.RESET_ALL}")

    print(f"Suggested strong password: {generate_strong_password()}\n")


def main():
    init(autoreset=True)

    print("Password Strength Checker")
    print("Type 'q' or 'quit' to exit.\n")

    while True:
        password = input("Enter a password to check: ")
        if password.lower() in {"q", "quit"}:
            print("Goodbye!")
            break

        print_result(password)


if __name__ == "__main__":
    main()
