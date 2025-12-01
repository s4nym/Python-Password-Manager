import os
import json
import base64
import random
import string
from getpass import getpass
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet, InvalidToken

VAULT = "vault.json"
SALT_SIZE = 16

def kdf(password, salt):
    k = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return base64.urlsafe_b64encode(k.derive(password.encode()))

def encrypt_data(data, password):
    salt = os.urandom(SALT_SIZE)
    key = kdf(password, salt)
    f = Fernet(key)
    blob = f.encrypt(json.dumps(data).encode())
    return {"salt": base64.b64encode(salt).decode(), "data": base64.b64encode(blob).decode()}

def decrypt_data(blob, password):
    salt = base64.b64decode(blob["salt"])
    cipher = base64.b64decode(blob["data"])
    key = kdf(password, salt)
    f = Fernet(key)
    out = f.decrypt(cipher)
    return json.loads(out.decode())

def load_vault(password):
    if not os.path.exists(VAULT):
        return {}
    try:
        with open(VAULT, "r") as f:
            blob = json.load(f)
        if "salt" not in blob or "data" not in blob:
            raise ValueError
        return decrypt_data(blob, password)
    except (InvalidToken, ValueError, json.JSONDecodeError):
        raise InvalidToken

def save_vault(vault, password):
    blob = encrypt_data(vault, password)
    temp = VAULT + ".tmp"
    with open(temp, "w") as f:
        json.dump(blob, f)
    os.replace(temp, VAULT)

def gen_password(length):
    length = max(6, min(length, 128))
    chars = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choice(chars) for _ in range(length))

def ask_service():
    s = input("Service name: ").strip().lower()
    return s if s else None

def main():
    print("Password Manager")
    pw = getpass("Master password: ")

    try:
        vault = load_vault(pw)
    except InvalidToken:
        print("Wrong master password or vault corrupted.")
        return

    while True:
        print("\n1) Add")
        print("2) View")
        print("3) List")
        print("4) Delete")
        print("5) Generate Password")
        print("6) Exit")

        choice = input("Choose: ").strip()

        if choice == "1":
            s = ask_service()
            if not s:
                print("Invalid name.")
                continue
            u = input("Username: ").strip()
            if not u:
                print("Invalid username.")
                continue
            p = getpass("Password (blank = type visible): ")
            if not p:
                p = input("Password: ").strip()
                if not p:
                    print("Invalid password.")
                    continue
            vault[s] = {"username": u, "password": p}
            save_vault(vault, pw)
            print("Saved.")

        elif choice == "2":
            s = ask_service()
            if not s or s not in vault:
                print("Not found.")
                continue
            print("Username:", vault[s]["username"])
            print("Password:", vault[s]["password"])

        elif choice == "3":
            if not vault:
                print("No entries.")
            else:
                for x in sorted(vault.keys()):
                    print("-", x)

        elif choice == "4":
            s = ask_service()
            if not s or s not in vault:
                print("Not found.")
                continue
            del vault[s]
            save_vault(vault, pw)
            print("Deleted.")

        elif choice == "5":
            raw = input("Length (default 16): ").strip()
            length = 16
            if raw.isdigit():
                length = int(raw)
            print(gen_password(length))

        elif choice == "6":
            print("Goodbye.")
            break

        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
