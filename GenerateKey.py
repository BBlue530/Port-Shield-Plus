from cryptography.fernet import Fernet

def generate_encryption_key():
    key = Fernet.generate_key()
    print(f"Generated Encryption Key: {key.decode()}")
    with open("encryption_key.key", "wb") as key_file:
        key_file.write(key)
    return key

generate_encryption_key()