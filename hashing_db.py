import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet,InvalidToken

def getKey()->bytes:
    password_provided = "password"  # This is input in the form of a string
    password = password_provided.encode()  # Convert to type bytes
    salt = b'salt_'  # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once
    return key

def encryptToStore(key:bytes,plaintext:str)->str:
    result = ""
    key = "dhruv"
    shift = sum(ord(char) for char in key) % 26  # Calculate a shift value based on the key
    for char in plaintext:
        if char.isalpha():
            ascii_value = ord(char)
            shifted_ascii_value = ascii_value + shift
            if char.islower():
                if shifted_ascii_value > ord('z'):
                    shifted_ascii_value -= 26
            elif char.isupper():
                if shifted_ascii_value > ord('Z'):
                    shifted_ascii_value -= 26
            result += chr(shifted_ascii_value)
        else:
            result += char  # Preserve numbers and other non-alphabetic characters

    return result

def decryptFromStore(key:bytes,enctext:str)->str:
    result = ""
    key = "dhruv"
    shift = sum(ord(char) for char in key) % 26  # Calculate the same shift value used during encryption
    for char in enctext:
        if char.isalpha():
            ascii_value = ord(char)
            shifted_ascii_value = ascii_value - shift
            if char.islower():
                if shifted_ascii_value < ord('a'):
                    shifted_ascii_value += 26
            elif char.isupper():
                if shifted_ascii_value < ord('A'):
                    shifted_ascii_value += 26
            result += chr(shifted_ascii_value)
        else:
            result += char  # Preserve numbers and other non-alphabetic characters

    return result


# def main():
#     plaintext = "My name is Dhruv"
#     key = "123"
#     enctxt = encryptToStore(key=key,plaintext=plaintext)
#     print(enctxt)
#     print(decryptFromStore(key="456",enctext=enctxt))
#     print("END")

# if __name__ == "__main__":
#     main()