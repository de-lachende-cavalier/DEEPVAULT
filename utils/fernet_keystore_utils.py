from cryptography.fernet import Fernet, MultiFernet
from utils.misc_utils import get_random_line
from utils import crypto_utils
import os

"""
This module is concerned with generating the Fernet keystore and the encryption/decryption of data using the keystore.
The functions below are basically self-explanatory.
"""

KEYSTORE = "/Users/d0larhyde/DEEPVAULT/keystore.enc"
try:
    SYMKEY_FILE = os.environ["KEY_FILE"]
except KeyError:
    print("The symmetric key file has not been defined in utils/fernet_keystore.py!")
    pass

def generate_keystore(key_num):
    with open(KEYSTORE, 'w+') as k:
        for _ in range(key_num):
            k.write(Fernet.generate_key().decode() + '\n')


def encrypt_with_random_key(message):
    crypto_utils.decrypt_keystore(KEYSTORE, SYMKEY_FILE)

    f = Fernet(get_random_line(KEYSTORE).encode())

    crypto_utils.encrypt_keystore(KEYSTORE, SYMKEY_FILE)

    return f.encrypt(message.encode())


def decrypt_with_random_key(encrypted_message):
    crypto_utils.decrypt_keystore(KEYSTORE, SYMKEY_FILE)

    with open(KEYSTORE, 'r') as k:
        keys = k.read().splitlines()
    crypto_utils.encrypt_keystore(KEYSTORE, SYMKEY_FILE)

    mf = MultiFernet([Fernet(key) for key in keys])

    return mf.decrypt(encrypted_message.encode()).decode()

