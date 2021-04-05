from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from binascii import unhexlify
import secrets
import os


def get_cipher(keyfile):
    """
    Constructs the correct AES cipher to be later user for encryption/decryption
    :return: the built AES cipher
    """
    with open(keyfile, 'r') as kf:
        data = kf.read().strip()
    data = data.split(':')

    nonce = bytes.fromhex(data[0])
    key = bytes.fromhex(data[1])

    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())

    return cipher


def encrypt_keystore(keystore_file, symkey_file):
    cipher = get_cipher(symkey_file)
    encryptor = cipher.encryptor()

    with open(keystore_file, 'r+') as k:
        clear_data = k.read()
        k.seek(0)

        cipher_data = encryptor.update(clear_data.encode()) + encryptor.finalize()
        k.write(cipher_data.hex())
        k.truncate()


def decrypt_keystore(keystore_file, symkey_file):
    cipher = get_cipher(symkey_file)
    decryptor = cipher.decryptor()

    with open(keystore_file, 'r') as k:
        cipher_data = bytes.fromhex(k.read())

    temp_list = (decryptor.update(cipher_data) + decryptor.finalize()).decode().split('\n')
    key_list = list(filter(None,  temp_list))

    with open(keystore_file, 'w') as k:
        for key in key_list:
            k.write(key + '\n')





