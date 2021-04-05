from utils.fernet_keystore_utils import generate_keystore, KEYSTORE
from cryptography.hazmat.primitives.ciphers import Cipher
from utils import crypto_utils
import unittest
import string


class CryptoUtilsTest(unittest.TestCase):

    keystore = generate_keystore(20)
    keystore_file = KEYSTORE
    symkey_file = "/tmp/4898cd929fd198abb10b06d5d35a117a4af46f3739396e2256af706fd474fa10d7ee81292d514e0da74000d0e03e16ff7bebe8e7946f35de7935c7143b8fef41af4445f87036852f6b08be1312ac193f"
    with open(KEYSTORE, 'r') as k:
        original_key_list = k.read().splitlines()

    def test_cipher_sanity(self):
        cipher = crypto_utils.get_cipher(self.symkey_file)

        self.assertTrue(isinstance(cipher, Cipher))

    def test_keystore_encryption_decryption(self):

        crypto_utils.encrypt_keystore(self.keystore_file, self.symkey_file)

        with open(self.keystore_file, 'r') as k:
            data = k.read()
            self.assertTrue(all(char in string.hexdigits for char in data))

        crypto_utils.decrypt_keystore(self.keystore_file, self.symkey_file)
        with open(KEYSTORE, 'r') as k:
            decrypted_data = k.read().splitlines()

        self.assertTrue(self.original_key_list.sort() == decrypted_data.sort())






