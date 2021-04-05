from cryptography.fernet import Fernet
from utils import fernet_keystore_utils
import colored_traceback.always
import unittest
import os

STORE_SIZE = 20
fernet_keystore_utils.SYMKEY_FILE = '/tmp/4898cd929fd198abb10b06d5d35a117a4af46f3739396e2256af706fd474fa10d7ee81292d514e0da74000d0e03e16ff7bebe8e7946f35de7935c7143b8fef41af4445f87036852f6b08be1312ac193f'


class FernetKeystoreTest(unittest.TestCase):

    def test_keystore_creation(self):
        os.system(f'shred -fuzn 90 {fernet_keystore_utils.KEYSTORE}')
        fernet_keystore_utils.generate_keystore(STORE_SIZE)

        self.assertTrue(os.path.exists(fernet_keystore_utils.KEYSTORE))

    def test_encryption_decryption(self):
        '''
        This test only works if I remove the encryption/decryption done by crypto_utils from the fernet_keystore_utils (which makes sense).
        '''
        message = 'testing'
        encrypted_messages = []

        with open(fernet_keystore_utils.KEYSTORE, 'r') as k:
            for line in k:
                f = Fernet(line.rstrip().encode())
                encrypted_messages.append(f.encrypt(message.encode()))

        self.assertTrue(len(encrypted_messages) == STORE_SIZE)
        self.assertTrue(len(encrypted_messages) == len(list(set(encrypted_messages))))

        for mes in encrypted_messages:
            self.assertEqual(message, fernet_keystore_utils.decrypt_with_random_key(mes.decode()))
