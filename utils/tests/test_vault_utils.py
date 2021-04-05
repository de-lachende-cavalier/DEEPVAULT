from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from utils.misc_utils import get_random_line
import unittest
import secrets
import base64

# ALERT:importing vault_utils crashes the tests (because Django decided to be a nice little chap, or maybe it's PyCharm)
# thus I copy-pasted the various functions directly here
# Importing anything django-related seems to have the same effect, thus I'll also adapt the code making sure to not
# change any functionality


def create_vaults(username):

    vaults = []

    for _ in range(10):
        vault = {'owner': username,
                 'app': get_random_line('/Users/d0larhyde/DEEPVAULT/utils/dictionary/b'),
                 'app_username': get_random_line('/Users/d0larhyde/DEEPVAULT/utils/dictionary/c'),
                 'app_password': get_random_line('/Users/d0larhyde/DEEPVAULT/utils/dictionary/d')}

        vaults.append(vault)

    return vaults


def build_cipher(token):
    kdf = Scrypt(
        salt=b'',
        length=32,
        n=2 ** 16,
        r=8,
        p=1,
        backend=default_backend()
    )

    key = kdf.derive(token.encode())
    cipher = AESGCM(key)

    return cipher, key


def encrypt_vault(cipher, nonce, vaults):
    for vault in vaults:
        vault['app'] = cipher.encrypt(nonce, vault['app'].encode(), b'').hex()
        vault['app_username'] = cipher.encrypt(nonce, vault['app_username'].encode(), b'').hex()
        vault['app_password'] = cipher.encrypt(nonce, vault['app_password'].encode(), b'').hex()

    return vaults


def decrypt_vault(cipher, nonce, vaults):
    for vault in vaults:
        vault['app'] = cipher.decrypt(nonce, bytes.fromhex(vault['app']), b'').decode()
        vault['app_username'] = cipher.decrypt(nonce, bytes.fromhex(vault['app_username']), b'').decode()
        vault['app_password'] = cipher.decrypt(nonce, bytes.fromhex(vault['app_password']), b'').decode()

    # cleanup
    nonce = b''

    return vaults, nonce

# END ALERT


def all_unique(x):
    seen = list()
    return not any(s in seen or seen.append(s) for s in x)


class VaultUtilsTest(unittest.TestCase):

    def test_vault_creation(self):
        test_vaults = create_vaults('test')

        self.assertEqual((len(test_vaults)), 10)

        apps = []
        app_usernames = []
        app_passwords = []
        for tv in test_vaults:
            self.assertEqual('test', tv['owner'])

            apps.append(tv['app'])
            app_usernames.append([tv['app_username']])
            app_passwords.append([tv['app_password']])

        self.assertTrue(all_unique(apps))
        self.assertTrue(all_unique(app_usernames))
        self.assertTrue(all_unique(app_passwords))

    def test_basic_cipher_func(self):
        test_cipher, test_key = build_cipher('test_token')

        self.assertEqual(len(test_key), 32)
        self.assertIsInstance(test_key, bytes)
        self.assertIsInstance(test_cipher, AESGCM)

    # noinspection DuplicatedCode
    def test_encryption_decryption(self):
        enc_token = 'test_token'
        username = 'test_user'
        enc_nonce = secrets.token_bytes(12)

        self.assertIsInstance(enc_nonce, bytes)
        self.assertEqual(len(enc_nonce), 12)

        vaults = create_vaults(username)
        clear_apps = []
        clear_app_usernames = []
        clear_app_passwords = []
        for v in vaults:
            clear_apps.append(v['app'])
            clear_app_usernames.append(v['app_username'])
            clear_app_passwords.append(v['app_password'])

        enc_cipher, key = build_cipher(enc_token)
        enc_vaults = encrypt_vault(enc_cipher, enc_nonce, vaults)

        enc_apps = []
        enc_app_usernames = []
        enc_app_passwords = []
        for ev in enc_vaults:
            enc_apps.append(ev['app'])
            enc_app_usernames.append(ev['app_username'])
            enc_app_passwords.append(ev['app_password'])

        self.assertTrue(all_unique(enc_apps))
        self.assertTrue(all_unique(enc_app_usernames))
        self.assertTrue(all_unique(enc_app_passwords))

        self.assertEqual(len(clear_apps), len(enc_apps))
        self.assertEqual(len(clear_app_usernames), len(enc_app_usernames))
        self.assertEqual(len(clear_app_passwords), len(enc_app_passwords))

        self.assertNotEqual(clear_apps, enc_apps)
        self.assertNotEqual(clear_app_usernames, enc_app_usernames)
        self.assertNotEqual(clear_app_passwords, enc_app_passwords)

        dec_token = enc_token

        self.assertEqual(dec_token, enc_token)

        dec_cipher, dec_key = build_cipher(dec_token)
        dec_vaults, enc_nonce = decrypt_vault(dec_cipher, enc_nonce, enc_vaults)

        self.assertEqual(len(enc_nonce), 0)

        dec_apps = []
        dec_app_usernames = []
        dec_app_passwords = []
        for dv in dec_vaults:
            dec_apps.append(dv['app'])
            dec_app_usernames.append(dv['app_username'])
            dec_app_passwords.append(dv['app_password'])

        self.assertTrue(all_unique(dec_apps))
        self.assertTrue(all_unique(dec_app_usernames))
        self.assertTrue(all_unique(dec_app_passwords))

        self.assertEqual(len(dec_apps), len(enc_apps))
        self.assertEqual(len(dec_app_usernames), len(enc_app_usernames))
        self.assertEqual(len(dec_app_passwords), len(enc_app_passwords))

        self.assertEqual(dec_apps, clear_apps)
        self.assertEqual(dec_app_usernames, clear_app_usernames)
        self.assertEqual(dec_app_passwords, clear_app_passwords)







