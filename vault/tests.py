from utils.vault_utils import decrypt_vault, encrypt_vault, build_cipher
from utils.fernet_keystore_utils import encrypt_with_random_key
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.models import User
from django.test import TestCase
from .models import Vault, Nonce
from secrets import token_bytes

def encrypt_vault_after_logout_testing(user, new_token):
    """
    A testing version of the function found in receivers.py. It's basically copy pasted, except for the fact that it doesn't take sender and request as
    args.
    """
    new_nonce = Nonce.objects.get(user=user)
    new_nonce.nonce = token_bytes(16)
    new_nonce.save()

    cipher = build_cipher(new_token, b'')
    encrypt_vault(cipher, user.username, new_nonce.nonce, b'')


class VaultTests(TestCase):

    def test_vault_creation(self):
        """
        Checks basic properties that need to be satisfied for correct vault creation and functioning.
        """
        vault_user = User.objects.create_user(username='vault_user', password='myvault')

        with self.assertRaises(ObjectDoesNotExist):
            Vault.objects.get(owner=vault_user)

        vault = Vault.objects.create(owner=vault_user)

        self.assertEqual(vault_user, vault.owner)

    def test_vault_permissions(self):
        """
        Checks the permission assigned to the various users regarding vaults.
        """
        users = [User.objects.create_user(username=token_bytes(16).decode('iso-8859-1'),
                                          password=token_bytes(16).decode('iso-8859-1')) for _ in range(7)]

        self.assertEqual(len(users), len(set(users)))

        for user in users:
            for _ in range(len(users)):
                # create n vaults for each user (with n defined above)
                Vault.objects.create(owner=user)

        # a list of querysets
        vaults = [Vault.objects.filter(owner=user) for user in users]

        for qs_vaults in vaults:
            for vault in qs_vaults:
                for user in users:
                    if vault.owner == user:
                        self.assertTrue(user.has_perm('vault.view_vault', vault))
                        self.assertFalse(user.has_perm('vault.add_vault', vault))
                        self.assertTrue(user.has_perm('vault.change_vault', vault))
                        self.assertTrue(user.has_perm('vault.delete_vault', vault))
                    else:
                        self.assertFalse(user.has_perm('vault.view_vault', vault))
                        self.assertFalse(user.has_perm('vault.add_vault', vault))
                        self.assertFalse(user.has_perm('vault.change_vault', vault))
                        self.assertFalse(user.has_perm('vault.delete_vault', vault))

    # noinspection DuplicateCode
    def test_vault_encryption_decryption(self):
        """
        Checks the encryption/decryption procedure as applied to actual vaults in the database.
        """
        user = User.objects.create_user(username='enc_dec', password='decryptthis')

        self.assertEqual(Nonce.objects.filter(user=user).count(), 1)

        nonce = Nonce.objects.get(user=user)
        self.assertEqual(nonce.nonce, b'')

        # first login and adding vaults
        new_token = encrypt_with_random_key('enc_token').decode()
        self.assertIsInstance(new_token, str)

        for _ in range(4):
            Vault.objects.create(
                owner=user,
                app=token_bytes(16).decode('iso-8859-1'),
                app_username=token_bytes(16).decode('iso-8859-1'),
                app_password=token_bytes(16).decode('iso-8859-1'),
            )

        self.assertEqual(Vault.objects.filter(owner=user).count(), 4)

        vaults = Vault.objects.filter(owner=user)
        clear_apps = [v.app for v in vaults]
        clear_app_usernames = [v.app_username for v in vaults]
        clear_app_passwords = [v.app_password for v in vaults]

        clear_apps.sort()
        clear_app_usernames.sort()
        clear_app_passwords.sort()

        self.assertEqual(len(clear_apps), 4)
        self.assertEqual(len(clear_app_usernames), 4)
        self.assertEqual(len(clear_app_passwords), 4)

        # logout
        encrypt_vault_after_logout_testing(user=user, new_token=new_token)

        nonce = Nonce.objects.get(user=user)
        self.assertNotEqual(nonce.nonce, b'')
        self.assertIsInstance(nonce.nonce, bytes)

        enc_vaults = Vault.objects.filter(owner=user)
        enc_apps = [ev.app for ev in enc_vaults]
        enc_app_usernames = [ev.app_username for ev in enc_vaults]
        enc_app_passwords = [ev.app_password for ev in enc_vaults]

        enc_apps.sort()
        enc_app_usernames.sort()
        enc_app_passwords.sort()

        self.assertNotEqual(enc_apps, clear_apps)
        self.assertEqual(len(enc_apps), len(enc_apps))

        self.assertNotEqual(enc_app_usernames, clear_app_usernames)
        self.assertEqual(len(enc_app_usernames), len(enc_app_usernames))

        self.assertNotEqual(enc_app_passwords, clear_app_passwords)
        self.assertEqual(len(enc_app_passwords), len(clear_app_passwords))

        # login yet again
        old_token = new_token

        cipher = build_cipher(old_token, b'')
        decrypt_vault(cipher, user, b'')

        nonce = Nonce.objects.get(user=user)
        self.assertEqual(nonce.nonce, b'')

        dec_vaults = Vault.objects.filter(owner=user)
        dec_apps = [dv.app for dv in dec_vaults]
        dec_app_usernames = [dv.app_username for dv in dec_vaults]
        dec_app_passwords = [dv.app_password for dv in dec_vaults]

        dec_apps.sort()
        dec_app_usernames.sort()
        dec_app_passwords.sort()

        self.assertEqual(dec_apps, clear_apps)
        self.assertEqual(dec_app_usernames, clear_app_usernames)
        self.assertEqual(dec_app_passwords, clear_app_passwords)





