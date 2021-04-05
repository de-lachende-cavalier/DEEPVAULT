from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from django.contrib.auth.models import User
from vault.models import Nonce, Vault


"""
Utils that handle the encryption/decryption of the various vaults.
Once more, the functions are self-explanatory.
"""


def build_cipher(token, salt):

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**16,
        r=8,
        p=1,
        backend=default_backend()
    )

    key = kdf.derive(token.encode())
    cipher = AESGCM(key)

    return cipher


def encrypt_vault(cipher, username, nonce, aad):
    user = User.objects.get(username=username)
    vaults = Vault.objects.filter(owner=user)

    for vault in vaults:
        if user.has_perm('vault.change_vault', vault):
            vault.app = cipher.encrypt(nonce, vault.app.encode(), aad).hex()
            vault.app_username = cipher.encrypt(nonce, vault.app_username.encode(), aad).hex()
            vault.app_password = cipher.encrypt(nonce, vault.app_password.encode(), aad).hex()

        vault.save()


def decrypt_vault(cipher, user, aad):
    old_nonce = Nonce.objects.get(user=user)
    vaults = Vault.objects.filter(owner=user)

    for vault in vaults:
        if user.has_perm('vault.view_vault', vault):
            vault.app = cipher.decrypt(old_nonce.nonce, bytes.fromhex(vault.app), aad).decode()
            vault.app_username = cipher.decrypt(old_nonce.nonce, bytes.fromhex(vault.app_username), aad).decode()
            vault.app_password = cipher.decrypt(old_nonce.nonce, bytes.fromhex(vault.app_password), aad).decode()

        vault.save()

    # cleanup
    old_nonce.nonce = b''
    old_nonce.save()


