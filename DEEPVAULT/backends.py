from utils.fernet_keystore_utils import decrypt_with_random_key
from utils.vault_utils import build_cipher, decrypt_vault
from django.contrib.auth.backends import ModelBackend
from cryptography.fernet import InvalidToken
from django.contrib.auth.models import User
from secrets import compare_digest


class FernetBackend(ModelBackend):
    """
    Custom backend for authentication through Fernet tokens.
    It's mostly a copy-paste of ModelBackend from Django up to the first login part.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None:
            username = kwargs.get(User.USERNAME_FIELD)
        if username is None or password is None:
            return None

        try:
            user = User._default_manager.get_by_natural_key(username)
        except User.DoesNotExist:
            # Hash once to reduce time to authenticate between an existing and a non existing user
            User().set_password(password)

        else:
            # First login
            if user.last_login is None:
                if self.user_can_authenticate(user) and user.check_password(password):
                    return user
            else:
                try:
                    # compare_digest to avoid timing attacks (just like above)
                    if self.user_can_authenticate(user) and compare_digest(user.password + str(user.last_login),
                                                                           decrypt_with_random_key(password)):
                        cipher = build_cipher(password, b'')
                        decrypt_vault(cipher, user, b'')

                        return user
                except InvalidToken:
                    return None
