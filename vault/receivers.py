from django.contrib.auth.signals import user_logged_out
from utils.vault_utils import build_cipher, encrypt_vault
from django.contrib.auth.models import User
from django.dispatch import receiver
from .models import Nonce
from secrets import token_bytes


@receiver(user_logged_out, sender=User)
def encrypt_vault_after_logout(user, sender, request, **kwargs):
    """
    Takes care of encrypting the vault as soon as the user logs out.
    It also clears the session (redundant, seeings as Django already does it).

    :param user: the username of the logged out user
    :param sender: the User model
    :param request: the current request object
    :param kwargs: extra args
    """
    if 'temp_token' in request.session:
        new_token = request.session['temp_token']
        del request.session['temp_token']
        request.session.flush()

        new_nonce = Nonce.objects.get(user__username__exact=user)
        new_nonce.nonce = token_bytes(16)
        new_nonce.save()

        cipher = build_cipher(new_token, b'')
        encrypt_vault(cipher, user, new_nonce.nonce, b'')

