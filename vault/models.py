from django.contrib.auth.models import User
from rules.contrib.models import RulesModel
from django.db import models
import rules


@rules.predicate
def is_owner(user, vault):
    """
    Rule used to check vault ownership of a certain user and give permissions based on that.

    :param user: the user instance to check
    :param vault: the vault instance to check against
    :return: True if the user is the owner, False otherwise
    """
    return vault.owner == user


class Vault(RulesModel):
    owner = models.ForeignKey(User, on_delete=models.CASCADE, default=None)
    app = models.CharField(max_length=200, default='')
    app_username = models.CharField(max_length=200, default='')
    app_password = models.CharField(max_length=200, default='')

    class Meta:
        """
        Give all permissions ONLY to the owner of the vault, except for the add permission, because users don't need it.
        (More explicitly, the add permission is never used/checked for)
        """
        rules_permissions = {
            'view': is_owner,
            'change': is_owner,
            'delete': is_owner
        }


class Nonce(RulesModel):
    user = models.OneToOneField(User, on_delete=models.CASCADE, default=None)
    nonce = models.BinaryField(max_length=30, default=b'')

    class Meta:
        """
        No user has any permission regarding the nonce. It's entirely managed by the server.
        """
        rules_permissions = {
            'view': False,
            'add': False,
            'change': False,
            'delete': False
        }
