from django.db.models.signals import post_save
from django.contrib.auth.models import User
from django.dispatch import receiver
from vault.models import Nonce


@receiver(post_save, sender=User)
def create_user_vault(sender, instance, created, **kwargs):
    """
    Receives the post_save signal and proceeds to create a nonce associated with the user just created

    :param sender: the model that sent the signal (in our case User)
    :param instance: the User instance
    :param created: boolean, checks that the User was created or not
    :param kwargs: other args
    """
    if created:
        Nonce.objects.create(user=instance)
