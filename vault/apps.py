from django.apps import AppConfig


class VaultConfig(AppConfig):
    name = 'vault'

    def ready(self):
        import vault.receivers

