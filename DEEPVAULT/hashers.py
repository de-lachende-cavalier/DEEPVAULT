from django.contrib.auth.hashers import Argon2PasswordHasher


class HardenedArgon2Hasher(Argon2PasswordHasher):
    """
    A class to harden the default argon2 hasher for storing hashed passwords on the database.
    """
    time_cost = Argon2PasswordHasher.time_cost * 17
    memory_cost = Argon2PasswordHasher.memory_cost * 220
    parallelism = Argon2PasswordHasher.parallelism * 2
