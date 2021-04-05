import secrets

"""
Miscellaneous utils used in other files, put here to avoid WET code.
"""


def get_random_line(file):
    with open(file, 'r') as f:
        lines = f.read().splitlines()

    return secrets.choice(lines)

def get_user_token_initials(user_token):
    """
    Splits up the token and isolates the initial letters.

    :param user_token: the tokenized username
    :return: the initials of the tokenized username, aka the username input at registration
    """
    initials = ''
    words = user_token.split('-')
    for _ in range(len(words)):
        initials += words[_][0]

    return initials
