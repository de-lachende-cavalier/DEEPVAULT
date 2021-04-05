from utils.misc_utils import get_random_line
import string

"""
Utils useful for the users app.
Again, the functions are pretty self-explanatory.
"""


def create_user_token(username):
    dict_path = '/Users/d0larhyde/DEEPVAULT/utils/dictionary/'
    tokenized_username = ""

    for char in username:
        if char in string.ascii_letters:
            if char in string.ascii_lowercase:
                if not tokenized_username:
                    tokenized_username += get_random_line(dict_path + char)
                else:
                    tokenized_username += '-' + get_random_line(dict_path + char)
            else:
                if not tokenized_username:
                    tokenized_username += get_random_line(dict_path + char).title()
                else:
                    tokenized_username += '-' + get_random_line(dict_path + char).title()

        else:
            if not tokenized_username:
                tokenized_username += char
            else:
                tokenized_username += '-' + char

    return tokenized_username
