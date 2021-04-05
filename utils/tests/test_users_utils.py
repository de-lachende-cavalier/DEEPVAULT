from utils.misc_utils import get_user_token_initials
from utils import users_utils
import unittest


class UserUtilsTest(unittest.TestCase):

    def test_uniqueness(self):
        starting_user = 'test'
        sample_size = 20000
        username_pool = []

        for i in range(sample_size):
            username_pool.append(users_utils.create_user_token(starting_user))

        self.assertTrue(len(username_pool) == sample_size)
        self.assertTrue(len(username_pool) == len(list(set(username_pool))))

    def test_empty_input(self):
        self.assertFalse(users_utils.create_user_token(""))

    def test_nonalpha_input(self):
        starting_user = 'test12__@'
        tokenized_user = users_utils.create_user_token(starting_user)

        self.assertEqual(get_user_token_initials(tokenized_user), starting_user)



