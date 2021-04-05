from django.core.exceptions import ObjectDoesNotExist
from utils.misc_utils import get_user_token_initials
from utils.users_utils import create_user_token
from django.contrib.auth.models import User
from secrets import token_bytes, choice
from vault.models import Vault, Nonce
from django.test import TestCase
from passlib.hash import argon2
from django.test import Client
from datetime import datetime
import string


class UserTests(TestCase):

    def set_up(self):
        self.client = Client()

    def test_user_registration(self):
        """
        Tests the registration procedure.
        First we test invalid cases (when the passwords don't match), then we check that the User is created and the
        username correctly tokenized if the registration is successful.
        """
        alphabet = string.ascii_letters + string.digits + '@.+-_'
        username = ''.join(choice(alphabet) for _ in range(4))
        password1 = 'notagain'
        correct_password2 = password1
        data = {'username': username,
                'password1': password1,
                'password2': ''}
        endpoint = '/registration/'

        for _ in range(10):
            data['password2'] = token_bytes(16).decode('iso-8859-1')
            invalid_req = self.client.post(endpoint, data, follow=True)

            self.assertEqual(len(invalid_req.redirect_chain), 0)

        data['password2'] = correct_password2
        valid_req = self.client.post(endpoint, data, follow=True)

        self.assertEqual(len(valid_req.redirect_chain), 1)  # aka the redirect to /login/

        self.assertIsNotNone(User.objects.last())

        registered_user = User.objects.last()
        self.assertIn('-', registered_user.username)

        initials = get_user_token_initials(registered_user.username)
        self.assertEqual(initials, username)

    def test_user_login(self):
        """
        Tests user login and correct fernet token usage.
        """
        username = 'test'
        user_token = create_user_token(username)
        password = 'notagain'

        test_user = User.objects.create_user(username=user_token, password=password)

        self.assertEqual(test_user.username, user_token)
        self.assertTrue(argon2.verify(password, test_user.password[6:]))

        initials = get_user_token_initials(user_token)

        self.assertEqual(initials, username)

        self.assertIsNone(test_user.last_login)

        for _ in range(20):
            self.assertFalse(self.client.login(username=user_token, password=token_bytes(16).decode('iso-8859-1')))

        self.assertIsNone(test_user.last_login)

        self.assertTrue(self.client.login(username=user_token, password=password))

        test_user.last_login = datetime.now()
        self.assertIsNotNone(test_user.last_login)

        user_token_list = []

        for _ in range(20):
            # we enter the loop already logged-in

            if self.client.get('/vault/').status_code != 200:
                # we're logged out -> log in with the most recent pass token
                self.client.login(username=user_token, password=user_token_list[-1])
                test_user.last_login = datetime.now()

            pass_token = self.client.get('/token').context['password_token']
            self.assertTrue(pass_token)
            self.assertIsInstance(pass_token, str)

            user_token_list.append(pass_token)

            self.client.logout()
            self.assertEqual(self.client.get('/vault/').status_code, 302)

        self.assertEqual(len(user_token_list), 20)

        for pass_tk in user_token_list:
            if pass_tk == user_token_list[-1]:
                # we should only be able to login with the most recent token
                self.assertTrue(self.client.login(username=user_token, password=pass_tk))
            else:
                self.assertFalse(self.client.login(username=user_token, password=pass_tk))

    def test_user_deletion(self):
        """
        Tests user deletion (and the deletion of all associated data).
        """
        user = User.objects.create_user(username='test_deletion', password='fulluserwipe1')

        self.assertNotEqual(User.objects.last(), None)

        for _ in range(4):
            Vault.objects.create(owner=user, app='testapp')

        self.assertEqual(Vault.objects.filter(owner=user).count(), 4)
        self.assertEqual(Nonce.objects.filter(user=user).count(), 1)

        user.delete()

        self.assertEqual(User.objects.last(), None)
        self.assertEqual(Vault.objects.filter(owner=user).exists(), False)
        self.assertEqual(Nonce.objects.filter(user=user).first(), None)

