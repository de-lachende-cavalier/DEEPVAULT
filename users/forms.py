from django.contrib.auth.forms import UserCreationForm
from utils.users_utils import create_user_token
from django.contrib.auth.models import User
from django import forms


class UserRegisterForm(UserCreationForm):
    """
    Form to register a new user.
    """

    class Meta:
        model = User
        fields = ['username', 'password1', 'password2']

    def clean_username(self):
        """
        Gets the input username and tokenizes it to make it far less guessable.
        :return: the correctly tokenized username
        """
        data = self.cleaned_data['username']
        return create_user_token(data)


class UserDeleteForm(forms.Form):
    """
    Form used to allow users to delete their account and associated data.
    """
    username = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput)



