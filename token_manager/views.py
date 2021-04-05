from utils.fernet_keystore_utils import encrypt_with_random_key
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import never_cache
from django.contrib import messages
from django.shortcuts import render


@login_required
@never_cache
def token(request):
    """
    View handling the token page.
    :param request: the request object
    :return: a different rendered template based on the view logic
    """
    if request.method == 'GET':
        context = {
            'password_token': encrypt_with_random_key(request.user.password + str(request.user.last_login))
        }
        request.session['temp_token'] = context['password_token'].decode()

        request.session['viewed_token'] = True

        context['password_token'] = str(context['password_token'])[2:-1]
        return render(request, 'token_manager/token.html', context)
    else:
        messages.warning(request, 'Not allowed')
        return render(request, 'home/home.html')



