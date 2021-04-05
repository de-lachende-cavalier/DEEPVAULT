from django.views.decorators import cache, csrf, debug
from .forms import UserRegisterForm, UserDeleteForm
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.contrib.auth import signals
from django.http import HttpResponse
from django.contrib import messages


@debug.sensitive_post_parameters()
@debug.sensitive_variables()
@cache.never_cache
@csrf.csrf_protect
def registration(request):
    """
    View that takes care of the logic behind user signup.
    :param request: the current request object
    :return: the rendered template based on the view logic
    """
    if request.user.is_authenticated:
        return redirect('vault_home')
    else:
        if request.method == 'POST':
            form = UserRegisterForm(request.POST)
            if form.is_valid():
                form.save()
                username = form.cleaned_data['username']
                messages.success(request, f'Account created for {username}.')
                return redirect('login')
        else:
            form = UserRegisterForm()

        return render(request, 'users/registration.html', {'form': form})

@debug.sensitive_post_parameters()
@debug.sensitive_variables()
@cache.never_cache
@csrf.csrf_protect
def user_delete(request):
    """
    View that handles user deletion.
    IMPORTANT -> it doesn't have the login_required decorator because it supposes the user has already been compromised,
    that is the same reason why we authenticate the user based on his password (we assume that the attacker got a hold
    of the correct fernet token, in which case there's no way he can know the password)
    :param request: the current request object
    :return: the rendered template based on the view logic
    """
    if request.user.is_authenticated:
        return redirect('vault_home')
    else:
        if request.method == 'POST':
            form = UserDeleteForm(request.POST)

            if not form.is_valid():
                signals.user_login_failed.send(sender=User,
                                               request=request,
                                               credentials={'username': form.cleaned_data['username']})
                return HttpResponse(status=400)

            user = User.objects.get(username__exact=form.cleaned_data['username'])
            user.last_login = None  # this way it authenticates against the original password
            user.save()

            authd_user = authenticate(request=request,
                                      username=form.cleaned_data['username'],
                                      password=form.cleaned_data['password'])

            if authd_user is not None:
                signals.user_logged_in.send(sender=User, request=request, user=authd_user)

                authd_user.is_active = False
                authd_user.delete()

                messages.success(request, 'Data successfully deleted.')
                return redirect('main_home')

            signals.user_login_failed.send(sender=User,
                                           request=request,
                                           credentials={'username': form.cleaned_data['username']})
            messages.warning(request, 'Incorrect credentials.')
            return HttpResponse(status=403)

        else:
            form = UserDeleteForm()

        return render(request, 'users/delete_user.html', {'form': form})
