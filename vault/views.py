from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.messages.views import SuccessMessageMixin
from rules.contrib.views import PermissionRequiredMixin
from django.views.decorators import cache, csrf, debug
from django.utils.decorators import method_decorator
from django.views.generic import (
    ListView,
    DetailView,
    CreateView,
    DeleteView,
    UpdateView,
)
from .models import Vault


@method_decorator(debug.sensitive_variables(), name='dispatch')
class VaultListView(LoginRequiredMixin, ListView):
    """
    Class based view to display the different safes a user has.
    It filters them redundantly: first by only querying the vaults belonging to the user, then by checking that the user
    has view permissions on them. A third permission check is done in the vault_home.html template.
    """
    model = Vault
    template_name = 'vault/vault_home.html'
    context_object_name = 'vault'

    def get_queryset(self):
        vaults = Vault.objects.filter(owner=self.request.user)
        valid_vaults = []
        for vault in vaults:
            if self.request.user.has_perm('vault.view_vault', vault):
                valid_vaults.append(vault)
        return valid_vaults


@method_decorator(debug.sensitive_variables(), name='dispatch')
class VaultDetailView(PermissionRequiredMixin, LoginRequiredMixin, DetailView):
    """
    Class based view to display the details of a single safe.
    Check for view permissions on the vault and restricts the queryset. Like above, permissions are checked a third time
    in the template.
    """
    model = Vault
    permission_required = 'vault.view_vault'

    def get_queryset(self):
        return Vault.objects.filter(owner=self.request.user)


@method_decorator(debug.sensitive_post_parameters(), name='dispatch')
@method_decorator(debug.sensitive_variables(), name='dispatch')
@method_decorator(cache.never_cache, name='dispatch')
@method_decorator(csrf.csrf_protect, name='dispatch')
class VaultCreateView(LoginRequiredMixin, SuccessMessageMixin, CreateView):
    """
    Class based view that allows user to create new safes.
    It sets the owner to the user currently logged in.
    """
    model = Vault
    fields = ['app', 'app_username', 'app_password']
    success_url = '/vault/'
    success_message = 'The safe has been successfully created.'

    def get_queryset(self):
        return None

    def form_valid(self, form):
        form.instance.owner = self.request.user
        return super(VaultCreateView, self).form_valid(form)


@method_decorator(debug.sensitive_post_parameters(), name='dispatch')
@method_decorator(debug.sensitive_variables(), name='dispatch')
@method_decorator(cache.never_cache, name='dispatch')
@method_decorator(csrf.csrf_protect, name='dispatch')
class VaultUpdateView(LoginRequiredMixin, PermissionRequiredMixin, UserPassesTestMixin,
                      SuccessMessageMixin, UpdateView):
    """
    Class based view that allows users to change safe details.
    As usual, it restricts the queryset, it checks for change permissions both here and in the template, and on top of
    that it checks that the current user is in fact the owner of the vault he wants to update (so four layers of
    redundancy)
    """
    model = Vault
    permission_required = 'vault.change_vault'
    fields = ['app', 'app_username', 'app_password']
    success_url = '/vault/'
    success_message = 'The safe has been successfully updated.'
    template_name = 'vault/vault_update_form.html'

    def get_queryset(self):
        return Vault.objects.filter(owner=self.request.user)

    def form_valid(self, form):
        form.instance.owner = self.request.user
        return super().form_valid(form)

    def test_func(self):
        cur_safe = self.get_object()
        if self.request.user == cur_safe.owner:
            return True
        else:
            return False


@method_decorator(debug.sensitive_variables(), name='dispatch')
class VaultDeleteView(LoginRequiredMixin, PermissionRequiredMixin, UserPassesTestMixin,
                      SuccessMessageMixin, DeleteView):
    """
    Class based view that allows users to delete safes.
    Just like the UpdateView it has four layers of redundancy, so refer to it for further explanation.
    """
    model = Vault
    permission_required = 'vault.delete_vault'
    success_url = '/vault/'
    success_message = 'The safe has been successfully deleted.'

    def get_queryset(self):
        return Vault.objects.filter(owner=self.request.user)

    def test_func(self):
        cur_safe = self.get_object()
        if self.request.user == cur_safe.owner:
            return True
        else:
            return False
