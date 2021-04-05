from django.urls import path
from .views import (
    VaultListView,
    VaultDetailView,
    VaultCreateView,
    VaultUpdateView,
    VaultDeleteView)

urlpatterns = [
    path('', VaultListView.as_view(), name='vault_home'),
    path('<int:pk>/', VaultDetailView.as_view(), name='vault_detail'),
    path('new/', VaultCreateView.as_view(), name='vault_create'),
    path('<int:pk>/update/', VaultUpdateView.as_view(), name='vault_update'),
    path('<int:pk>/delete/', VaultDeleteView.as_view(), name='vault_delete'),
]
