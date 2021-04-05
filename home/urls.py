from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='main_home'),
    path('about/', views.AboutListView.as_view(), name='main_about'),
]