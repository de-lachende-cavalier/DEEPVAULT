from django.views.generic import ListView
from django.shortcuts import render
from home.models import About


def home(request):
    return render(request, 'home/home.html')


class AboutListView(ListView):
    """
    Class based view to allow for pagination.
    """
    model = About
    template_name = 'home/about.html'
    context_object_name = 'about'
    paginate_by = 1

    def get_queryset(self):
        return About.objects.all()





