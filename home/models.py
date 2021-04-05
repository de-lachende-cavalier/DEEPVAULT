from django.db import models


class About(models.Model):
    """
    Holds the title and content of the various pages of the about route, so that I can use pagination to format them.
    """
    title = models.CharField(max_length=30, unique=False, default='')
    content = models.TextField()




