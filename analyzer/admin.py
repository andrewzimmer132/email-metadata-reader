from django.contrib import admin
from analyzer import models
from analyzer.models import Email


# Register your models here.
admin.site.register(models.Email)
