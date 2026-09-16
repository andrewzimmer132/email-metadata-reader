from django.contrib import admin
from analyzer import models
from analyzer.models import User, Email


# Register your models here.
admin.site.register(models.User)
admin.site.register(models.Email)
