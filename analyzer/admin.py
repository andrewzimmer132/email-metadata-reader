from django.contrib import admin
from analyzer import models
from analyzer.models import Email, LoginAttempt


# Register your models here.
admin.site.register(models.Email)
admin.site.register(models.LoginAttempt)