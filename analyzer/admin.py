from django.contrib import admin
from analyzer import models
from analyzer.models import User, Email


# Register your models here.
@admin.register(models.User)
class User(User):
    model = models.User
    list_display = ('get_username', 'get_email')

    def get_username(self, obj):
        return obj.user.username
    get_username.short_description = 'Username'
    def get_email(self, obj):
        return obj.user.email
    get_email.short_description = 'Email'

@admin.register(models.Email)
class Email(Email):
    model = models.Email
    list_display = ('sender', 'recipient', 'subject')
    list_filter = ('sender', 'recipient', 'subject')
    search_fields = ('sender', 'recipient', 'subject')
