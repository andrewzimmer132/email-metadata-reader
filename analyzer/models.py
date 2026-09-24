from django.contrib.auth.models import AbstractUser
from django.db import models

# Create your models here.

class Email(models.Model):
    email = models.EmailField()

    #Status choices for email
    status = models.CharField(
        max_length = 20,
        default = 'pending',
        choices = [
            ('pending', 'pending'),
            ('safe', 'safe'),
            ('unsafe', 'unsafe'),
            ('spam/scam', 'spam/scam'),
        ]

    )
    def __str__(self):
        return self.email


class LoginAttempt(models.Model):
    username = models.CharField(max_length=150, unique=True)
    failures = models.PositiveIntegerField(default=0)
    lock_time = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.username