from django.contrib.auth.models import AbstractUser
from django.db import models

# Create your models here.

class Email(models.Model):
    header = models.TextField(default="")
    body = models.TextField(default="")

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

    def compare(self, other_email) -> list[dict]:
        """Return differences in email address"""
        if not isinstance(other_email, Email):
            raise TypeError("other_email must be of type Email")

        differences = []

        for field in ("email", "status"): # TODO: Add more fields to compare
            current_value = getattr(self, field)
            other_value = getattr(other_email, field)

            if current_value != other_value:
                differences.append(
                    {
                        "field": field,
                        "current": current_value,
                        "other": other_value,
                    }
                )

        return differences

    def __str__(self):
        return self.body


class LoginAttempt(models.Model):
    username = models.CharField(max_length=150, unique=True)
    failures = models.PositiveIntegerField(default=0)
    lock_time = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.username