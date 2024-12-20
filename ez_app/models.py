from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
import os
from ez_app.utility import validate_file_extension

class User(AbstractUser):
    USER_TYPE_CHOICES = (
        ('ops', 'Operations User'),
        ('client', 'Client User'),
    )
    user_type = models.CharField(max_length=10, choices=USER_TYPE_CHOICES)
    email = models.EmailField(unique=True)
    email_verified = models.BooleanField(default=False)
    verification_token = models.CharField(max_length=100, null=True, blank=True)
    def __str__(self):
        return str(self.username)+"-"+str(self.email)

class File(models.Model):
    file = models.FileField(upload_to='uploads/', validators=[validate_file_extension])
    uploaded_by = models.ForeignKey(User, on_delete=models.CASCADE)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    download_token = models.CharField(max_length=100, null=True, blank=True)

    def __str__(self):
        return self.file.name