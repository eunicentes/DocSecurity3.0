from django.contrib.auth.models import AbstractUser
from django.db import models
from document_secure import settings
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.hashers import make_password, check_password


class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    profile_password_hash = models.CharField(max_length=128, blank=True, null=True)

    def set_profile_password(self, raw_password):
        self.profile_password_hash = make_password(raw_password)

    def check_profile_password(self, raw_password):
        return check_password(raw_password, self.profile_password_hash)
   

class UserRSAKey(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='rsa_keys')
    public_key = models.TextField()
    private_key = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Clés RSA de {self.user.username}"

