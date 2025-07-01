from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings  # Utilise toujours settings.AUTH_USER_MODEL pour rester générique

class CustomUser(AbstractUser):
    prenom = models.CharField(max_length=100)
    nom = models.CharField(max_length=100)

    def __str__(self):
        return self.username

#dash

class Document(models.Model):
    utilisateur = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE
    )
    fichier = models.FileField(upload_to='documents/')
    hash_code = models.CharField(max_length=100)
    date_envoi = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.utilisateur.username} - {self.fichier.name}"