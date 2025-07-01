from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import CustomUser
import random
from django import forms
class RegistrationForm(UserCreationForm):
    nom = forms.CharField(max_length=100)
    prenom = forms.CharField(max_length=100)

    class Meta:
        model = CustomUser
        fields = ('prenom', 'nom', 'password1', 'password2')

    def save(self, commit=True):
        user = super().save(commit=False)
        nom = self.cleaned_data['nom']
        prenom = self.cleaned_data['prenom']
        user.nom = nom
        user.prenom = prenom
        user.username = f"{prenom.lower()}.{nom.lower()}{random.randint(1000,9999)}"
        if commit:
            user.save()
        return user


class VerificationForm(forms.Form):
    fichier = forms.FileField(label="Document à vérifier")
    qr_code = forms.ImageField(label="QR Code (image)")
