from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import CustomUser


class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True, label="Adresse e-mail")
    profile_password1 = forms.CharField(label="Mot de passe Profil", widget=forms.PasswordInput)
    profile_password2 = forms.CharField(label="Confirmation Mot de passe Profil", widget=forms.PasswordInput)

    class Meta:
        model = CustomUser  # Utiliser le bon modèle
        fields = ("username", "email", "password1", "password2")
       


    def clean_email(self):
        email = self.cleaned_data.get('email')
        if CustomUser.objects.filter(email=email).exists():
            raise forms.ValidationError("Cette adresse e-mail est déjà utilisée.")
        return email


    def clean(self):
        cleaned_data = super().clean()
        p1 = cleaned_data.get("profile_password1")
        p2 = cleaned_data.get("profile_password2")
        if p1 and p2 and p1 != p2:
            self.add_error('profile_password2', "Les mots de passe Profil ne correspondent pas")
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        if "profile_password1" in self.cleaned_data:
            user.set_profile_password(self.cleaned_data["profile_password1"])
        if commit:
            user.save()
        return user


class ProfilePasswordForm(forms.Form):
    profile_password = forms.CharField(label="Mot de passe Profil", widget=forms.PasswordInput)

class LoginForm(AuthenticationForm):
    username = forms.CharField(label="Nom d'utilisateur")
    password = forms.CharField(widget=forms.PasswordInput) 
    from django import forms

