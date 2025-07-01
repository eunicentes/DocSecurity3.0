import hashlib
import qrcode
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from .forms import RegistrationForm
from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from .models import Document
#from pyzbar.pyzbar import decode
#from PIL import Image
from .forms import VerificationForm
from .utils import decode_qr_opencv
import os
from django.conf import settings


#inscription
def register(request):
    if request.method == "POST":
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(request, f"Inscription réussie. Votre nom d'utilisateur est : {user.username}")
            return redirect("login")
    else:
        form = RegistrationForm()
    return render(request, "register.html", {"form": form})

#connexion
def login_view(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect("dashboard")  # Tu vas créer cette vue plus tard
        else:
            messages.error(request, "Nom d'utilisateur ou mot de passe incorrect.")
    return render(request, "login.html")

#deconnexion
def logout_view(request):
    logout(request)
    return redirect('login')

#dashboard

@login_required
def dashboard(request):
    if request.method == 'POST' and 'fichier' in request.FILES:
        fichier = request.FILES['fichier']
        contenu = fichier.read()
        hash_val = hashlib.sha256(contenu).hexdigest()

        # Création d’un QR code
        qr = qrcode.make(hash_val)
        qr_path = f"media/qrcodes/{request.user.username}_{fichier.name}.png"
        qr.save(qr_path)

        # Sauvegarde document
        doc = Document.objects.create(
            utilisateur=request.user,
            fichier=fichier,
            hash_code=hash_val
        )

        return render(request, 'dashboard.html', {
            'message': 'Document envoyé et QR code généré avec succès.',
            'qr_image': qr_path,
            'nb_envoyes': Document.objects.filter(utilisateur=request.user).count()
        })

    nb_envoyes = Document.objects.filter(utilisateur=request.user).count()
    return render(request, 'dashboard.html', {'nb_envoyes': nb_envoyes})

#verification


def verifier_document(request):
    result = None
    if request.method == "POST":
        form = VerificationForm(request.POST, request.FILES)
        if form.is_valid():
            fichier = request.FILES['fichier']
            qr_code_img = request.FILES['qr_code']

            # Calculer le hash du document
            contenu = fichier.read()
            hash_document = hashlib.sha256(contenu).hexdigest()

            # Lire le QR code
            image = Image.open(qr_code_img)
            data = decode(image)
            if not data:
                result = "QR code non lisible ou vide."
            else:
                hash_attendu = data[0].data.decode("utf-8")
                if hash_document == hash_attendu:
                    result = "✅ Le document est intègre (non modifié)."
                else:
                    result = "❌ Le document a été modifié ou altéré !"
    else:
        form = VerificationForm()
    
    return render(request, 'dashboard/verifier_document.html', {'form': form, 'result': result})
