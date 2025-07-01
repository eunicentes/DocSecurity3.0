from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from .forms import LoginForm,  RegisterForm,  ProfilePasswordForm
from django.contrib import messages
import hashlib
import os , io
from django.contrib.auth import logout
from io import BytesIO
from django.contrib.auth.decorators import login_required 
from django.http import HttpResponse,FileResponse
from PyPDF2 import PdfReader, PdfWriter
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.colors import white
from .models import UserRSAKey
from PIL import Image
import xml.etree.ElementTree as ET
from django.conf import settings
from django.core.files.storage import FileSystemStorage 


@login_required
def sign_and_protect_pdf(request):
    if request.method == 'POST' and request.FILES.get('pdf_file') and request.POST.get('rsa_public_key'):
        try:
            # 1. Lecture du fichier PDF
            uploaded_file = request.FILES['pdf_file']
            original_pdf_bytes = uploaded_file.read()

            # 2. Calcul du hash SHA-256
            hash_value = hashlib.sha256(original_pdf_bytes).hexdigest()

            # 3. Copier les pages existantes
            pdf_reader = PdfReader(BytesIO(original_pdf_bytes))
            pdf_writer = PdfWriter()
            for page in pdf_reader.pages:
                pdf_writer.add_page(page)

            # 4. Générer la page blanche contenant le hash (invisible)
            hash_page_stream = BytesIO()
            c = canvas.Canvas(hash_page_stream, pagesize=letter)
            c.setFont("Helvetica", 1)
            c.setFillColor(white)  # Texte invisible
            c.drawString(50, 500, f"Hash: {hash_value}")
            c.showPage()
            c.save()
            hash_page_stream.seek(0)
            hash_page_pdf = PdfReader(hash_page_stream)
            pdf_writer.add_page(hash_page_pdf.pages[0])

            # 5. Générer un mot de passe AES aléatoire (16 caractères)
            aes_password = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')[:16]

            # 6. Appliquer le mot de passe au PDF
            pdf_writer.encrypt(aes_password)  # ✅ Correction ici

            # 7. Écriture du PDF final chiffré
            final_pdf = BytesIO()
            pdf_writer.write(final_pdf)
            final_pdf.seek(0)

            # 8. Chiffrer la clé AES avec la clé publique RSA
            try:
                rsa_public_key_pem = request.POST['rsa_public_key']
                rsa_key = RSA.import_key(rsa_public_key_pem)
                cipher_rsa = PKCS1_OAEP.new(rsa_key)
                encrypted_aes_key = cipher_rsa.encrypt(aes_password.encode())
                encrypted_key_b64 = base64.b64encode(encrypted_aes_key).decode('utf-8')
            except Exception as e:
                return render(request, 'core/sign_document.html', {
                    'error': f"Clé RSA invalide : {e}"
                })

            # 9. Sauvegarde temporaire en session
            request.session['final_pdf_bytes'] = base64.b64encode(final_pdf.read()).decode('utf-8')
            request.session['encrypted_key'] = encrypted_key_b64
            request.session['aes_password'] = aes_password  # Pour affichage uniquement, à supprimer en prod

            return render(request, 'core/sign_document_result.html', {
                'hash': hash_value,
                'aes_password': aes_password,  # Affiché seulement à titre indicatif
            })

        except Exception as e:
            return render(request, 'core/sign_document.html', {
                'error': f"Erreur lors du traitement : {str(e)}"
            })

    return render(request, 'core/sign_document.html')

@login_required
def download_locked_pdf(request):
    encoded_pdf = request.session.get('final_pdf_bytes')
    if not encoded_pdf:
        return HttpResponse("Aucun fichier disponible", status=404)
    
    pdf_bytes = base64.b64decode(encoded_pdf)
    response = HttpResponse(pdf_bytes, content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="document_verrouille.pdf"'
    return response


@login_required
def download_encrypted_aes_key(request):
    encrypted_key = request.session.get('encrypted_key')
    if not encrypted_key:
        return HttpResponse("Clé AES non disponible", status=404)

    response = HttpResponse(encrypted_key, content_type='text/plain')
    response['Content-Disposition'] = 'attachment; filename="cle_aes_chiffree.txt"'
    return response  

def extraire_hash_depuis_pdf(pdf_path):
    lecteur = PdfReader(pdf_path)
    texte = lecteur.pages[-1].extract_text()
    return texte.strip().split()[-1]


def calculer_hash_sans_derniere_page(pdf_path):
    lecteur = PdfReader(pdf_path)
    redacteur = PdfWriter()

    for i in range(len(lecteur.pages) - 1):
        redacteur.add_page(lecteur.pages[i])

    buffer = io.BytesIO()
    redacteur.write(buffer)
    buffer.seek(0)
    return hashlib.sha256(buffer.read()).hexdigest()

# def calculate_sha256_bytes(original_pdf_bytes):
#     hash_value = hashlib.sha256(original_pdf_bytes).hexdigest()
#     return 

@login_required
def verify_signed_pdf(request):
    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'decrypt_aes':
            try:
                rsa_key_pem = request.POST['rsa_private_key']
                encrypted_aes_b64 = request.POST['encrypted_aes_key']
                decrypted_key = decrypt_aes_key(rsa_key_pem, encrypted_aes_b64)

                request.session['decrypted_aes_key'] = decrypted_key

                return render(request, 'core/verify_document.html', {
                    'message': '✅ Clé AES déchiffrée avec succès.'
                })
            except Exception as e:
                return render(request, 'core/verify_document.html', {
                    'error': str(e)
                })

        elif action == 'verify_pdf':
            aes_key = request.session.get('decrypted_aes_key')
            if not aes_key:
                return render(request, 'core/verify_document.html', {
                    'error': "❗ Clé AES manquante. Veuillez d'abord la déchiffrer."
                })

            try:
                uploaded_pdf = request.FILES.get('pdf_file')
                if not uploaded_pdf or not uploaded_pdf.name.endswith('.pdf'):
                    return render(request, 'core/verify_document.html', {
                        'error': "❗ Aucun fichier PDF valide n'a été fourni."
                    })

                # Sauvegarde temporaire
                temp_path = os.path.join(settings.MEDIA_ROOT, 'uploads', 'verifs', uploaded_pdf.name)
                os.makedirs(os.path.dirname(temp_path), exist_ok=True)
                with open(temp_path, 'wb+') as f:
                    for chunk in uploaded_pdf.chunks():
                        f.write(chunk)

                # Appel de la vraie fonction de vérification
                success, result_msg = verify_pdf_signature(temp_path, aes_key=aes_key)

                request.session.pop('decrypted_aes_key', None)

                return render(request, 'core/verify_document_result.html', {
                    'message': result_msg
                })

            except Exception as e:
                return render(request, 'core/verify_document.html', {
                    'error': str(e)
                })

    return render(request, 'core/verify_document.html')


def verify_pdf_signature(pdf_path, aes_key):
    try:
        # 1. Extraire le hash signé depuis la dernière page
        signed_hash = extraire_hash_depuis_pdf(pdf_path)

        # 2. Calculer le hash du PDF sans la dernière page
        calculated_hash = calculer_hash_sans_derniere_page(pdf_path)

        # 3. Comparaison
        if signed_hash == calculated_hash:
            return True, "✅ Document vérifié avec succès. Il n’a pas été modifié."
        else:
            return False, "❌ Intégrité du document compromise. Les contenus ne correspondent pas."

    except Exception as e:
        return False, f"Erreur lors de la vérification : {str(e)}"


def decrypt_aes_key(rsa_private_key_pem: str, encrypted_aes_b64: str) -> str:
    try:
        private_key = RSA.import_key(rsa_private_key_pem)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        encrypted_aes = base64.b64decode(encrypted_aes_b64)
        decrypted_aes = cipher_rsa.decrypt(encrypted_aes)
        return decrypted_aes.decode()
    except Exception as e:
        raise Exception(f"Erreur de déchiffrement AES : {e}")





#home############################################################################
def home(request):
    return render(request, 'core/home.html') 

#LOGIN
def login_view(request):
    if request.method == "POST":
        form = LoginForm(request=request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('dashboard')
            else:
                messages.error(request, "Nom d'utilisateur ou mot de passe incorrect.")
        else:
            messages.error(request, "Erreur dans le formulaire.")
    else:
        form = LoginForm()
    return render(request, 'core/login.html', {'form': form})

#regsiter
def register_view(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)  # connecte directement l'utilisateur après inscription
            return redirect('dashboard')  # assure-toi que cette url existe
    else:
        form = RegisterForm()

    return render(request, 'core/register.html', {'form': form})


#dashboard
@login_required
def dashboard_view(request):
    user = request.user

    # Pour l'instant, on simule les stats :
    signed_docs_count = 5  # à remplacer par un vrai comptage en base
    verified_docs_count = 3  # idem

    context = {
        'signed_docs_count': signed_docs_count,
        'verified_docs_count': verified_docs_count,
    }
    return render(request, 'core/dashboard.html', context)


def about(request):
    # ta logique ici
    return render(request, 'core/templates/core/about.html')

def logout_view(request):
    logout(request)
    return redirect('login') 


@login_required

def generate_rsa_keys(request):
    if request.method == 'POST':
        key = RSA.generate(2048)
        private_key_pem = key.export_key().decode('utf-8')
        public_key_pem = key.publickey().export_key().decode('utf-8')

        # Sauvegarde en base
        rsa_key, created = UserRSAKey.objects.get_or_create(user=request.user)
        rsa_key.public_key = public_key_pem
        rsa_key.private_key = private_key_pem
        rsa_key.save()

        return render(request, 'core/profil.html', {
            'public_key': public_key_pem,
            'private_key': private_key_pem,
        })

    # GET : afficher les clés existantes si elles existent
    rsa_key = getattr(request.user, 'rsa_k', None)
    return render(request, 'core/profil.html', {
        'public_key': rsa_key.public_key if rsa_key else None,
        'private_key': rsa_key.private_key if rsa_key else None,
    })


@login_required
def confirm_profile_password(request):
    if request.method == 'POST':
        password = request.POST.get('password')

        if request.user.check_profile_password(password):
            request.session['profile_password_verified'] = True
            return redirect('user_profile')
        else:
            messages.error(request, "Mot de passe Profil incorrect")

    return render(request, 'core/confirm_password.html')

@login_required
def user_profile(request):
    if not request.session.get('profile_password_verified'):
        return redirect('confirm_profile_password')

    # Optionnel : supprime la validation après accès
    del request.session['profile_password_verified']

    # Récupère l'utilisateur courant
    user = request.user

    # Passe le champ profile_password_hash au template
    context = {
        'user': user,
        'profile_password_hash': user.profile_password_hash,  # <-- ajout important
    }
    return render(request, 'core/profil.html', context)


@login_required
def profile_view(request):
    if request.method == "POST":
        form = ProfilePasswordForm(request.POST)
        if form.is_valid():
            entered_password = form.cleaned_data['profile_password']
            if request.user.check_profile_password(entered_password):
                return redirect('core:profil')  # redirige vers ta page profil (à adapter)
            else:
                messages.error(request, "Mot de passe incorrect pour accéder au profil.")
    else:
        form = ProfilePasswordForm()

    return render(request, 'core/verify_profile_password.html', {'form': form})   
#conversion en pdf

@login_required
def convert_file_to_pdf(request):
    if request.method == 'POST' and request.FILES.get('uploaded_file'):
        uploaded_file = request.FILES['uploaded_file']
        file_type = uploaded_file.content_type
        file_name = uploaded_file.name

        fs = FileSystemStorage()
        filename = fs.save(file_name, uploaded_file)
        file_path = fs.path(filename)

        output_pdf_path = os.path.join(settings.MEDIA_ROOT, 'converted_output.pdf')

        try:
            if 'image' in file_type:
                # Convertir image en PDF
                image = Image.open(file_path)
                if image.mode != 'RGB':
                    image = image.convert('RGB')
                image.save(output_pdf_path, "PDF")

            elif 'xml' in file_type:
                # Convertir XML en texte PDF
                tree = ET.parse(file_path)
                root = tree.getroot()

                c = canvas.Canvas(output_pdf_path)
                c.drawString(100, 800, f"Fichier XML: {file_name}")
                y = 780
                for elem in root.iter():
                    text = f"{elem.tag}: {elem.text}"
                    c.drawString(100, y, text)
                    y -= 15
                    if y < 50:
                        c.showPage()
                        y = 800
                c.save()

            else:
                return render(request, 'convert_form.html', { 'error': 'Type de fichier non pris en charge.' })

            return FileResponse(open(output_pdf_path, 'rb'), as_attachment=True, filename='converted_output.pdf')

        except Exception as e:
            return render(request, 'convert_form.html', { 'error': f'Erreur lors de la conversion: {str(e)}' })

    return render(request, 'core/convert_form.html')
