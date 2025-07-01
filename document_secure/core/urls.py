from django.urls import path
from . import views
from core.views import logout_view
from .views import dashboard_view, sign_and_protect_pdf, download_locked_pdf, download_encrypted_aes_key,verify_signed_pdf

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('register/', views.register_view, name='register'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('sign/', sign_and_protect_pdf, name='sign_and_protect_pdf'),
    # path('verify/', verify_document_view, name='verify_document'),
    path('about/', views.about, name='about'),
    path('download-locked-pdf/', download_locked_pdf, name='download_locked_pdf'),
    path('download-encrypted-aes-key/', download_encrypted_aes_key, name='download_encrypted_aes_key'),
    path('generate_rsa_keys/', views.generate_rsa_keys, name='generate_rsa_keys'),
    path('profil/', views.user_profile, name='user_profile'),
    path('verify_profile_password/', views.generate_rsa_keys, name='verify_profile_password'),
    path('verify-signed-pdf/', views.verify_signed_pdf, name='verify_signed_pdf'),
     path('convert/', views.convert_file_to_pdf, name='convert_file_to_pdf'),

]
# from django.urls import path
# from .views import dashboard_view, sign_document_view, verify_document_view

# urlpatterns = [
#     path('dashboard/', dashboard_view, name='dashboard'),
#     path('sign/', sign_document_view, name='sign_document'),
#     path('verify/', verify_document_view, name='verify_document'),
# ]
