from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register, name="register"),
    path('login/', views.login_view, name="login"),
    path('logout/', views.logout_view, name="logout"),
    path('dashboard/', views.dashboard, name="dashboard"),
    path('verifier/', views.verifier_document, name='verifier_document'),

    # on ajoutera logout + dashboard + autres vues ensuite
]
