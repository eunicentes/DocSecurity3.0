from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser,UserRSAKey

admin.site.register(CustomUser, UserAdmin)
admin.site.register(UserRSAKey)
