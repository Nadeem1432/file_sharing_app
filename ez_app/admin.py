from django.contrib import admin
from .models import *
# Register your models here.



# admin.site.register(User)

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ['username','email','user_type','email_verified','verification_token']

@admin.register(File)
class FileAdmin(admin.ModelAdmin):
    list_display = ["file","uploaded_by","download_token","uploaded_at"]
