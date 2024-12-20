from rest_framework import serializers
from .models import User, File
from django.core.files.uploadedfile import UploadedFile
from rest_framework.validators import ValidationError

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    user_type = serializers.ChoiceField(choices=User.USER_TYPE_CHOICES)

    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password', 'user_type')
    def create(self, data):
        user = User.objects.create_user(
            username=data['username'],
            email=data['email'],
            password=data['password'],
            user_type=data['user_type']
        )
        return user
    
class FileSerializer(serializers.ModelSerializer):
    download_url = serializers.SerializerMethodField()
    uploaded_by = serializers.SerializerMethodField()

    class Meta:
        model = File
        fields = ( 'file', 'uploaded_by', 'download_url')
        read_only_fields = ('uploaded_by', 'download_url')

    def get_download_url(self, obj):
        request = self.context.get('request')
        if request and request.user.user_type == 'client':
            return f"/api/download-file/{obj.download_token}/"
        return None
    
    def get_uploaded_by(self, obj):
        uploader_name = obj.uploaded_by.email
        return uploader_name