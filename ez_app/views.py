from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth import authenticate
from django.core.mail import send_mail
from django.conf import settings
from django.shortcuts import get_object_or_404, HttpResponse
from cryptography.fernet import Fernet
from rest_framework_simplejwt.tokens import RefreshToken
import uuid
import os
from .models import User, File
from .serializers import UserSerializer, FileSerializer
from .permissions import IsOpsUser, IsClientUser
from .utility import validate_file_extension
import logging

logger = logging.getLogger('ez_app')

class UserLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            username = request.data.get('username','').strip()
            password = request.data.get('password','').strip()
            
            if not all([username,password]):
                return Response(
                    {'error': 'Please provide username and password'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            user = authenticate(username=username, password=password)

            if user:
                if user.user_type == 'client' and not user.email_verified:
                    return Response(
                        {'error': 'Please verify your email first.'},
                        status=status.HTTP_403_FORBIDDEN
                    )

                refresh = RefreshToken.for_user(user)
                
                return Response({
                    'token': str(refresh.access_token),
                    'refresh_token': str(refresh),
                    'user_type': user.user_type,
                    'message': 'Login successful'
                })
            
            return Response(
                {'error': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        except Exception as E:
            logger.error(f"user_login view: {E}")
            return Response({'message': 'server error'},status=status.HTTP_412_PRECONDITION_FAILED)

class UserSignupView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            serializer = UserSerializer(data=request.data)
            if serializer.is_valid():
                user = serializer.save(email_verified=False)
                
                verification_token = str(uuid.uuid4())
                user.verification_token = verification_token
                user.save()

                # Create verification URL
                verification_url = f"{request.scheme}://{request.get_host()}/api/verify-email/{verification_token}/"

                # Send verification email
                try:
                    send_mail(
                        'Verify your email',
                        f'Please click the following link to verify your email: {verification_url}',
                        settings.EMAIL_HOST_USER,
                        [user.email],
                        fail_silently=False,
                    )

                    return Response({
                        'message': 'User created successfully. Please check your email for verification.',
                        'verification_url': verification_url
                    }, status=status.HTTP_201_CREATED)

                except Exception as e:
                    user.delete()  # Delete user if email sending fails
                    return Response({
                        'error': 'Could not send verification email. Please try again.'
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as E:
            logger.error(f"user_signup view: {E}")
            return Response({'message': 'server error'},status=status.HTTP_412_PRECONDITION_FAILED)

class EmailVerificationView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, token):
        try:
            try:
                user = User.objects.get(verification_token=token)
            except User.DoesNotExist:
                return Response({'message': 'Invalid verification token.'}, status=status.HTTP_400_BAD_REQUEST)

            if user.email_verified:
                return Response({
                    'message': 'Email already verified.'
                }, status=status.HTTP_200_OK)

            user.email_verified = True
            user.verification_token = None
            user.save()

            return Response({'message': 'Email verified successfully.'}, status=status.HTTP_200_OK)
        except Exception as E:
            logger.error(f"email_verification view: {E}")
            return Response({'message': 'server error'},status=status.HTTP_412_PRECONDITION_FAILED)
            
class FileUploadView(APIView):
    permission_classes = [IsAuthenticated, IsOpsUser]

    def post(self, request):
        try:
            if 'file' not in request.FILES:
                return Response({'error': 'No file provided'}, status=status.HTTP_400_BAD_REQUEST)

            file_obj = request.FILES['file']
            serializer = FileSerializer(data={'file': file_obj})
            if serializer.is_valid():
                file_instance = serializer.save(uploaded_by=request.user)
                file_instance.download_token = str(uuid.uuid4())
                file_instance.save()

                return Response({'message':"file successfully uploaded"}, status=status.HTTP_201_CREATED)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as E:
            logger.error(f"file_upload view: {E}")
            return Response({'message': 'server error'},status=status.HTTP_412_PRECONDITION_FAILED)

class FileDownloadView(APIView):
    permission_classes = [IsAuthenticated, IsClientUser]

    def get(self, request, download_token):
        try:
            file = get_object_or_404(File, download_token=download_token)
            file_path = file.file.path
            response = HttpResponse(open(file_path, 'rb').read())
            response['Content-Type'] = 'application/octet-stream'
            response['Content-Disposition'] = 'attachment; filename="' + file.file.name + '"'
            return response

        except Exception as E:
            logger.error(f"file_download view: {E}")
            return Response({'message': 'server error'},status=status.HTTP_412_PRECONDITION_FAILED)

class FileListView(APIView):
    permission_classes = [IsAuthenticated, IsClientUser]

    def get(self, request):
        try:
            files = File.objects.all().order_by('-uploaded_at')
            serializer = FileSerializer(
                files, 
                many=True, 
                context={'request': request}
            )
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as E:
            logger.error(f"file_download view: {E}")
            return Response({'message': 'server error'},status=status.HTTP_412_PRECONDITION_FAILED)
        
class FileDownloadLink(APIView):
    permission_classes = [IsAuthenticated, IsClientUser]

    def get(self, request, download_token):
        try:
            try:
                file = File.objects.get(download_token = download_token)
            except File.DoesNotExist as E:
                return Response({'message':'file not found for this token.'},status=status.HTTP_404_NOT_FOUND)
            download_url = f"/api/download-file/{file.download_token}/"
            response = {
                "message":"success",
                "download_url":download_url
            }
            return Response(response, status=status.HTTP_200_OK)

        except Exception as E:
            logger.error(f"file_download view: {E}")
            return Response({'message': f'server error{E}'},status=status.HTTP_412_PRECONDITION_FAILED)        