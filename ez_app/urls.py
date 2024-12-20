from django.urls import path
from .views import (
    UserLoginView, 
    UserSignupView,
    EmailVerificationView,
    FileUploadView,
    FileDownloadView,
    FileListView,
    FileDownloadLink
)

urlpatterns = [
    path('login/', UserLoginView.as_view(), name='user-login'),
    path('signup/', UserSignupView.as_view(), name='user-signup'),
    path('verify-email/<str:token>/', EmailVerificationView.as_view(), name='email-verify'),
    
    path('files/', FileListView.as_view(), name='file-list'),
    path('files/upload/', FileUploadView.as_view(), name='file-upload'),
    path('download-file-link/<str:download_token>/', FileDownloadLink.as_view(), name='file-download-link'),
    path('download-file/<str:download_token>/', FileDownloadView.as_view(), name='file-download'),
]