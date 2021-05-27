
from django.urls import path
from .views import RegisterView, VerifyEmail, LoginView, VerifyOTP
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)


urlpatterns = [
    path('register/', RegisterView.as_view(), name="register"),
    path('login/', LoginView.as_view(), name="login"),
    # path('logout/', LogoutAPIView.as_view(), name="logout"),
    path('email-verify/', VerifyEmail.as_view(), name="email-verify"),
    path('login/<str:pk>/', VerifyOTP.as_view(), name="otp"),
]
