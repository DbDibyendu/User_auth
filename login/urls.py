
from django.urls import path
from .views import RegisterView, VerifyEmail, LoginView, VerifyOTP, ResetPassword, LogoutAPIView, NewToken, Update


urlpatterns = [
    path('register/', RegisterView.as_view(), name="register"),
    path('login/', LoginView.as_view(), name="login"),
    path('logout/<str:pk>/', LogoutAPIView.as_view(), name="logout"),
    path('email-verify/', VerifyEmail.as_view(), name="email-verify"),
    path('login/<str:pk>/', VerifyOTP.as_view(), name="otp"),
    path('reset-password/', ResetPassword.as_view(), name="reset-password"),
    path('refresh-token/', NewToken.as_view(), name='token'),
    path('update/<str:pk>/', Update.as_view(), name='update'),
]
