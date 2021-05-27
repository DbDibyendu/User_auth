from django.core.mail.message import EmailMessage
from django.shortcuts import render
from rest_framework import generics, serializers, status, views, permissions
from .serializers import RegisterSerializer, EmailVerificationSerializer, LoginSerializer,OTPVerificationSerializer
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import smtplib
import random
from email.message import EmailMessage
# from drf_yasg.utils import swagger_auto_schema
# from drf_yasg import openapi
# from .renderers import UserRenderer
# from django.contrib.auth.tokens import PasswordResetTokenGenerator
# from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
# from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
# from django.contrib.sites.shortcuts import get_current_site
# from django.shortcuts import redirect
# from django.http import HttpResponsePermanentRedirect
# import os

from django.template.loader import get_template


class RegisterView(generics.GenericAPIView):

    serializer_class = RegisterSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])
        token = RefreshToken.for_user(user).access_token
        current_site = get_current_site(request).domain
        relativeLink = reverse('email-verify')

        absurl = 'http://'+current_site+relativeLink+"?token="+str(token)
        html_message = get_template('mail.html').render({'link': absurl, 'user':user.username})
        
        msg=EmailMessage()
        msg['Subject']='Email Verification'
        msg['From']=settings.EMAIL_HOST_USER
        msg['To']=user.email
        msg.add_alternative(html_message,subtype='html')
        server = smtplib.SMTP("mail.fintract.co.uk", 587)
        server.starttls()
        server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
        server.send_message(msg)
        server.quit()
            
        return Response(user_data, status=status.HTTP_201_CREATED)


class VerifyEmail(views.APIView):

    serializer_class = EmailVerificationSerializer

    def get(self, request):
        token = request.GET.get('token')
        # print(token)
        try:
            payload = jwt.decode(
                token, settings.SECRET_KEY, algorithms='HS256')

            user = User.objects.get(id=payload['user_id'])
            # print(user)
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response({'email': 'Successfully activated'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(generics.GenericAPIView):

    serializer_class=LoginSerializer

    def post(self, request):
        user=request.data
        serializer=self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])
        key=random.randint(100000,999999)

        user.otp=key
        no=user.id
        user.save()
        msg=EmailMessage()
        msg['Subject']='Login OTP'
        msg['From']=settings.EMAIL_HOST_USER
        msg['To']=user.email
        html_message = get_template('mail.html').render({'link': key, 'user':user.username})
        msg.add_alternative(html_message,subtype='html')
        server = smtplib.SMTP("mail.fintract.co.uk", 587)
        server.starttls()
        server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
        server.send_message(msg)
        server.quit()

        return Response({"id":user.id}, status=status.HTTP_200_OK)
    
class VerifyOTP(views.APIView):

    serializer_class=OTPVerificationSerializer
    def post(self, request, pk):
        otp=request.POST.get('otp')
        user = User.objects.get(id=pk)
          
        if otp == user.otp:
                user.is_loggedin = True
                user.save()
                return Response({'email': 'Successfully Logged In'}, status=status.HTTP_200_OK)
        else:
              return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
        