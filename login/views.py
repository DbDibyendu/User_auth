from django.core.mail.message import EmailMessage
from django.shortcuts import render
from rest_framework import generics, serializers, status, views, permissions
from .serializers import RegisterSerializer, EmailVerificationSerializer, LoginSerializer,OTPVerificationSerializer, ResetPasswordEmailSerializer
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.conf import settings
import random, string, smtplib, jwt
from email.message import EmailMessage
from django.template.loader import get_template


# asinghrajput.che18@itbhu.ac.in   these are examples of restricted mails
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
        html_message = get_template('email.html').render({'link': absurl, 'user':user.username,'email':user.email})
        
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
        # current_minute = timezone.now().minute
        # if current_minute > 1:
        #     user.otp=None
        #     user.save()
        #     return Response({'error': 'Sesssion Expired, Login again'}, status=status.HTTP_400_BAD_REQUEST)
        if otp == user.otp:
                user.is_loggedin = True
                user.otp=0
                user.save()
                return Response({'email': 'Successfully Logged In'}, status=status.HTTP_200_OK)
        else:
              return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

class LogoutAPIView(views.APIView):

    def get(self,request, pk):
        user = User.objects.get(id=pk)
          
        if user.is_loggedin == True:
                user.is_loggedin = False
                user.save()
                return Response({'email': 'Successfully Looged Out'}, status=status.HTTP_200_OK)
        else:
              return Response({'error': 'Failed, Please try again'}, status=status.HTTP_400_BAD_REQUEST)

class ResetPassword(generics.GenericAPIView):

    serializer_class=ResetPasswordEmailSerializer

    def post(self, request):
        user_mail=request.POST.get('email')
        try:
            user = User.objects.get(email=user_mail)
        except User.DoesNotExist:
            user = None

        if not user:
            return Response({'error':'Invalid credentials, try again'}, status=status.HTTP_400_BAD_REQUEST)
        if not user.is_active:
            return Response({'error':'Account Dissabled, contact admin'}, status=status.HTTP_400_BAD_REQUEST)
        if not user.is_verified:
            return Response({'error':'Email is not Verified, Create a new account'}, status=status.HTTP_400_BAD_REQUEST)

        N = 8
        # using random.choices()
        # generating random strings 
        res = ''.join(random.choices(string.ascii_uppercase + string.digits, k = N))
        password=str(res)
        user.set_password(password)
        user.save()
        msg=EmailMessage()
        msg['Subject']='Login OTP'
        msg['From']=settings.EMAIL_HOST_USER
        msg['To']=user.email
        html_message = get_template('mail.html').render({'link': password, 'user':user.username})
        msg.add_alternative(html_message,subtype='html')
        server = smtplib.SMTP("mail.fintract.co.uk", 587)
        server.starttls()
        server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
        server.send_message(msg)
        server.quit()

        return Response({'password': 'Successfully Changed'}, status=status.HTTP_200_OK)