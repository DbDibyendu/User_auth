
from rest_framework import serializers
from .models import User
from django.contrib import auth
# from rest_framework.exceptions import AuthenticationFailed
# from rest_framework_simplejwt.tokens import RefreshToken, TokenError
# from django.contrib.auth.tokens import PasswordResetTokenGenerator
# from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
# from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    password2 = serializers.CharField(max_length=68, min_length=6, write_only=True)

    default_error_messages = {
        'username': 'The username should only contain alphanumeric characters'}

    class Meta:
        model = User
        fields = ['email', 'username', 'password','password2']

    def validate(self, attrs):
        email = attrs.get('email', '')
        username = attrs.get('username', '')
        password=attrs.get('password','')
        password2=attrs.get('password2','')

        if password != password2:
            raise serializers.ValidationError("Passwords should be same")
        if not username.isalnum():
            raise serializers.ValidationError(self.default_error_messages)
        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ['token']