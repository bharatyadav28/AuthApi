from django.core.mail import send_mail
from rest_framework import serializers
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator

from .models import MyUser


class MyUserSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = MyUser
        fields = ['email', 'name', 'password', 'password2']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password doesn't match")
        return attrs

    def create(self, validated_data):
        user = MyUser.objects.create(
            email=validated_data['email'],
            name=validated_data['name'],
        )

        user.set_password(validated_data['password'])
        user.save()
        return user


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.CharField(max_length=50)

    class Meta:
        model = MyUser
        fields = ['email', 'password']


class PasswordChangeSerializer(serializers.Serializer):
    password = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['password', 'passsword1']

    def validate(self, attrs):
        password = attrs['password']
        password2 = attrs['password2']
        user = self.context['user']
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password doesnot match")
        return attrs

    def create(self, validated_data):
        user = self.context['user']
        user.set_password(validated_data['password'])
        user.save()
        return user


class PasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=50)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs['email']
        user = MyUser.objects.get(email=email)
        print("user object", user)
        if user is not None:
            # uid = urlsafe_base64_encode(force_bytes(user.id))
            # print("Encoded user id:",uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print("token:", token)
            link = 'http://127.0.0.1:8000/password-reset/' + str(user.id) + '/' + token
            print("Password reset link:", link)
            send_mail(
                'Welcome',
                "Click on the link to reset your password "+link,
                'bharatyadav032000@gmail.com',
                [user.email],
                fail_silently=False,
            )
        return attrs

class PasswordResetPageSerializer(serializers.Serializer):
    password = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['password', 'passsword1']

    def validate(self, attrs):
        password = attrs['password']
        password2 = attrs['password2']
        id = int(self.context['id'])
        token=self.context['token']
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password doesnot match")
        user = MyUser.objects.get(id=id)
        if not PasswordResetTokenGenerator().check_token(user,token):
            raise serializers.ValidationError("Invalid Url")
        user.set_password(password)
        user.save()
        return attrs

