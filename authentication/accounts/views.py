from django.core.mail import send_mail
from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import (MyUserSerializer, LoginSerializer, PasswordChangeSerializer,
                          PasswordResetEmailSerializer, PasswordResetPageSerializer
                          )


# Create your views here.
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class signup(APIView):
    def post(self, request):
        serializer = MyUserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            send_mail(
                'Welcome',
                'SignUp successfull.',
                'bharatyadav032000@gmail.com',
                [serializer.data['email']],
                fail_silently=False,
            )
            return Response({"msg": "SignUp Successfull"})
        return Response(serializer.errors)


class login(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data['email']
        password = serializer.data['password']
        user = authenticate(email=email, password=password)
        if user is not None:
            token = get_tokens_for_user(user)
            return Response({"msg": "Login Successfull", "token": token})
        return Response({"msg": "wrong username or password"})


class profile(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response("Hello, Welcome to our site")

class PasswordChange(APIView):
    permission_classes = [IsAuthenticated]

    def post(self,request):
        serializer=PasswordChangeSerializer(data=request.data,context={'user':request.user})
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({'msg':'Password Changed Successfully'})
        return Response(serializer.errors)

class PasswordResetEmail(APIView):

    def post(self,request):
        serializer=PasswordResetEmailSerializer(data=request.data,context={'user':request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'Password Reset mail sent to your registered email id'})
        return Response(serializer.errors)

class PasswordResetPage(APIView):
    def post(self, request, uid, token, format=None):
        id=uid
        serializer=PasswordResetPageSerializer(data=request.data,context={'id':id,'token':token})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'Password Reset successfull'})
        return Response(serializer.errors)





