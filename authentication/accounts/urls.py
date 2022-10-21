from django.urls import path

from . import views

urlpatterns = [
    path('signup/', views.signup.as_view()),
    path('login/', views.login.as_view()),
    path('profile/', views.profile.as_view()),
    path('passwordchange/', views.PasswordChange.as_view()),
    path('password-reset-email/', views.PasswordResetEmail.as_view()),
    path('password-reset/<int:uid>/<token>/', views.PasswordResetPage.as_view()),
]
