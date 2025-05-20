from django.urls import path
from .views import (
    RegisterView, 
    LoginView, 
    LogoutView, 
    DeleteAccountView, 
    GetUserByIDView, 
    UpdateProfileUser, 
    GetMe
)
# from .auth_views import PasswordResetView, PasswordResetConfirmView
from .views import CustomTokenRefreshView

urlpatterns = [
    # User Authentication
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),

    # User Account & Profile
    path('me/', GetMe.as_view(), name='me'),
    path('delete/', DeleteAccountView.as_view(), name='delete_account'),
    path('user/<int:user_id>/', GetUserByIDView.as_view(), name='get_user_by_id'),
    path('updateProfileUser/<int:user_id>/', UpdateProfileUser.as_view(), name='update_profile_user'),

    # Password Reset
    # path('reset-password/', PasswordResetView.as_view(), name='password_reset'),
    # path('reset/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
]
