from django.urls import path
from .views import HomeView, LoginView, LogoutView, SignupView

urlpatterns = [
    path('', HomeView.as_view(), name='home_view'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('signup/', SignupView.as_view(), name='signup')
]
