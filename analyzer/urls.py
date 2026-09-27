from django.urls import path
from .views import HomeView, LoginView, LogoutView, SignupView, ResultsView

urlpatterns = [
    path('home/', HomeView.as_view(), name='home_view'),
    path('', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('signup/', SignupView.as_view(), name='signup'),
    path('results/', ResultsView.as_view(), name='results'),
]
