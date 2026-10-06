from django.urls import path
from .views import HomeView, LoginView, LogoutView, SignupView, ResultsView, PastEmailsAnalyzedView, \
    DeleteEmailAnalyzedView, EmailResultsView

urlpatterns = [
    path('home/', HomeView.as_view(), name='home_view'),
    path('', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('signup/', SignupView.as_view(), name='signup'),
    path('results/', ResultsView.as_view(), name='results'),
    path('past-emails/', PastEmailsAnalyzedView.as_view(), name='past_emails'),
    path('past-emails/<int:email_id>/', EmailResultsView.as_view(), name='email_results'),
    path('past-emails/<int:email_id>/delete/', DeleteEmailAnalyzedView.as_view(), name='delete_email'),
]
