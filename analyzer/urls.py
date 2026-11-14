from django.urls import path

from . import views
from .views import HomeView, LoginView, LogoutView, SignupView, ResultsView, PastEmailsAnalyzedView, \
    DeleteEmailAnalyzedView, EmailResultsView, WelcomePageView, header_help_view, reminder_view

urlpatterns = [
    path('home/', HomeView.as_view(), name='home_view'),
    path('', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('signup/', SignupView.as_view(), name='signup'),
    path('results/', ResultsView.as_view(), name='results'),
    path('past-emails/', PastEmailsAnalyzedView.as_view(), name='past_emails'),
    path('past-emails/<int:email_id>/', EmailResultsView.as_view(), name='email_results'),
    path('past-emails/<int:email_id>/delete/', DeleteEmailAnalyzedView.as_view(), name='delete_email'),
    path('welcome/', WelcomePageView.as_view(), name='welcome'),
    path('compare_emails/', views.compare_emails, name='compare_emails'),
    path('welcome/', WelcomePageView.as_view(), name='welcome'),
    path("header-help/", header_help_view, name="Gmail_header_help"),
    path('set-reminder/', reminder_view, name='reminder_view'),
    path("header-help/", header_help_view, name="header_help"),
]
