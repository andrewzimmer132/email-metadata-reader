from django.contrib.auth.models import User
from django.urls import reverse
from django.test import TestCase, Client

from analyzer.models import Email, LoginAttempt

from analyzer.spoofed_chars import find_spoof_characters


# Create your tests here.

#Model tests
class UserModelTest(TestCase):
    def setUp(self):
        self.test_user = User.objects.create_user(username='test_user', password='test', email='test1@uwm.edu')

    def test_str(self):
        self.assertEqual(str(self.test_user), 'test_user')

class EmailModelTest(TestCase):
    def setUp(self):
        self.test_email = Email.objects.create(email='test email')

    def test_str(self):
        self.assertEqual(str(self.test_email), 'test email')

class LoginAttemptModelTest(TestCase):
    def setUp(self):
        self.test_attempt = LoginAttempt.objects.create(username='test_user')

    def test_str(self):
        self.assertEqual(str(self.test_attempt), 'test_user')

#View tests
class LoginViewTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.url = reverse('login')
        self.test_user = User.objects.create_user(username='test_user2', password='test', email='test2@uwm.edu')

    def test_login_get(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'analyzer/login.html')

    def test_login_post(self):
        response = self.client.post(self.url, {'username': 'test_user2', 'password': 'test'})
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('home_view'))
        response = self.client.get(reverse('home_view'))
        self.assertTrue(response.wsgi_request.user.is_authenticated)

    def test_login_invalid_post(self):
        response = self.client.post(self.url, {'username': 'test_user2', 'password': 'incorrect'})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'analyzer/login.html')
        self.assertFalse(response.wsgi_request.user.is_authenticated)

class FindSpoofCharactersTests(TestCase):
    """python manage.py test analyzer.tests.FindSpoofCharactersTests"""
    def test_clean_ascii_text_returns_empty(self):
        self.assertEqual(find_spoof_characters("Amazon Support"), [])

    def test_accented_character_is_flagged(self):
        flags = find_spoof_characters("Amazón")
        self.assertEqual(len(flags), 1)
        self.assertEqual(flags[0]["char"], "ó")