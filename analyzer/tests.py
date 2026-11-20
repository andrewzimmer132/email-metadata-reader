from email import policy

from django.contrib.auth.models import User
from django.template.context_processors import request
from django.urls import reverse
from django.test import TestCase, Client

from analyzer.models import Email, LoginAttempt, EmailReminder
from analyzer.parser import analyze_body
from email.parser import Parser

from analyzer.spoofed_chars import find_spoof_characters
from zoneinfo import ZoneInfo
from datetime import datetime
from analyzer.views import email_similarity, compare_email_text


# Create your tests here.

#Model tests
class UserModelTest(TestCase):
    def setUp(self):
        self.test_user = User.objects.create_user(username='test_user', password='test', email='test1@uwm.edu')

    def test_str(self):
        self.assertEqual(str(self.test_user), 'test_user')

class EmailModelTest(TestCase):
    def setUp(self):
        self.test_email = Email.objects.create(header='test header', body='test email')

    def test_str(self):
        self.assertEqual(str(self.test_email), 'test email')

    def test_compare(self):
        """python manage.py test analyzer.tests.EmailModelTest.test_compare"""
        other_email = Email.objects.create(header='test', body='test email')
        differences = self.test_email.compare(other_email)
        self.assertEqual(differences, [])

    def test_compare_differences(self):
        """python manage.py test analyzer.tests.EmailModelTest.test_compare_differences"""
        other_email = Email.objects.create(header='different', body='different email', status='safe')
        differences = self.test_email.compare(other_email)
        expected_differences = [
            {'field': 'body', 'current': 'test email', 'other': 'different email'},
            {'field': 'status', 'current': 'pending', 'other': 'safe'}
        ]
        self.assertEqual(differences, expected_differences)

class LoginAttemptModelTest(TestCase):
    def setUp(self):
        self.test_attempt = LoginAttempt.objects.create(username='test_user')

    def test_str(self):
        self.assertEqual(str(self.test_attempt), 'test_user')

    def test_failed_login(self):
        self.test_attempt.failures = 3
        response = self.client.post(reverse('login'), {'username': 'test_user', 'password': 'test'})
        self.assertTemplateUsed(response, 'analyzer/login.html')
        self.assertFalse(response.wsgi_request.user.is_authenticated)

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
        self.assertRedirects(response, reverse('welcome'))
        response = self.client.get(reverse('welcome'))
        self.assertTrue(response.wsgi_request.user.is_authenticated)

    def test_login_invalid_post(self):
        response = self.client.post(self.url, {'username': 'test_user2', 'password': 'incorrect'})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'analyzer/login.html')
        self.assertFalse(response.wsgi_request.user.is_authenticated)

class ResultsViewTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.email = Email.objects.create(body='This is a test email', status='pending')
        self.email2 = Email.objects.create(body='This is a test email', status='safe')
        self.email3 = Email.objects.create(body='This is a test email', status='unsafe')
        self.email4 = Email.objects.create(body='This is a test email', status='spam/scam')

    def test_pending_email(self):
        response = self.client.get(reverse('results'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'analyzer/results.html')
        self.assertTrue(self.email.status == 'pending')

    def test_safe_email(self):
        response = self.client.get(reverse('results'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'analyzer/results.html')
        self.assertTrue(self.email2.status == 'safe')

    def test_unsafe_email(self):
        response = self.client.get(reverse('results'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'analyzer/results.html')
        self.assertTrue(self.email3.status == 'unsafe')

    def test_spam_email(self):
        response = self.client.get(reverse('results'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'analyzer/results.html')
        self.assertTrue(self.email4.status == 'spam/scam')

class PastEmailsAnalyzedViewTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.email = Email.objects.create(body='This is a test email', status='pending')

    def test_past_emails(self):
        response = self.client.get(reverse('past_emails'))
        self.assertEqual(response.status_code, 302)

class ResetPasswordViewTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='test_user', email='test_user@uwm.edu', password='old_password')

    def test_reset_password_get(self):
        response = self.client.get(reverse('reset_password'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'analyzer/reset_password.html')

    def test_reset_password_post(self):
        response = self.client.post(reverse('reset_password'), {'username': 'test_user', 'email': 'test_user@uwm.edu','new_password': 'new_password', 'confirm_new_password': 'new_password'})
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('login'))
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('new_password'))

    def invalid_reset_password_post(self):
        response = self.client.post(reverse('reset_password'), {'username': 'test_user', 'email': 'test_user@uwm.edu', 'new_password': 'new_password', 'confirm_new_password': 'old_password'})
        self.assertEqual(response.status_code, 302)
        self.assertTemplateUsed(response, 'analyzer/reset_password.html')
        self.user.refresh_from_db()
        self.assertFalse(self.user.check_password('new_password'))

        response = self.client.post(reverse('reset_password'), {'username': 'incorrect', 'email': 'test_user@uwm.edu', 'new_password': 'new_password', 'confirm_new_password': 'new_password'})
        self.assertEqual(response.status_code, 302)
        self.assertTemplateUsed(response, 'analyzer/reset_password.html')
        self.user.refresh_from_db()
        self.assertFalse(self.user.check_password('new_password'))

        response = self.client.post(reverse('reset_password'), {'username': 'test_user', 'email': 'incorrect', 'new_password': 'new_password', 'confirm_new_password': 'new_password'})
        self.assertEqual(response.status_code, 302)
        self.assertTemplateUsed(response, 'analyzer/reset_password.html')
        self.user.refresh_from_db()
        self.assertFalse(self.user.check_password('new_password'))

class ParserEmailBodyTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.email = Email.objects.create(header='test header', body='Click on the link https://www.google.com')

    def test_found_url(self):
        results = analyze_body(self.email.body)
        self.assertTrue(any(result['match'] == 'https://www.google.com' for result in results))

class FindSpoofCharactersTests(TestCase):
    """python manage.py test analyzer.tests.FindSpoofCharactersTests"""
    def test_clean_ascii_text_returns_empty(self):
        self.assertEqual(find_spoof_characters("Amazon Support"), [])

    def test_accented_character_is_flagged(self):
        flags = find_spoof_characters("Amazón")
        self.assertEqual(len(flags), 1)
        self.assertEqual(flags[0]["char"], "ó")

    def test_spoof_m_is_flagged(self):
        flags = find_spoof_characters(".corn")
        self.assertEqual(len(flags), 2)
        self.assertEqual(flags[0]["char"], "r")
        self.assertEqual(flags[1]["char"], "n")

    def test_spoof_l_is_flagged(self):
        flags = find_spoof_characters("f1agged")
        self.assertEqual(len(flags), 1)
        self.assertEqual(flags[0]["char"], "1")
        flags = find_spoof_characters("fIagged")
        self.assertEqual(len(flags), 1)
        self.assertEqual(flags[0]["char"], "I")

    def test_spoof_o_is_flagged(self):
        flags = find_spoof_characters("w0rd")
        self.assertEqual(len(flags), 1)
        self.assertEqual(flags[0]["char"], "0")


class ReminderViewTests(TestCase):
    #Unit tests included here
    def test_model_creation_and_defaults(self):
        dt = datetime(2026, 12, 25, 10, 0, tzinfo=ZoneInfo("UTC"))
        reminder = EmailReminder.objects.create(
            email="test@example.com",
            timezone="US/Eastern",
            remind_at=dt,
            message="Holiday check-in"
        )
        self.assertEqual(str(reminder), "test@example.com")
        self.assertFalse(reminder.sent)

    def test_timezone_conversion_to_utc(self):
        local_dt = datetime(2026, 11, 14, 12, 0).replace(tzinfo=ZoneInfo("US/Central"))
        utc_dt = local_dt.astimezone(ZoneInfo("UTC"))

        self.assertEqual(utc_dt.hour, 18)
        self.assertEqual(utc_dt.tzinfo, ZoneInfo("UTC"))

    #Acceptance or end-to-end tests included here
    def setUp(self):
        self.client = Client()
        self.url = reverse("reminder_view")

    def test_get_reminder_page(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "analyzer/reminder.html")
        self.assertContains(response, "Meta-Data Reminder")
        self.assertContains(response, 'name="remind_at"')

    def test_submit_optional_empty_message(self):
        form_data = {
            "email": "user@example.com",
            "timezone": "US/Eastern",
            "remind_at": "2026-11-20T09:00",
            "message": ""
        }
        self.client.post(self.url, data=form_data)
        self.assertEqual(EmailReminder.objects.count(), 1)
        self.assertEqual(EmailReminder.objects.first().message, "")
class CompareEmailsTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='test_user3', password='test_password')
        self.email = Email.objects.create(header='email1', body='This is a test email', status='safe', user=self.user)
        self.email2 = Email.objects.create(header='email2', body='This is another test email', status='unsafe', user=self.user)
        self.email3 = Email.objects.create(header='email3', body='Singular email', status='unsafe', user=self.user)
        self.compare_url = reverse('compare_emails')
        self.past_emails_url = reverse('past_emails')

    def test_compare_emails(self):
        self.client.login(username='test_user3', password='test_password')
        email_ids = [self.email.pk, self.email2.pk]
        response = self.client.post(self.compare_url, {'email_ids': email_ids})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'analyzer/compare_emails.html')

    def test_compare_one_email(self):
        self.client.login(username='test_user3', password='test_password')
        email_ids = [self.email3.pk]
        response = self.client.post(self.compare_url, {'email_ids': email_ids})
        self.assertEqual(response.status_code, 302)

    def test_email_differences(self):
        self.client.login(username='test_user3', password='')
        ratio = email_similarity(self.email, self.email2)
        self.assertTrue(ratio < 100, ratio > 0)
        email1_lines, email2_lines = compare_email_text(self.email, self.email2)
        self.assertEqual(len(email1_lines), len(email2_lines))
