from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.models import User


class HomeViewTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username="testuser",
            password="testpassword"
        )
        self.client.login(
            username="testuser",
            password="testpassword"
        )

    def test_header_is_analyzed(self):
        raw_header = """\
From: bob@example.com
Subject: Test Email
"""

        response = self.client.post(
            reverse("home_view"),
            {"header": raw_header}
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.context["results"]["from"],
            "bob@example.com"
        )
        self.assertEqual(
            response.context["results"]["subject"],
            "Test Email"
        )
    def test_real_email_header(self):
        with open("analyzer/Tests/test_data/real_email.txt", "r") as file:
            raw_header = file.read()

        response = self.client.post(
            reverse("home_view"),
            {"header": raw_header}
        )

        self.assertEqual(response.status_code, 200)

        results = response.context["results"]

        #print(results)

        self.assertIsNotNone(results["from"])
        self.assertIsNotNone(results["date"])