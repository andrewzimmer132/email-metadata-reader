
from unittest.mock import patch
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

    @patch("analyzer.views.add_location_and_network_info")
    def test_home_includes_location_and_network(self, mock_enrich):
        mock_enrich.return_value = [
            {
                "server": "mail.example.com",
                "ip": "8.8.8.8",
                "location": {
                    "country": "United States",
                    "region": None,
                    "city": None,
                    "latitude": 37.751,
                    "longitude": -97.822,
                },
                "network": {
                    "asn": 15169,
                    "organization": "Google LLC",
                    "network": "8.8.8.0/24",
                },
            }
        ]

        header = (
            "From: sender@example.com\n"
            "Subject: Test email\n"
            "Received: from mail.example.com "
            "(mail.example.com [8.8.8.8]) by mx.example.net;\n"
        )

        response = self.client.post(
            reverse("home_view"),
            {"header": header},
        )

        self.assertEqual(response.status_code, 200)
        mock_enrich.assert_called_once()

        results = response.context["results"]
        hop = results["received"][0]

        self.assertEqual(
            hop["location"]["country"],
            "United States",
        )
        self.assertEqual(
            hop["network"]["asn"],
            15169,
        )



    def test_real_email_header_with_location_and_network(self):
        with open("analyzer/Tests/test_data/real_email.txt", "r") as file:
            raw_header = file.read()

        response = self.client.post(
            reverse("home_view"),
            {"header": raw_header},
        )

        self.assertEqual(response.status_code, 200)

        results = response.context["results"]

        print("\n--- Parsed Email Results ---")
        print("From:", results["from"])
        print("Date:", results["date"])

        print("\n--- Received Hops ---")
        for hop in results["received"]:
            print("Server:", hop.get("server"))
            print("IP:", hop.get("ip"))
            print("Location:", hop.get("location"))
            print("Network:", hop.get("network"))
            print("--------------------")

        self.assertTrue(len(results["received"]) > 0)
        self.assertIn("location", results["received"][0])
        self.assertIn("network", results["received"][0])








