from django.test import TestCase
from analyzer.parser import analyze_header
from analyzer.geolocation import lookup_ip


class GeolocationTests(TestCase):

    def test_lookup_ip(self):
        result = lookup_ip("8.8.8.8")

        """
        print("Country:", result["country"])
        print("Region:", result["region"])
        print("City:", result["city"])
        print("Latitude:", result["latitude"])
        print("Longitude:", result["longitude"])
        """

        self.assertIsNotNone(result)
        self.assertIsNotNone(result["country"])
        self.assertIsNotNone(result["latitude"])
        self.assertIsNotNone(result["longitude"])


    def test_real_email_header(self):
        with open("analyzer/Tests/test_data/real_email.txt", "r") as file:
            raw_header = file.read()

        results = analyze_header(raw_header)

        for hop in results["received"]:
            ip = hop["ip"]

            if ip:
                location = lookup_ip(ip)

                print("\nServer:", hop["server"])
                print("IP:", ip)

                
                if location:
                    print("Country:", location["country"])
                    print("Region:", location["region"])
                    print("City:", location["city"])
                    print("Latitude:", location["latitude"])
                    print("Longitude:", location["longitude"])
                else:
                    print("Location: Not found")


    def test_region_city(self):
        result = lookup_ip("128.101.101.101")
        print()
        print("test3  for region and city")
        print("Country:", result["country"])
        print("Region:", result["region"])
        print("City:", result["city"])
        print("Latitude:", result["latitude"])
        print("Longitude:", result["longitude"])