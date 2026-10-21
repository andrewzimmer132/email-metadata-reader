from django.test import TestCase
from analyzer.parser import analyze_header
from analyzer.geolocation import lookup_ip, lookup_asn


class GeoIPTests(TestCase):

    def test_city_lookup(self):
        result = lookup_ip("8.8.8.8")

        self.assertIsNotNone(result)
        self.assertEqual(result["country"], "United States")

    def test_asn_lookup(self):
        result = lookup_asn("8.8.8.8")

        self.assertIsNotNone(result)
        self.assertEqual(result["asn"], 15169)
        self.assertTrue(result["organization"])

    def test_city_ip_not_found(self):
        # Reserved documentation address
        result = lookup_ip("192.0.2.1")

        self.assertIsNone(result)

    def test_asn_ip_not_found(self):
        # Reserved documentation address
        result = lookup_asn("192.0.2.1")

        self.assertIsNone(result)

    def test_print_google_ip(self):
        city_result = lookup_ip("8.8.8.8")
        asn_result = lookup_asn("8.8.8.8")

        print("\n=== City Lookup: 8.8.8.8 ===")
        print(city_result)

        print("\n=== ASN Lookup: 8.8.8.8 ===")
        print(asn_result)

class EmailASNTests(TestCase):

    def test_real_email_asn(self):
        with open(
            "analyzer/Tests/test_data/real_email.txt",
            "r",
            encoding="utf-8"
        ) as file:
            raw_header = file.read()

        results = analyze_header(raw_header)

        print("\n=== EMAIL RECEIVED HOPS ===")

        for hop in results["received"]:
            ip = hop.get("ip")

            print(f"\nServer: {hop.get('server')}")
            print(f"IP: {ip}")

            if ip:
                print(f"Location: {lookup_ip(ip)}")
                print(f"ASN: {lookup_asn(ip)}")
            else:
                print("No IP address found for this hop.")