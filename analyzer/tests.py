from django.test import TestCase

# Create your tests here.
class IP_ApiContainerTestCase(TestCase):
    def setUp(self):
        from analyzer.services import IpApiContainer
        self.container = IpApiContainer()

    def test_get_single_ip_info(self):
        ip_address = "8.8.8.8" # Google Public DNS
        result = self.container.get_single_ip_info(ip_address)
        self.assertEqual(result["query"], "8.8.8.8")
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["country"], "United States")
        self.assertAlmostEqual(result["lat"], 39.03, places=1)
        self.assertAlmostEqual(result["lon"], -77.5, places=1)
        self.assertEqual(result["isp"], "Google LLC")
