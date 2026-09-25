from django.test import TestCase

from analyzer.parser import analyze_header


class ParserTests(TestCase):

    def test_basic_headers(self):
        raw_header = """\
From: bob1@example.com
To: bob2@example.com
Subject: Test Email
Date: Mon, 21 Sep 2026 12:00:00 -0500
Return-Path: <bounce@example.com>
Message-ID: <12345@example.com>
"""

        results = analyze_header(raw_header)

        self.assertEqual(results["from"], "bob1@example.com")
        self.assertEqual(results["to"], "bob2@example.com")
        self.assertEqual(results["subject"], "Test Email")
        self.assertEqual(results["date"], "Mon, 21 Sep 2026 12:00:00 -0500")
        self.assertEqual(results["return_path"], "<bounce@example.com>")
        self.assertEqual(results["message_id"], "<12345@example.com>")


    def test_multiple_received_headers(self):
        raw_header = """\
From: bob@example.com
Received: from server1.example.com
Received: from server2.example.com
Received: from server3.example.com
"""

        results = analyze_header(raw_header)

        self.assertEqual(len(results["received"]), 3)


    def test_authentication_results(self):
        raw_header = """\
From: bob@example.com
Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass
"""

        results = analyze_header(raw_header)

        self.assertEqual(len(results["authentication"]), 1)
        self.assertIn("spf=pass", results["authentication"][0])
        self.assertIn("dkim=pass", results["authentication"][0])
        self.assertIn("dmarc=pass", results["authentication"][0])


    def test_missing_headers(self):
        raw_header = """\
From: bob@example.com
Subject: Test
"""

        results = analyze_header(raw_header)

        self.assertEqual(results["from"], "bob@example.com")
        self.assertEqual(results["subject"], "Test")

        self.assertIsNone(results["to"])
        self.assertIsNone(results["return_path"])
        self.assertIsNone(results["message_id"])
        self.assertEqual(results["received"], [])
        self.assertEqual(results["authentication"], [])

    def test_received_parentheses_and_ipv6(self):
        raw_header = """\
Received: from mail.example.com (54.240.38.187) by outlook.example.com
Received: from server.example.com (2603:10b6:303:18e::16) by outlook.example.com
"""

        results = analyze_header(raw_header)

        self.assertEqual(results["received"][0]["server"], "mail.example.com")
        self.assertEqual(results["received"][0]["ip"], "54.240.38.187")

        self.assertEqual(results["received"][1]["server"], "server.example.com")
        self.assertEqual(results["received"][1]["ip"], "2603:10b6:303:18e::16")

#testing received

    def test_received_server_and_ip(self):
        raw_header = """\
Received: from mail.example.com (mail.example.com [123.45.67.89])
"""

        results = analyze_header(raw_header)

        self.assertEqual(results["received"][0]["server"], "mail.example.com")
        self.assertEqual(results["received"][0]["ip"], "123.45.67.89")

    def test_multiple_received_server_and_ip(self):
        raw_header = """\
Received: from server1.example.com [123.45.67.89]
Received: from server2.example.com [98.76.54.32]
"""

        results = analyze_header(raw_header)

        self.assertEqual(len(results["received"]), 2)

        self.assertEqual(results["received"][0]["server"], "server1.example.com")
        self.assertEqual(results["received"][0]["ip"], "123.45.67.89")

        self.assertEqual(results["received"][1]["server"], "server2.example.com")
        self.assertEqual(results["received"][1]["ip"], "98.76.54.32")



    def test_real_email_header(self):
        with open("analyzer/Tests/test_data/real_email.txt", "r") as file:
            raw_header = file.read()

        results = analyze_header(raw_header)
        #un-comment print line to see how this email's data in tests
        #print(results)

        self.assertIsNotNone(results["from"])
        self.assertIsNotNone(results["date"])