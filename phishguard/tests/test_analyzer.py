import unittest
from phishguard.analyzer import PhishGuardAnalyzer

class TestPhishGuardAnalyzer(unittest.TestCase):
    def test_safe_url(self):
        analyzer = PhishGuardAnalyzer("https://www.google.com")
        report = analyzer.analyze()
        self.assertEqual(report['risk_level'], "Low")
        self.assertLess(report['risk_score'], 25)

    def test_ip_address_url(self):
        analyzer = PhishGuardAnalyzer("http://192.168.1.1/login.php")
        report = analyzer.analyze()
        self.assertTrue(any(f['check'] == "IP Address Usage" for f in report['findings']))
        self.assertGreaterEqual(report['risk_score'], 30)

    def test_typosquatting_url(self):
        analyzer = PhishGuardAnalyzer("https://paypal-secure-login.com/verify")
        report = analyzer.analyze()
        self.assertTrue(any(f['check'] == "Typosquatting / Brand Imitation" for f in report['findings']))
        self.assertGreaterEqual(report['risk_score'], 40)

    def test_obfuscation_at_symbol(self):
        analyzer = PhishGuardAnalyzer("http://legitimate.com@evil.com/signin")
        report = analyzer.analyze()
        self.assertTrue(any(f['check'] == "Credential Spoofing (@ symbol)" for f in report['findings']))

if __name__ == '__main__':
    unittest.main()
