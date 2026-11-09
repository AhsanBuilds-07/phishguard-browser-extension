"""
SentinelAI Phishing & Scam Link Shield
Multi-Signal Detection Engine Automated Test Suite

Tests:
1. Brand impersonation & typosquatting detection.
2. Homoglyph and Punycode spoofing detection.
3. DOM credential security signals (form action destinations).
4. Multi-signal composite verdict scoring and attack chain formulation.
5. Calibrated confidence and unverified signals transparency.
"""

import json
import os
import subprocess
import unittest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DETECTOR_PATH = os.path.join(ROOT_DIR, "ml", "detector.js")


class TestMultiSignalDetector(unittest.TestCase):

    def run_node_detector(self, js_eval_code: str):
        full_code = f"""
        const detector = require('{DETECTOR_PATH}');
        {js_eval_code}
        """
        res = subprocess.run(
            ["node", "-e", full_code],
            capture_output=True,
            text=True,
            check=True
        )
        return json.loads(res.stdout.strip())

    def test_brand_subdomain_impersonation(self):
        js = """
        const res = detector.detectBrandImpersonation(
            'http://paypal.com.verify-user-account.xyz/login.php',
            'paypal.com.verify-user-account.xyz'
        );
        console.log(JSON.stringify(res));
        """
        res = self.run_node_detector(js)
        self.assertTrue(res["isImpersonating"])
        self.assertEqual(res["matchedBrand"], "PayPal")
        self.assertTrue(any(f["type"] == "BRAND_SUBDOMAIN_MISMATCH" for f in res["findings"]))

    def test_brand_typosquatting(self):
        js = """
        const res = detector.detectBrandImpersonation(
            'http://paypa1.com/auth',
            'paypa1.com'
        );
        console.log(JSON.stringify(res));
        """
        res = self.run_node_detector(js)
        self.assertTrue(res["isImpersonating"])
        self.assertEqual(res["matchedBrand"], "PayPal")
        self.assertTrue(any(f["type"] == "BRAND_TYPOSQUATTING" for f in res["findings"]))

    def test_canonical_brand_domain_allowed(self):
        js = """
        const res = detector.detectBrandImpersonation(
            'https://accounts.google.com/signin/v2/identifier',
            'accounts.google.com'
        );
        console.log(JSON.stringify(res));
        """
        res = self.run_node_detector(js)
        self.assertFalse(res["isImpersonating"])
        self.assertIsNone(res["matchedBrand"])

    def test_punycode_and_homoglyphs(self):
        js = """
        const res = detector.detectHomoglyphs('xn--pypal-4ve.com');
        console.log(JSON.stringify(res));
        """
        res = self.run_node_detector(js)
        self.assertTrue(res["isPunycode"])
        self.assertTrue(res["hasHomoglyphs"])

    def test_dom_password_to_raw_ip(self):
        js = """
        const domSignals = {
            formCount: 1,
            passwordInputCount: 1,
            insecureForms: 0,
            ipFormDestinations: ['188.214.104.180'],
            crossOriginFormDestinations: []
        };
        const res = detector.evaluateDomSafety(domSignals, 'login-portal.com');
        console.log(JSON.stringify(res));
        """
        res = self.run_node_detector(js)
        self.assertTrue(any(f["type"] == "PASSWORD_TO_IP_DESTINATION" for f in res["findings"]))
        self.assertTrue(res["hasSensitiveInputs"])

    def test_composite_verdict_malicious_phishing(self):
        js = """
        const res = detector.evaluateUrlSignals({
            url: 'http://paypal.com.verify-account.xyz/login.php',
            hostname: 'paypal.com.verify-account.xyz',
            features: new Array(14).fill(0),
            mlProbabilities: [0.05, 0.95],
            lexicalFlags: ['Unencrypted HTTP', 'High-abuse TLD .xyz'],
            domSignals: { formCount: 1, passwordInputCount: 1, insecureForms: 1 }
        });
        console.log(JSON.stringify(res));
        """
        res = self.run_node_detector(js)
        self.assertEqual(res["verdict"], "malicious")
        self.assertGreaterEqual(res["riskScore"], 0.75)
        self.assertGreaterEqual(res["confidence"], 0.85)
        self.assertEqual(res["brandMatch"], "PayPal")
        self.assertTrue(len(res["attackChain"]["observedFacts"]) >= 2)
        self.assertIn("signalsNotChecked", res)
        self.assertIn("scamCoachTip", res)

    def test_composite_verdict_benign_site(self):
        js = """
        const res = detector.evaluateUrlSignals({
            url: 'https://en.wikipedia.org/wiki/Computer_security',
            hostname: 'en.wikipedia.org',
            features: new Array(14).fill(0),
            mlProbabilities: [0.99, 0.01],
            lexicalFlags: []
        });
        console.log(JSON.stringify(res));
        """
        res = self.run_node_detector(js)
        self.assertEqual(res["verdict"], "safe")
        self.assertLess(res["riskScore"], 0.20)
        self.assertGreaterEqual(res["confidence"], 0.70)


if __name__ == "__main__":
    unittest.main()
