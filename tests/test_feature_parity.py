"""
SentinelAI Phishing & Scam Link Shield
Feature Parity Unit Test Suite

Verifies 100% mathematical and positional equivalence between
Python (ml/features.py) and JavaScript (ml/features.js).
"""

import json
import os
import subprocess
import sys
import unittest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from ml.features import extract_features, FEATURE_NAMES

TEST_CASES = [
    "https://www.google.com/search?q=cybersecurity",
    "https://mail.corp.service.google.com/inbox",
    "http://192.168.1.100/paypal/login.php?cmd=login&auth=verify",
    "http://security@amazon.account-update.xyz/signin.htm",
    "https://secure-banking-alert.top/verify/account",
    "https://example.com/redirect//evil.com/path",
    "https://x7k9p2m4q8z1.biz/auth/login",
    "http://portal.org/page.php?id=123&token=abc&user=test&session=xyz",
    "http://bank-account.info/verify.cgi?a=1%20&b=2~_",
    "http://localhost:8080/demo.html",
    "http://[2001:4860:4860::8888]/login",
    "https://example.com/sign-in/confirmation/support-help",
    "https://example.com/signin/verify"
]


class TestFeatureParity(unittest.TestCase):

    def run_node_extraction(self, url: str):
        js_script = f"""
        const features = require('{os.path.join(ROOT_DIR, "ml", "features.js")}');
        const vec = features.extractFeatures({json.dumps(url)});
        console.log(JSON.stringify(vec));
        """
        res = subprocess.run(
            ["node", "-e", js_script],
            capture_output=True,
            text=True,
            check=True
        )
        return json.loads(res.stdout.strip())

    def test_all_cases_parity(self):
        print("\n--- Running Feature Parity Tests across Python & JavaScript ---")
        for i, url in enumerate(TEST_CASES):
            py_vec = extract_features(url)
            js_vec = self.run_node_extraction(url)

            self.assertEqual(
                len(py_vec), 14,
                f"Python vector length is {len(py_vec)} for URL: {url}"
            )
            self.assertEqual(
                len(js_vec), 14,
                f"JavaScript vector length is {len(js_vec)} for URL: {url}"
            )

            for feat_idx in range(14):
                feat_name = FEATURE_NAMES[feat_idx]
                py_val = py_vec[feat_idx]
                js_val = js_vec[feat_idx]

                if feat_name == "domain_entropy":
                    self.assertAlmostEqual(
                        py_val, js_val, places=3,
                        msg=f"Entropy mismatch for [{feat_name}] on {url}: Py={py_val}, JS={js_val}"
                    )
                else:
                    self.assertEqual(
                        py_val, js_val,
                        msg=f"Value mismatch for [{feat_name}] (index {feat_idx}) on {url}: Py={py_val}, JS={js_val}"
                    )

            print(f"  [PASS] Case {i+1:02d}: {url[:60]}")

        print("--- All Feature Parity Tests Passed Successfully! ---\n")


if __name__ == "__main__":
    unittest.main()
