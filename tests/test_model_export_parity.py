"""
SentinelAI Phishing & Scam Link Shield
Model Export Parity & Prediction Verification Test

Verifies:
1. The exported JavaScript model (ml/models/model_exported.js) loads and executes cleanly in Node.js.
2. The JavaScript model receives the exact canonical 14-feature order matching Python.
3. Node.js prediction probabilities match Python Scikit-Learn RandomForest probabilities within a tolerance of < 1e-3.
"""

import json
import os
import subprocess
import sys
import unittest

import joblib
import numpy as np

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from ml.features import extract_features, FEATURE_NAMES

JOBLIB_PATH = os.path.join(ROOT_DIR, "ml", "models", "phishing_rf.joblib")
EXPORTED_JS_PATH = os.path.join(ROOT_DIR, "ml", "models", "model_exported.js")

VERIFICATION_URLS = [
    # Benign URLs
    "https://www.google.com/search?q=cybersecurity",
    "https://github.com/torvalds/linux",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://aws.amazon.com/console/",
    "https://aboutamazon.com/news/retail",
    # Phishing / Malicious URLs
    "http://188.214.104.180/online/atb/5f54443b9c0f/login.php",
    "http://134.209.118.49/banks/td/step1.html",
    "http://security-paypal-login-account-update.xyz/signin.htm",
    "http://apple-support-recover-locked-id.top/auth/verify",
    "http://192.119.66.93/cra/finance/desj/ondetverif/index.php"
]


class TestModelExportParity(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.py_model = joblib.load(JOBLIB_PATH)

    def run_js_prediction(self, feature_vec):
        js_code = f"""
        const model = require('{EXPORTED_JS_PATH}');
        const proba = model.predictProba({json.dumps(feature_vec)});
        const score = model.predictPhishingScore({json.dumps(feature_vec)});
        console.log(JSON.stringify({{ proba, score }}));
        """
        res = subprocess.run(
            ["node", "-e", js_code],
            capture_output=True,
            text=True,
            check=True
        )
        return json.loads(res.stdout.strip())

    def test_feature_order_and_probability_parity(self):
        print("\n--- Testing Model Prediction Parity between Python and Exported JS ---")
        for i, url in enumerate(VERIFICATION_URLS):
            feat_vec = extract_features(url)
            self.assertEqual(len(feat_vec), 14)

            # Python inference
            py_proba = self.py_model.predict_proba([feat_vec])[0]
            py_phish_prob = float(py_proba[1])

            # JS inference via Node
            js_res = self.run_js_prediction(feat_vec)
            js_proba = js_res["proba"]
            js_phish_prob = js_res["score"]

            # Parity assertions
            self.assertAlmostEqual(
                py_proba[0], js_proba[0], places=3,
                msg=f"Class 0 probability mismatch on {url}: Py={py_proba[0]}, JS={js_proba[0]}"
            )
            self.assertAlmostEqual(
                py_proba[1], js_proba[1], places=3,
                msg=f"Class 1 probability mismatch on {url}: Py={py_proba[1]}, JS={js_proba[1]}"
            )

            status = "PHISHING" if js_phish_prob > 0.5 else "SAFE"
            print(f"  [{status:<8}] URL: {url[:55]:<55} | Py Score: {py_phish_prob:.4f} | JS Score: {js_phish_prob:.4f}")

        print("--- Model Export Parity Verification PASS! ---\n")


if __name__ == "__main__":
    unittest.main()
