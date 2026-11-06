import json
import os
import subprocess
import sys
import unittest

import joblib

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from ml.features import extract_domain_group, extract_features


class TestBackgroundModelParity(unittest.TestCase):
    def test_background_uses_canonical_feature_vectors(self):
        urls = [
            "http://[2001:4860:4860::8888]/login",
            "https://example.com/sign-in/confirmation/support-help",
            "https://example.com/signin/verify",
        ]
        script = f"""
        const bg = require({json.dumps(os.path.join(ROOT_DIR, 'background.js'))});
        const urls = {json.dumps(urls)};
        console.log(JSON.stringify(urls.map(url => bg.extractUrlFeatures(url).featureArray)));
        """
        completed = subprocess.run(
            ["node", "-e", script],
            check=True,
            capture_output=True,
            text=True,
        )
        js_vectors = json.loads(completed.stdout)
        for url, js_vector in zip(urls, js_vectors):
            with self.subTest(url=url):
                self.assertEqual(extract_features(url), js_vector)

    def test_domain_grouping_uses_local_suffix_data(self):
        self.assertEqual(extract_domain_group("https://mail.example.co.uk/login"), "example.co.uk")
        self.assertEqual(extract_domain_group("http://[2001:4860:4860::8888]/"), "2001:4860:4860::8888")

    def test_background_inference_uses_generated_model(self):
        url = "http://security-paypal-login-account-update.xyz/signin.htm"
        py_model = joblib.load(os.path.join(ROOT_DIR, "ml", "models", "phishing_rf.joblib"))
        python_score = float(py_model.predict_proba([extract_features(url)])[0][1])
        script = f"""
        const bg = require({json.dumps(os.path.join(ROOT_DIR, 'background.js'))});
        const model = require({json.dumps(os.path.join(ROOT_DIR, 'ml', 'models', 'model_exported.js'))});
        const result = bg.investigateUrl({json.dumps(url)});
        console.log(JSON.stringify({{
          score: result.riskScore,
          modelVersion: result.modelVersion,
          exportVersion: model.MODEL_VERSION,
          featureCount: result.featureSchema.length
        }}));
        """
        completed = subprocess.run(
            ["node", "-e", script],
            check=True,
            capture_output=True,
            text=True,
        )
        js_result = json.loads(completed.stdout)
        self.assertAlmostEqual(python_score, js_result["score"], places=3)
        self.assertEqual(js_result["featureCount"], 14)
        self.assertEqual(js_result["modelVersion"], js_result["exportVersion"])

    def test_dashboard_sync_is_opt_in_and_sends_only_the_url_to_loopback(self):
        script = f"""
        let enabled = false;
        const calls = [];
        global.chrome = {{
          storage: {{ local: {{ get(keys, callback) {{ callback({{ sentinel_local_dashboard_sync: enabled }}); }} }} }},
          webNavigation: {{ onCompleted: {{ addListener() {{}} }} }},
          tabs: {{ onUpdated: {{ addListener() {{}} }}, onActivated: {{ addListener() {{}} }}, onRemoved: {{ addListener() {{}} }} }},
          runtime: {{ onMessage: {{ addListener() {{}} }} }}
        }};
        global.fetch = async (...args) => {{ calls.push(args); return {{ ok: true }}; }};
        const background = require({json.dumps(os.path.join(ROOT_DIR, 'background.js'))});
        (async () => {{
          await background.syncLocalDashboard({{ url: 'https://example.com/', riskScore: 0.1 }});
          if (calls.length !== 0) throw new Error('Dashboard sync must be opt-in.');
          enabled = true;
          await background.syncLocalDashboard({{ url: 'https://example.com/', riskScore: 0.1 }});
          if (calls.length !== 1) throw new Error('Opted-in scan was not sent.');
          if (calls[0][0] !== 'http://127.0.0.1:8000/api/extension-events') throw new Error('Unexpected sync destination.');
          const payload = JSON.parse(calls[0][1].body);
          if (Object.keys(payload).join(',') !== 'url') throw new Error('Sync must not send score or other browsing data.');
          console.log('opt-in sync verified');
        }})().catch(error => {{ console.error(error); process.exitCode = 1; }});
        """
        completed = subprocess.run(
            ["node", "-e", script],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("opt-in sync verified", completed.stdout)


if __name__ == "__main__":
    unittest.main()
