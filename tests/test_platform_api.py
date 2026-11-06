import csv
import tempfile
import unittest
from pathlib import Path

from fastapi import HTTPException
from fastapi.testclient import TestClient

from ml import platform_api


class PlatformApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_data_dir = platform_api.DATA_DIR
        self.original_history = platform_api.ANALYSIS_HISTORY
        platform_api.DATA_DIR = Path(self.temp_dir.name)
        platform_api.ANALYSIS_HISTORY = Path(self.temp_dir.name) / "history.json"

    def tearDown(self):
        platform_api.DATA_DIR = self.original_data_dir
        platform_api.ANALYSIS_HISTORY = self.original_history
        self.temp_dir.cleanup()

    def test_validate_and_clean_dataset_counts_bad_and_duplicate_rows(self):
        source = Path(self.temp_dir.name) / "sample.csv"
        with source.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=["url", "label"])
            writer.writeheader()
            writer.writerows([
                {"url": "https://example.com/", "label": "benign"},
                {"url": "http://bad-login.xyz/verify", "label": "phishing"},
                {"url": "https://example.com/", "label": "0"},
                {"url": "not a url", "label": "1"},
                {"url": "https://other.example/", "label": "unknown"},
            ])

        validation = platform_api.validate_dataset(source)
        self.assertEqual(validation["total_rows"], 5)
        self.assertEqual(validation["valid_rows"], 2)
        self.assertEqual(validation["invalid_urls"], 1)
        self.assertEqual(validation["invalid_labels"], 1)
        self.assertEqual(validation["duplicate_urls"], 1)
        self.assertEqual(validation["class_counts"], {"benign": 1, "phishing": 1})

        cleaned = platform_api.clean_dataset("sample.csv")
        self.assertEqual(cleaned["kept_rows"], 2)
        self.assertEqual(cleaned["rejected_rows"], 2)
        self.assertEqual(cleaned["duplicate_rows"], 1)
        self.assertEqual(cleaned["validation"]["class_counts"], {"benign": 1, "phishing": 1})

    def test_investigation_uses_active_sklearn_model_and_canonical_features(self):
        report = platform_api._investigate("http://security-paypal-login-account-update.xyz/signin.htm")
        self.assertEqual(len(report["features"]), 14)
        self.assertEqual(report["feature_names"], platform_api.FEATURE_NAMES)
        self.assertEqual(report["model_type"], "RandomForestClassifier")
        self.assertGreater(report["risk_score"], 0.75)
        self.assertTrue(report["model_version"].startswith("rf-"))
        self.assertTrue(report["signals"])

    def test_investigation_rejects_non_http_urls(self):
        with self.assertRaises(HTTPException) as context:
            platform_api._investigate("javascript:alert(1)")
        self.assertEqual(context.exception.status_code, 422)

    def test_api_upload_and_investigation_routes(self):
        client = TestClient(platform_api.app)
        csv_content = (
            "url,label\n"
            "https://example.com/,benign\n"
            "http://bad-login.xyz/verify,phishing\n"
        )
        response = client.put(
            "/api/datasets/imported.csv",
            content=csv_content,
            headers={"content-type": "text/csv"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["validation"]["valid_rows"], 2)

        report_response = client.post(
            "/api/investigate",
            json={"url": "http://bad-login.xyz/verify"},
        )
        self.assertEqual(report_response.status_code, 200)
        self.assertEqual(report_response.json()["model_type"], "RandomForestClassifier")
        self.assertEqual(len(report_response.json()["features"]), 14)

        history_response = client.get("/api/history")
        self.assertEqual(len(history_response.json()["items"]), 1)

    def test_extension_event_is_re_scored_and_origin_is_allowlisted(self):
        client = TestClient(platform_api.app)
        origin = "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
        response = client.post(
            "/api/extension-events",
            json={"url": "https://example.com/"},
            headers={"Origin": origin},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["source"], "browser_extension")
        self.assertEqual(response.headers["access-control-allow-origin"], origin)


if __name__ == "__main__":
    unittest.main()
