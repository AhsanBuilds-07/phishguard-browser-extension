"""Automated tests for SentinelAI Database, 2FA, Authentication, and Search Logging."""

import sys
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from fastapi.testclient import TestClient
import ml.platform_api as platform_api
import ml.database as db


class AuthAndDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(platform_api.app)
        self.test_email = f"operator_{unittest.TestCase().id().split('.')[-1]}@sentinelai.security"
        self.test_password = "MasterPassword#2026!"

    def test_01_user_registration_and_2fa_challenge(self):
        import uuid
        email = f"test_reg_{uuid.uuid4().hex[:8]}@sentinelai.security"
        response = self.client.post(
            "/api/auth/register",
            json={
                "name": "Jane Security",
                "email": email,
                "password": "StrongPassword#2026!",
                "two_factor_enabled": True
            }
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["require_2fa"])
        self.assertTrue("temp_token" in data)
        self.assertTrue("dev_code_hint" in data)
        self.assertEqual(len(data["dev_code_hint"]), 6)

        # Verify 2FA code
        verify_res = self.client.post(
            "/api/auth/2fa/verify",
            json={
                "temp_token": data["temp_token"],
                "code": data["dev_code_hint"]
            }
        )
        self.assertEqual(verify_res.status_code, 200)
        verify_data = verify_res.json()
        self.assertTrue("token" in verify_data)
        self.assertEqual(verify_data["user"]["email"], email)

    def test_02_login_and_incorrect_password(self):
        import uuid
        # Register user with known credentials
        email = f"test_login_{uuid.uuid4().hex[:8]}@sentinelai.security"
        self.client.post(
            "/api/auth/register",
            json={
                "name": "Bob Analyst",
                "email": email,
                "password": "CorrectPassword#123",
                "two_factor_enabled": False
            }
        )

        # Test wrong password
        fail_res = self.client.post(
            "/api/auth/login",
            json={
                "email": email,
                "password": "WrongPassword!"
            }
        )
        self.assertEqual(fail_res.status_code, 401)

        # Test correct password
        success_res = self.client.post(
            "/api/auth/login",
            json={
                "email": email,
                "password": "CorrectPassword#123"
            }
        )
        self.assertEqual(success_res.status_code, 200)
        self.assertTrue("token" in success_res.json())

    def test_03_google_oauth_simulation(self):
        import uuid
        google_email = f"goog_{uuid.uuid4().hex[:8]}@sentinelai.security"
        res = self.client.post(
            "/api/auth/google",
            json={
                "name": "Google Operator",
                "email": google_email,
                "avatar_url": "https://lh3.googleusercontent.com/a/test"
            }
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue("token" in data)
        self.assertEqual(data["user"]["email"], google_email)

    def test_04_record_and_retrieve_searches_in_database(self):
        import uuid
        # 1. Login user to get token
        email = f"search_tester_{uuid.uuid4().hex[:8]}@sentinelai.security"
        reg = self.client.post(
            "/api/auth/register",
            json={
                "name": "Audit Auditor",
                "email": email,
                "password": "Password#9999",
                "two_factor_enabled": False
            }
        )
        self.assertEqual(reg.status_code, 200)
        token = reg.json().get("token")
        self.assertTrue(token)

        # 2. Record search in database
        record_res = self.client.post(
            "/api/user/searches",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "query_url": "https://paypal-credential-scam.xyz/login",
                "risk_score": 0.985,
                "verdict": "PHISHING",
                "features_summary": "16 brands checked, raw entropy high",
                "user_email": email
            }
        )
        self.assertEqual(record_res.status_code, 200)
        self.assertTrue("search_id" in record_res.json())

        # 3. Retrieve searches from database
        history_res = self.client.get(
            "/api/user/searches",
            headers={"Authorization": f"Bearer {token}"}
        )
        self.assertEqual(history_res.status_code, 200)
        searches = history_res.json()["searches"]
        self.assertTrue(len(searches) >= 1)
        # Verify the saved record has our URL
        urls = [s["query_url"] for s in searches]
        self.assertIn("https://paypal-credential-scam.xyz/login", urls)

    def test_05_investigate_url_automatically_persists_to_database(self):
        url = "http://bad-login-phish.xyz/signin"
        res = self.client.post(
            "/api/investigate",
            json={"url": url}
        )
        self.assertEqual(res.status_code, 200)

        # Verify search is stored in SQLite DB
        searches = db.get_search_history(limit=10)
        stored_urls = [s["query_url"] for s in searches]
        self.assertIn(url, stored_urls)


if __name__ == "__main__":
    unittest.main()
