"""Automated tests for SentinelAI Database, 2FA, Authentication, and Search Logging."""

import secrets
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

    def test_06_reject_dummy_and_disposable_emails(self):
        # 1. Disposable domain
        res1 = self.client.post(
            "/api/auth/register",
            json={
                "name": "Bot One",
                "email": "scammer123@tempmail.com",
                "password": "Password#1234",
                "two_factor_enabled": False
            }
        )
        self.assertEqual(res1.status_code, 400)
        self.assertIn("disposable", res1.json()["detail"].lower())

        # 2. Obvious dummy address
        res2 = self.client.post(
            "/api/auth/register",
            json={
                "name": "Dummy Tester",
                "email": "test@gmail.com",
                "password": "Password#1234",
                "two_factor_enabled": False
            }
        )
        self.assertEqual(res2.status_code, 400)
        self.assertIn("dummy", res2.json()["detail"].lower())

    def test_07_phone_number_and_otp_dispatch_log(self):
        import uuid
        email = f"verified_user_{uuid.uuid4().hex[:8]}@acmecorp.com"
        phone = "+1-415-555-2671"
        res = self.client.post(
            "/api/auth/register",
            json={
                "name": "Security Chief",
                "email": email,
                "phone": phone,
                "password": "SecurePassword#999",
                "two_factor_enabled": True
            }
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["require_2fa"])
        self.assertEqual(data["dispatch"]["channel"], "sms")
        self.assertEqual(data["dispatch"]["recipient"], phone)

        # Check in database
        dispatches = db.get_otp_dispatches(limit=5)
        matched = [d for d in dispatches if d["recipient"] == phone]
        self.assertTrue(len(matched) >= 1)
        self.assertEqual(matched[0]["status"], "delivered")

    def test_08_guest_scan_limit_one_time(self):
        simulated_ip = f"198.51.100.{secrets.randbelow(200) + 10}"
        # Scan 1: Allowed
        quota1 = db.check_scan_quota(user_id=None, ip_address=simulated_ip)
        self.assertTrue(quota1["allowed"])
        self.assertEqual(quota1["limit"], 1)

        db.record_scan_consumption(user_id=None, ip_address=simulated_ip)

        # Scan 2: Blocked!
        quota2 = db.check_scan_quota(user_id=None, ip_address=simulated_ip)
        self.assertFalse(quota2["allowed"])
        self.assertEqual(quota2["reason"], "guest_limit")

    def test_09_demo_account_five_token_limit(self):
        demo_user = db.get_user_by_email("demo@sentinelai.security")
        self.assertIsNotNone(demo_user)
        user_id = demo_user["id"]

        # Reset demo scans for predictable test state
        with db.get_connection() as conn:
            conn.execute("UPDATE users SET scans_used = 0, account_tier = 'demo' WHERE id = ?", (user_id,))
            conn.commit()

        # Simulate 5 scans
        for i in range(5):
            q = db.check_scan_quota(user_id=user_id, ip_address="127.0.0.1")
            self.assertTrue(q["allowed"], f"Scan {i+1} should be allowed")
            db.record_scan_consumption(user_id=user_id, ip_address="127.0.0.1")

        # 6th scan must be rejected with demo_limit
        q6 = db.check_scan_quota(user_id=user_id, ip_address="127.0.0.1")
        self.assertFalse(q6["allowed"])
        self.assertEqual(q6["reason"], "demo_limit")
        self.assertIn("5 scan tokens", q6["message"])


if __name__ == "__main__":
    unittest.main()
