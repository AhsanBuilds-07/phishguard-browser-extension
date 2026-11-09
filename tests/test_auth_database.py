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
        import uuid
        simulated_ip = f"203.0.113.{uuid.uuid4().hex[:6]}"
        with db.get_connection() as conn:
            conn.execute("DELETE FROM guest_scan_limits WHERE ip_address = ?", (simulated_ip,))
            conn.commit()

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


    def test_admin_endpoints_reject_anonymous_and_non_admin_sessions(self):
        admin_routes = [
            ("get", "/api/admin/users"),
            ("get", "/api/admin/searches"),
            ("get", "/api/admin/metrics"),
            ("get", "/api/admin/otp-dispatches"),
            ("delete", "/api/admin/users/999999"),
            ("delete", "/api/admin/searches/999999"),
        ]
        for method, route in admin_routes:
            self.assertEqual(getattr(self.client, method)(route).status_code, 401, route)
        role_res = self.client.patch("/api/admin/users/1/role", json={"role": "admin"})
        self.assertEqual(role_res.status_code, 401)

        # A regular operator session is authenticated but not authorised.
        import uuid
        reg = self.client.post(
            "/api/auth/register",
            json={
                "name": "Regular Operator",
                "email": f"test_reg_{uuid.uuid4().hex[:8]}@sentinelai.security",
                "password": "StrongPassword#2026!",
                "two_factor_enabled": True,
            },
        ).json()
        session = self.client.post(
            "/api/auth/2fa/verify",
            json={"temp_token": reg["temp_token"], "code": reg["dev_code_hint"]},
        ).json()
        headers = {"Authorization": f"Bearer {session['token']}"}
        for method, route in admin_routes:
            self.assertEqual(getattr(self.client, method)(route, headers=headers).status_code, 403, route)

    def test_static_2fa_bypass_code_only_works_for_root_admin(self):
        import uuid
        reg = self.client.post(
            "/api/auth/register",
            json={
                "name": "Bypass Probe",
                "email": f"test_reg_{uuid.uuid4().hex[:8]}@sentinelai.security",
                "password": "StrongPassword#2026!",
                "two_factor_enabled": True,
            },
        ).json()
        if reg["dev_code_hint"] != "999888":
            bypass = self.client.post(
                "/api/auth/2fa/verify",
                json={"temp_token": reg["temp_token"], "code": "999888"},
            )
            self.assertNotEqual(bypass.status_code, 200)

        login = self.client.post(
            "/api/auth/login",
            json={"email": "admin@sentinelai.security", "password": "SentinelAdmin#2026!"},
        ).json()
        if login.get("require_2fa"):
            login = self.client.post(
                "/api/auth/2fa/verify",
                json={"temp_token": login["temp_token"], "code": "999888"},
            ).json()
        headers = {"Authorization": f"Bearer {login['token']}"}
        self.assertEqual(self.client.get("/api/admin/users", headers=headers).status_code, 200)

    def test_search_history_is_scoped_and_never_leaks_credentials(self):
        import uuid
        self.client.post(
            "/api/user/searches",
            json={"query_url": "https://scoped-probe.example/", "risk_score": 0.1, "verdict": "SAFE"},
        )
        anon = self.client.get("/api/user/searches?limit=200").json()
        self.assertTrue(anon["searches"])
        self.assertTrue(all(row["user_id"] is None for row in anon["searches"]))

        reg = self.client.post(
            "/api/auth/register",
            json={
                "name": "Scoped Operator",
                "email": f"test_reg_{uuid.uuid4().hex[:8]}@sentinelai.security",
                "password": "StrongPassword#2026!",
                "two_factor_enabled": True,
            },
        ).json()
        session = self.client.post(
            "/api/auth/2fa/verify",
            json={"temp_token": reg["temp_token"], "code": reg["dev_code_hint"]},
        ).json()
        mine = self.client.get(
            "/api/user/searches",
            headers={"Authorization": f"Bearer {session['token']}"},
        ).json()
        self.assertEqual(mine["searches"], [])
        for secret in ("password_hash", "password_salt", "two_factor_secret"):
            self.assertNotIn(secret, mine["user"])

if __name__ == "__main__":
    unittest.main()
