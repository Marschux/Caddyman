import os
import tempfile
import unittest

# Module constants are read once at import, so the data directory has to be set first.
_DATA = tempfile.TemporaryDirectory()
os.environ["CADDYMAN_DATA_DIR"] = _DATA.name
os.environ["CADDYMAN_SECRET_KEY"] = "test-key"
os.environ.pop("CADDYMAN_ADMIN_USER", None)

from fastapi.testclient import TestClient  # noqa: E402

from app import main  # noqa: E402

PASSWORD = "correct horse"


class TestAuth(unittest.TestCase):
    def setUp(self):
        main.AUTH_FILE.unlink(missing_ok=True)
        main.LOGIN_FAILS.clear()
        # Entering the client runs the startup that creates the setup token.
        self.client = TestClient(main.app, follow_redirects=False)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)

    def setup_admin(self, **overrides):
        form = {"token": main.SETUP_TOKEN, "username": "admin", "password": PASSWORD, "repeat": PASSWORD}
        return self.client.post("/setup", data={**form, **overrides})

    def test_everything_redirects_to_setup_without_admin(self):
        for path in ("/", "/login"):
            self.assertEqual(self.client.get(path).headers["location"], "/setup")
        self.assertEqual(self.client.get("/healthz").status_code, 200)
        self.assertEqual(self.client.get("/static/app.css").status_code, 200)

    def test_setup_needs_the_token(self):
        self.assertEqual(self.setup_admin(token="wrong").status_code, 400)
        self.assertEqual(self.setup_admin(token="").status_code, 400)
        self.assertFalse(main.AUTH_FILE.exists())

    def test_setup_rejects_bad_passwords(self):
        self.assertEqual(self.setup_admin(repeat="different").status_code, 400)
        self.assertEqual(self.setup_admin(password="short", repeat="short").status_code, 400)
        long = "x" * 73
        self.assertEqual(self.setup_admin(password=long, repeat=long).status_code, 400)
        self.assertFalse(main.AUTH_FILE.exists())

    def test_setup_creates_admin_and_logs_in(self):
        response = self.setup_admin()
        self.assertEqual(response.headers["location"], "/")
        self.assertIn("HttpOnly", response.headers["set-cookie"])
        self.assertIn("SameSite=lax", response.headers["set-cookie"])
        self.assertNotIn(PASSWORD, main.AUTH_FILE.read_text())
        self.assertEqual(self.client.get("/").status_code, 200)
        # The token is spent and the page is closed for good.
        self.assertIsNone(main.SETUP_TOKEN)
        self.assertEqual(self.client.get("/setup").headers["location"], "/")

    def test_login_and_logout(self):
        self.setup_admin()
        self.assertEqual(self.client.post("/logout").headers["location"], "/login")
        self.assertEqual(self.client.get("/").headers["location"], "/login")
        self.assertEqual(self.client.post("/login", data={"username": "admin", "password": "nope"}).status_code, 401)
        self.assertEqual(self.client.post("/login", data={"username": "other", "password": PASSWORD}).status_code, 401)
        response = self.client.post("/login", data={"username": "admin", "password": PASSWORD})
        self.assertEqual(response.headers["location"], "/")
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_forged_session_is_rejected(self):
        self.setup_admin()
        self.client.cookies.clear()
        self.client.cookies.set(main.SESSION_COOKIE, "admin.forged")
        self.assertEqual(self.client.get("/").headers["location"], "/login")

    def test_login_locks_after_five_failures(self):
        self.setup_admin()
        self.client.post("/logout")
        for _ in range(main.MAX_LOGIN_FAILS):
            self.client.post("/login", data={"username": "admin", "password": "nope"})
        # Even the right password is refused while the lock holds.
        response = self.client.post("/login", data={"username": "admin", "password": PASSWORD})
        self.assertEqual(response.status_code, 429)
        main.LOGIN_FAILS.clear()
        response = self.client.post("/login", data={"username": "admin", "password": PASSWORD})
        self.assertEqual(response.headers["location"], "/")


if __name__ == "__main__":
    unittest.main()
