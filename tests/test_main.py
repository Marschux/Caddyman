import os
import tempfile
import unittest
from unittest import mock

# Module constants are read once at import, so the data directory has to be set first.
_DATA = tempfile.TemporaryDirectory()
os.environ["CADDYMAN_DATA_DIR"] = _DATA.name
os.environ["CADDYMAN_SECRET_KEY"] = "test-key"
os.environ.pop("CADDYMAN_ADMIN_USER", None)

from fastapi.testclient import TestClient  # noqa: E402

from app import main  # noqa: E402

PASSWORD = "correct horse"


class AppTest(unittest.TestCase):
    def setUp(self):
        main.AUTH_FILE.unlink(missing_ok=True)
        main.HOSTS_FILE.unlink(missing_ok=True)
        main.LOGIN_FAILS.clear()
        # Entering the client runs the startup that creates the setup token.
        self.client = TestClient(main.app, follow_redirects=False)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)

    def setup_admin(self, **overrides):
        form = {"token": main.SETUP_TOKEN, "username": "admin", "password": PASSWORD, "repeat": PASSWORD}
        return self.client.post("/setup", data={**form, **overrides})


class TestAuth(AppTest):
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
        self.assertEqual(self.client.get("/hosts").status_code, 200)
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
        self.assertEqual(self.client.get("/hosts").status_code, 200)

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


class TestHosts(AppTest):
    def setUp(self):
        super().setUp()
        self.setup_admin()
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.sites = os.path.join(self.dir.name, "sites").replace("\\", "/")
        self.caddyfile = os.path.join(self.dir.name, "Caddyfile").replace("\\", "/")
        os.mkdir(self.sites)

    def host(self, **overrides):
        return {**main.HOST_DEFAULTS, "name": "lab", "tls_snippet": "stepca", **overrides}

    def checks(self, caddyfile_text, admin=None):
        if caddyfile_text is not None:
            with open(self.caddyfile, "w", encoding="utf-8") as handle:
                handle.write(caddyfile_text)
        admin = admin or mock.Mock(return_value=mock.Mock(status_code=200))
        with mock.patch.object(main.httpx, "get", admin):
            result = main.preflight(self.host(caddyfile=self.caddyfile, sites_dir=self.sites))
        return {check["label"]: check["ok"] for check in result}

    def test_setup_dialog_until_a_host_exists(self):
        self.assertEqual(self.client.get("/").headers["location"], "/hosts/new")
        self.assertEqual(self.client.post("/hosts/new", data=self.host()).headers["location"], "/status")
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_host_is_validated(self):
        bad = [
            {"name": ""},
            {"admin_url": "ftp://caddy:2019"},
            {"admin_url": "http://user:pw@caddy:2019"},
            {"admin_url": "http://caddy:2019/config"},
            {"caddyfile": "relative/Caddyfile"},
            {"sites_dir": "/etc/caddy/../../root"},
            {"tls_snippet": "step ca"},
            {"tls_snippet": "x) {\nevil"},
            {"root_ca_url": "file:///etc/passwd"},
            {"domain_suffix": "bad suffix"},
        ]
        for fields in bad:
            with self.subTest(fields):
                self.assertEqual(self.client.post("/hosts/new", data=self.host(**fields)).status_code, 400)
        self.assertEqual(main.load_hosts(), [])

    def test_edit_and_delete(self):
        self.client.post("/hosts/new", data=self.host())
        self.assertEqual(self.client.post("/hosts/new", data=self.host()).status_code, 400)  # same name
        host_id = main.load_hosts()[0]["id"]
        self.client.post(f"/hosts/{host_id}/edit", data=self.host(name="renamed", admin_url="http://caddy:2019/"))
        self.assertEqual(
            [(h["id"], h["name"], h["admin_url"]) for h in main.load_hosts()],
            [(host_id, "renamed", "http://caddy:2019")],
        )
        self.client.post(f"/hosts/{host_id}/delete")
        self.assertEqual(main.load_hosts(), [])

    def test_preflight_all_good(self):
        text = f"{{\n\tadmin :2019\n}}\n\n(stepca) {{\n\ttls internal\n}}\n\nimport {self.sites}/*.caddy\n"
        self.assertEqual(set(self.checks(text).values()), {True})

    def test_preflight_names_what_is_missing(self):
        down = mock.Mock(side_effect=main.httpx.ConnectError("refused"))
        result = self.checks("example.test {\n\trespond 200\n}\n", admin=down)
        self.assertEqual(
            result,
            {
                "Base Caddyfile is readable": True,
                "Base Caddyfile imports the sites directory": False,
                "TLS snippet 'stepca' exists": False,
                "Admin API is reachable": False,
                "Sites directory is writable": True,
            },
        )

    def test_preflight_without_caddyfile(self):
        result = self.checks(None)
        self.assertFalse(result["Base Caddyfile is readable"])
        self.assertNotIn("Base Caddyfile imports the sites directory", result)

    def test_status_page_never_writes_the_caddyfile(self):
        self.checks("example.test {\n}\n")
        before = os.stat(self.caddyfile).st_mtime_ns
        self.client.post("/hosts/new", data=self.host(caddyfile=self.caddyfile, sites_dir=self.sites))
        with mock.patch.object(main.httpx, "get", mock.Mock(side_effect=main.httpx.ConnectError("x"))):
            self.assertEqual(self.client.get("/status").status_code, 200)
        self.assertEqual(os.stat(self.caddyfile).st_mtime_ns, before)
        self.assertEqual(os.listdir(self.sites), [])


if __name__ == "__main__":
    unittest.main()
