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


class TestRoutes(AppTest):
    def setUp(self):
        super().setUp()
        self.setup_admin()
        main.AUDIT_FILE.unlink(missing_ok=True)
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.sites = os.path.join(self.dir.name, "sites")
        self.caddyfile = os.path.join(self.dir.name, "Caddyfile")
        os.mkdir(self.sites)
        with open(self.caddyfile, "w", encoding="utf-8") as handle:
            handle.write(f"(stepca) {{\n\ttls internal\n}}\n\nimport {self.sites}/*.caddy\n")
        self.host = {
            **main.HOST_DEFAULTS,
            "id": "h1",
            "name": "lab",
            "caddyfile": self.caddyfile,
            "sites_dir": self.sites,
            "tls_snippet": "stepca",
            "domain_suffix": "lab.test",
        }
        main.save_hosts([self.host])
        # Nothing here may reach a real Caddy or a real target.
        self.load = self.patch(main.httpx, "post", mock.Mock(return_value=mock.Mock(status_code=200)))
        self.patch(main, "target_reachable", mock.Mock(return_value=True))

    def patch(self, target, name, value):
        patcher = mock.patch.object(target, name, value)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def form(self, **overrides):
        return {"type": "reverse_proxy", "host": "pdf", "upstream": "10.0.0.5:9005", "tls": "acme_ca", **overrides}

    def create(self, **overrides):
        return self.client.post("/routes/new", data=self.form(**overrides))

    def read(self, name):
        with open(os.path.join(self.sites, name), encoding="utf-8") as handle:
            return handle.read()

    def reject(self):
        self.load.return_value = mock.Mock(status_code=400, json=lambda: {"error": "unknown directive"})

    def test_reverse_proxy_file(self):
        self.assertEqual(self.create().headers["location"], "/?host=h1")
        self.assertEqual(
            self.read("pdf.caddy"),
            '# caddyman {"type":"reverse_proxy","host":"pdf.lab.test","port":"","tls":"acme_ca",'
            '"upstream":"10.0.0.5:9005"}\n'
            "pdf.lab.test {\n\timport stepca\n\treverse_proxy 10.0.0.5:9005\n}\n",
        )
        # The reload carries the base Caddyfile word for word, as a Caddyfile and never as JSON.
        call = self.load.call_args
        self.assertTrue(call.args[0].endswith("/load"))
        self.assertEqual(call.kwargs["headers"], {"Content-Type": "text/caddyfile"})
        with open(self.caddyfile, "rb") as handle:
            self.assertEqual(call.kwargs["content"], handle.read())
        self.assertEqual(main.read_audit()[0]["result"], "ok")
        self.assertIn("pdf.lab.test", self.client.get("/").text)

    def test_other_types_and_tls_modes(self):
        self.create(type="redirect", host="old", target="https://new.lab.test/", code="301", tls="internal")
        self.assertIn("old.lab.test {\n\ttls internal\n\tredir https://new.lab.test{uri} 301\n}\n", self.read("old.caddy"))
        self.create(type="static", host="docs.other.test", root="/srv/www", tls="none", port="8080")
        self.assertIn(
            "http://docs.other.test:8080 {\n\troot * /srv/www\n\tfile_server\n}\n",
            self.read("docs.other.test_8080.caddy"),
        )
        self.create(host="plain", tls="default")
        self.assertIn("plain.lab.test {\n\treverse_proxy 10.0.0.5:9005\n}\n", self.read("plain.caddy"))

    def test_input_that_must_never_reach_the_file(self):
        bad = [
            {"host": "a/b"},
            {"host": "../x"},
            {"host": "a b"},
            {"host": "x {\nrespond 200\n}"},
            {"host": ""},
            {"port": "70000"},
            {"port": "80 {"},
            {"upstream": "10.0.0.5"},
            {"upstream": "10.0.0.5:99999"},
            {"upstream": "10.0.0.5:80\n\trespond 200"},
            {"upstream": "unix//run/x.sock"},
            {"tls": "off"},
            {"type": "exec"},
            {"type": "redirect", "target": "https://x.test/{\nrespond", "code": "301"},
            {"type": "redirect", "target": "javascript:alert(1)", "code": "301"},
            {"type": "redirect", "target": "https://x.test", "code": "200"},
            {"type": "static", "root": "relative"},
            {"type": "static", "root": "/srv/../etc"},
            {"type": "static", "root": "/srv/www\n}"},
        ]
        for fields in bad:
            with self.subTest(fields):
                self.assertEqual(self.create(**fields).status_code, 400)
        self.assertEqual(os.listdir(self.sites), [])
        self.load.assert_not_called()

    def test_acme_ca_needs_the_snippet(self):
        main.save_hosts([{**self.host, "tls_snippet": ""}])
        self.assertEqual(self.create().status_code, 400)
        self.assertEqual(os.listdir(self.sites), [])

    def test_rejected_create_leaves_no_file(self):
        self.reject()
        response = self.create()
        self.assertEqual(response.status_code, 400)
        self.assertIn("unknown directive", response.text)
        self.assertEqual(os.listdir(self.sites), [])
        self.assertEqual(main.read_audit()[0]["result"], "unknown directive")

    def test_existing_file_is_not_overwritten(self):
        self.create()
        before = self.read("pdf.caddy")
        self.assertEqual(self.create(upstream="10.0.0.9:1").status_code, 400)
        self.assertEqual(self.read("pdf.caddy"), before)

    def test_delete_and_rejected_delete(self):
        self.create()
        before = self.read("pdf.caddy")
        self.reject()
        self.client.post("/routes/pdf/delete")
        self.assertEqual(self.read("pdf.caddy"), before)
        self.load.return_value = mock.Mock(status_code=200)
        self.client.post("/routes/pdf/delete")
        self.assertEqual(os.listdir(self.sites), [])
        self.assertEqual([entry["action"] for entry in main.read_audit()], ["delete", "delete", "create"])

    def test_route_names_cannot_leave_the_sites_directory(self):
        for name in ("..", "../x", "a/b", ".hidden", ""):
            self.assertIsNone(main.route_path(self.host, name))
        self.client.post("/routes/..%2FCaddyfile/delete")
        self.assertTrue(os.path.exists(self.caddyfile))

    def test_hand_edited_file_is_no_longer_ours(self):
        self.create()
        path = main.Path(self.sites) / "pdf.caddy"
        self.assertEqual(main.read_route(path, self.host)["upstream"], "10.0.0.5:9005")
        with open(path, "a", encoding="utf-8") as handle:
            handle.write("# tweaked\n")
        self.assertIsNone(main.read_route(path, self.host))
        with open(os.path.join(self.sites, "legacy.caddy"), "w", encoding="utf-8") as handle:
            handle.write("legacy.lab.test {\n\trespond 200\n}\n")
        self.assertIn("legacy.caddy", self.client.get("/").text)

    def test_unreachable_target_only_warns(self):
        main.target_reachable.return_value = False
        self.assertEqual(self.create().headers["location"], "/?host=h1")
        self.assertIn("does not answer yet", self.client.get("/").text)
        self.assertTrue(os.path.exists(os.path.join(self.sites, "pdf.caddy")))


if __name__ == "__main__":
    unittest.main()
