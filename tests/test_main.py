import base64
import gzip
import io
import os
import shutil
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from unittest import mock

# Module constants are read once at import, so the data directory has to be set first.
_DATA = tempfile.TemporaryDirectory()
os.environ["CADDYMAN_DATA_DIR"] = _DATA.name
os.environ["CADDYMAN_SECRET_KEY"] = "test-key-of-at-least-32-characters"
os.environ.pop("CADDYMAN_SETUP_TOKEN", None)

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import main  # noqa: E402

PASSWORD = "correct horse"


class AppTest(unittest.TestCase):
    def setUp(self):
        main.AUTH_FILE.unlink(missing_ok=True)
        main.HOSTS_FILE.unlink(missing_ok=True)
        main.MAIL_FILE.unlink(missing_ok=True)
        main.SETTINGS_FILE.unlink(missing_ok=True)
        main.GROUPS_FILE.unlink(missing_ok=True)
        main.ERRORS_FILE.unlink(missing_ok=True)
        main.LOGIN_FAILS.clear()
        main.LOCK_ROUNDS.clear()
        # No name is looked up from a test: where "Caddy" sits is said by each test that needs it.
        self.patch(main, "resolve_addresses", mock.Mock(return_value=set()))
        main.CADDY_ADDRESSES.update(until=0.0, found=frozenset(), busy=False)
        # Entering the client runs the startup that creates the setup token.
        self.client = self.guest()
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)

    def patch(self, target, name, value):
        patcher = mock.patch.object(target, name, value)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def guest(self):
        """A browser of its own, with no session."""
        return TestClient(main.app, follow_redirects=False)

    def setup_admin(self, **overrides):
        form = {"token": main.SETUP_TOKEN, "username": "admin", "password": PASSWORD, "repeat": PASSWORD}
        return self.client.post("/setup", data={**form, **overrides})


class TestAuth(AppTest):
    def test_everything_redirects_to_setup_without_admin(self):
        for path in ("/", "/login"):
            self.assertEqual(self.client.get(path).headers["location"], "/setup")
        self.assertEqual(self.client.get("/healthz").status_code, 200)
        self.assertEqual(self.client.get("/static/app.css").status_code, 200)
        # The icon is linked from every page and has to load before anyone is logged in.
        self.assertIn('rel="icon" type="image/svg+xml" href="/static/favicon.svg"', self.client.get("/setup").text)
        self.assertEqual(self.client.get("/static/favicon.svg").headers["content-type"], "image/svg+xml")
        # License and source are named on every page, also before login.
        footer = self.client.get("/setup").text.split("<footer>")[1]
        self.assertIn("AGPL-3.0-or-later", footer)
        self.assertIn(f'href="{main.SOURCE_URL}"', footer)

    def test_setup_takes_an_email_for_the_admin(self):
        self.assertEqual(self.setup_admin(email="not an address").status_code, 400)
        self.assertFalse(main.AUTH_FILE.exists())
        self.assertEqual(self.setup_admin(email=" ada@lab.test ").headers["location"], "/")
        self.assertEqual(main.load_users()[0]["email"], "ada@lab.test")

    def test_setup_needs_the_token(self):
        self.assertEqual(self.setup_admin(token="wrong").status_code, 400)
        self.assertEqual(self.setup_admin(token="").status_code, 400)
        self.assertFalse(main.AUTH_FILE.exists())

    def test_setup_token_can_come_from_the_environment(self):
        with mock.patch.object(main, "ENV_SETUP_TOKEN", "my own token"), mock.patch("builtins.print") as log:
            with self.guest() as client:
                self.assertNotIn("my own token", str(log.call_args_list))  # not repeated in the log
                self.assertIn("CADDYMAN_SETUP_TOKEN", client.get("/setup").text)
                form = {"username": "admin", "password": PASSWORD, "repeat": PASSWORD}
                self.assertEqual(client.post("/setup", data={**form, "token": "wrong"}).status_code, 400)
                self.assertEqual(client.post("/setup", data={**form, "token": "my own token"}).headers["location"], "/")

    def test_short_setup_token_blocks_the_setup(self):
        with mock.patch.object(main, "ENV_SETUP_TOKEN", "short"), mock.patch("builtins.print"):
            with self.guest() as client:
                self.assertIn("too short", client.get("/setup").text)
                form = {"token": "short", "username": "admin", "password": PASSWORD, "repeat": PASSWORD}
                self.assertEqual(client.post("/setup", data=form).status_code, 400)
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
        self.assertEqual(self.client.get("/status").status_code, 200)
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
        self.assertEqual(self.client.get("/status").status_code, 200)

    def test_logout_ends_every_session_of_the_account(self):
        self.setup_admin()
        copied = self.client.cookies.get(main.SESSION_COOKIE)
        # The stamp in the cookie shows nothing of the password hash.
        self.assertNotIn(main.SESSIONS.loads(copied)[1], main.load_users()[0]["password_hash"])
        elsewhere = self.guest()
        elsewhere.post("/login", data={"username": "admin", "password": PASSWORD})
        self.client.post("/logout")
        self.client.cookies.clear()
        self.client.cookies.set(main.SESSION_COOKIE, copied)
        self.assertEqual(self.client.get("/").headers["location"], "/login")
        self.assertEqual(elsewhere.get("/").headers["location"], "/login")

    def test_forged_session_is_rejected(self):
        self.setup_admin()
        self.client.cookies.clear()
        self.client.cookies.set(main.SESSION_COOKIE, "admin.forged")
        self.assertEqual(self.client.get("/").headers["location"], "/login")

    def test_host_header_cannot_move_the_path(self):
        # The rights go by the path the router uses, not by a URL rebuilt from the Host header.
        self.setup_admin()
        new = {"username": "eve", "password": PASSWORD, "repeat": PASSWORD, "right_users": "1"}
        guest, bent = self.guest(), {"host": "x/login?"}
        self.assertEqual(guest.get("/settings/users", headers=bent).headers["location"], "/login")
        self.assertEqual(guest.post("/settings/users/new", data=new, headers=bent).headers["location"], "/login")
        self.assertIsNone(main.find_user(main.load_users(), "eve"))
        # An account without rights gets no further with it either.
        self.client.post("/settings/users/new", data={"username": "viewer", "password": PASSWORD, "repeat": PASSWORD})
        guest.post("/login", data={"username": "viewer", "password": PASSWORD})
        self.assertEqual(guest.get("/settings/users", headers={"host": "x/profile?"}).status_code, 403)
        self.assertEqual(guest.post("/settings/users/new", data=new, headers={"host": "x/profile?"}).status_code, 403)
        self.assertIsNone(main.find_user(main.load_users(), "eve"))

    def test_a_form_from_another_site_is_refused(self):
        self.setup_admin()
        new = {"username": "eve", "password": PASSWORD, "repeat": PASSWORD}
        elsewhere = ({"origin": "https://app.lab.test"}, {"sec-fetch-site": "same-site"}, {"sec-fetch-site": "cross-site", "origin": "http://testserver"})
        for headers in elsewhere:
            with self.subTest(headers):
                self.assertEqual(self.client.post("/settings/users/new", data=new, headers=headers).status_code, 403)
        self.assertIsNone(main.find_user(main.load_users(), "eve"))
        # A browser on Caddyman's own page says so; a client that is no browser says nothing.
        own = {"origin": "http://testserver", "sec-fetch-site": "same-origin"}
        self.assertEqual(self.client.post("/settings/users/new", data=new, headers=own).headers["location"], "/settings/users")
        # A failed request that Caddy hands to an error page keeps the headers of its visitor.
        self.assertEqual(self.client.post("/error/502", headers={"sec-fetch-site": "cross-site"}).status_code, 502)

    def test_a_request_larger_than_any_form_is_refused(self):
        self.setup_admin()
        large = "x" * (main.MAX_BODY_BYTES + 1)
        self.assertEqual(self.client.post("/login", data={"username": large}).status_code, 413)
        self.assertEqual(self.client.post("/login", content=iter([b"username=x"])).status_code, 413)  # no length given
        self.assertEqual(self.client.post("/logout").headers["location"], "/login")
        # What Caddy hands to an error page is somebody else's request and is never read.
        self.assertEqual(self.guest().post("/error/502", content=large.encode()).status_code, 502)

    def test_another_login_does_not_reset_the_limit(self):
        self.setup_admin()
        self.client.post("/settings/users/new", data={"username": "bob", "password": PASSWORD, "repeat": PASSWORD})
        guest = self.guest()
        for _ in range(main.MAX_LOGIN_FAILS - 1):
            guest.post("/login", data={"username": "admin", "password": "nope"})
        self.assertEqual(self.guest().post("/login", data={"username": "bob", "password": PASSWORD}).headers["location"], "/")
        guest.post("/login", data={"username": "admin", "password": "nope"})
        self.assertEqual(guest.post("/login", data={"username": "admin", "password": PASSWORD}).status_code, 429)
        # A failure only counts for a while.
        main.LOGIN_FAILS.clear()
        guest.post("/login", data={"username": "admin", "password": "nope"})
        main.LOGIN_FAILS["testclient"][2] -= main.FAIL_SECONDS + 1
        main.LOGIN_FAILS["192.0.2.7"] = [3, 0.0, main.time.monotonic() - main.FAIL_SECONDS - 1]
        guest.post("/login", data={"username": "admin", "password": "nope"})
        self.assertEqual(main.LOGIN_FAILS["testclient"][0], 1)
        self.assertNotIn("192.0.2.7", main.LOGIN_FAILS)  # and is then cleared away

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
        # Counted per name too: a new address for every attempt does not get around the limit.
        self.client.post("/logout")
        main.LOGIN_FAILS.clear()
        main.resolve_addresses.return_value = {"testclient"}  # the peer counts as Caddy and is believed
        main.CADDY_ADDRESSES["until"] = 0.0
        answers = [
            self.client.post("/login", data={"username": "Admin ", "password": "nope"}, headers={"x-forwarded-for": f"198.51.100.{count}"}).status_code
            for count in range(main.MAX_LOGIN_FAILS + 1)
        ]
        self.assertEqual(answers, [401] * main.MAX_LOGIN_FAILS + [429])


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

    def checks(self, caddyfile_text, admin=None, root_ca=None, **fields):
        if caddyfile_text is not None:
            with open(self.caddyfile, "w", encoding="utf-8") as handle:
                handle.write(caddyfile_text)
        admin = admin or mock.Mock(return_value=mock.Mock(status_code=200))
        root_ca = root_ca or mock.Mock(return_value=("pem", "source", True))
        with mock.patch.object(main.httpx, "get", admin), mock.patch.object(main, "fetch_root_ca", root_ca):
            host = self.host(caddyfile=self.caddyfile, sites_dir=self.sites, **fields)
            if fields.get("admin_user"):
                host["admin_password_enc"] = main.VAULT.encrypt(b"pw").decode()
            result = main.preflight(host)
        return {check["label"]: check["ok"] for check in result}

    def test_a_snippet_below_the_import_is_reported(self):
        label = "Snippet 'stepca' stands above the import of the routes"
        snippet, imports = "(stepca) {\n\ttls internal\n}\n", f"import {self.sites}/*.caddy\n"
        self.assertIs(self.checks(snippet + imports)[label], True)
        late = self.checks(imports + snippet)
        self.assertEqual((late["TLS snippet 'stepca' exists"], late[label]), (True, False))
        # Without the snippet there is nothing to place.
        self.assertNotIn(label, self.checks(imports))

    def test_dns_snippet_is_handed_to_caddy_to_read(self):
        label = "Caddy understands the DNS snippet"
        text = "(dns) {\n\ttls {\n\t\tdns cloudflare {env.TOKEN}\n\t}\n}\n" + f"import {self.sites}/*.caddy\n"
        refused = mock.Mock(status_code=400, json=lambda: {"error": "module not registered: dns.providers.cloudflare"})
        with mock.patch.object(main.httpx, "post", mock.Mock(return_value=refused)) as post:
            self.assertIs(self.checks(text, dns_snippet="dns")[label], False)
        # Only the snippet and a site that uses it, to be adapted and never loaded.
        self.assertTrue(post.call_args.args[0].endswith("/adapt"))
        self.assertEqual(post.call_args.kwargs["content"].decode(), text.split("import")[0] + "\ndns-check.invalid {\n\timport dns\n}\n")
        with mock.patch.object(main.httpx, "post", mock.Mock(return_value=mock.Mock(status_code=200))):
            self.assertIs(self.checks(text, dns_snippet="dns")[label], True)
            self.assertNotIn(label, self.checks(text))

    def test_setup_dialog_until_a_host_exists(self):
        self.assertEqual(self.client.get("/").headers["location"], "/hosts/new")
        self.assertEqual(self.client.post("/hosts/new", data=self.host()).headers["location"], "/status")
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_host_is_validated(self):
        bad = [
            {"admin_url": "ftp://caddy:2019"},
            {"admin_url": "http://user:pw@caddy:2019"},
            {"admin_url": "http://caddy:2019/config"},
            {"caddyfile": "relative/Caddyfile"},
            {"sites_dir": "/etc/caddy/../../root"},
            # Never Caddyman's own files: the base Caddyfile travels in the backup and to Caddy.
            {"caddyfile": f"{main.DATA_DIR}/secret.key"},
            {"sites_dir": str(main.DATA_DIR)},
            {"caddyfile": "/proc/self/environ"},
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
        host_id = main.load_hosts()[0]["id"]
        # There is one Caddy: a second one cannot be added, the old list leads to its settings.
        self.assertEqual(self.client.post("/hosts/new", data=self.host(domain_suffix="second.test")).headers["location"], "/hosts")
        self.assertEqual(self.client.get("/hosts").headers["location"], f"/hosts/{host_id}/edit")
        self.assertEqual(self.client.get("/hosts/new").headers["location"], f"/hosts/{host_id}/edit")
        self.assertEqual(len(main.load_hosts()), 1)
        self.client.post(f"/hosts/{host_id}/edit", data=self.host(domain_suffix="new.test", admin_url="http://caddy:2019/"))
        self.assertEqual(
            [(h["id"], h["domain_suffix"], h["admin_url"]) for h in main.load_hosts()],
            [(host_id, "new.test", "http://caddy:2019")],
        )
        # The name from the days of several Caddys is gone: not asked for, not stored.
        self.assertNotIn("name", main.load_hosts()[0])
        self.assertNotIn('name="name"', self.client.get(f"/hosts/{host_id}/edit").text)
        self.assertEqual(self.client.post(f"/hosts/{host_id}/delete").headers["location"], "/hosts/new")
        self.assertEqual(main.load_hosts(), [])
        self.assertEqual(self.client.get("/hosts/new").status_code, 200)

    def test_preflight_all_good(self):
        text = f"(stepca) {{\n\ttls internal\n}}\n\nimport {self.sites}/*.caddy\n"
        self.assertEqual(set(self.checks(text, admin_user="caddyman").values()), {True})

    def test_preflight_flags_an_admin_api_without_login(self):
        text = f"{{\n\tadmin :2019\n}}\n\nimport {self.sites}/*.caddy\n"
        result = self.checks(text)
        self.assertTrue(result["Admin API is reachable"])
        self.assertFalse(result["Admin API asks for a login"])
        refused = mock.Mock(return_value=mock.Mock(status_code=401))
        self.assertNotIn("Admin API asks for a login", self.checks(text, admin=refused))

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
                "Secret key comes from the environment": True,
            },
        )
        # A key Caddyman made itself is flagged, and the page never prints it.
        with mock.patch.object(main, "SECRET_KEY_FROM_ENV", False):
            self.assertFalse(self.checks("")["Secret key comes from the environment"])
            self.client.post("/hosts/new", data=self.host())
            status = self.client.get("/status").text
        self.assertIn("docker exec caddyman cat /data/secret.key", status)
        self.assertNotIn(main.SECRET_KEY, status)

    def test_preflight_asks_the_acme_ca_and_the_root_ca(self):
        text = f"(stepca) {{\n\ttls {{\n\t\tca https://ca.lab.test:9001/acme/acme/directory\n\t}}\n}}\n\nimport {self.sites}/*.caddy\n"
        result = self.checks(text, admin_user="caddyman")
        self.assertTrue(result["ACME CA answers"])
        self.assertTrue(result["Root CA can be downloaded"])

        def ca_down(url, **kwargs):
            if "ca.lab.test" in url:
                raise main.httpx.ConnectError("refused")
            return mock.Mock(status_code=200)

        gone = mock.Mock(side_effect=ValueError("did not answer with a certificate"))
        result = self.checks(text, admin=mock.Mock(side_effect=ca_down), root_ca=gone)
        self.assertFalse(result["ACME CA answers"])
        self.assertFalse(result["Root CA can be downloaded"])
        self.assertTrue(result["Admin API is reachable"])
        # From another machine Caddyman may not see what Caddy sees, so it does not ask there.
        up = mock.Mock(return_value=mock.Mock(status_code=200, content=b""))
        self.assertNotIn("ACME CA answers", self.checks(text, admin=up, storage="managed", id="h1"))
        # A snippet that names no CA in the plain form is left alone, as is Caddy's own CA while the admin API is down.
        down = mock.Mock(side_effect=main.httpx.ConnectError("refused"))
        result = self.checks(f"(stepca) {{\n\ttls internal\n}}\n\nimport {self.sites}/*.caddy\n", admin=down)
        self.assertNotIn("ACME CA answers", result)
        self.assertNotIn("Root CA can be downloaded", result)
        self.assertIn("Root CA can be downloaded", self.checks(text, admin=down, root_ca_url="https://ca.lab.test:9001/roots.pem"))

    def test_preflight_asks_for_the_two_words_the_log_setup_gained(self):
        logger = "{\n\tlog caddyman {\n\t\toutput file /var/log/caddy/caddy.log\n\t\tformat json\n\t}\n}\n"
        base = logger + f"import {self.sites}/*.caddy\n"
        twice = "Requests of routes with an access log stay out of Caddy's own log"
        # Nothing to say while no route writes an access log.
        self.assertNotIn(twice, self.checks(base))
        host = self.host(caddyfile=self.caddyfile, sites_dir=self.sites, domain_suffix="lab.test")
        route = {"type": "reverse_proxy", "host": "pdf.lab.test", "port": "", "tls": "default", "log": True, "upstream": "10.0.0.5:80"}
        with open(os.path.join(self.sites, "pdf.caddy"), "w", encoding="utf-8", newline="\n") as handle:
            handle.write(main.render_route(route, host))
        self.assertFalse(self.checks(base, domain_suffix="lab.test")[twice])
        self.assertTrue(self.checks(base.replace("format json", "format json\n\t\texclude http.log.access"), domain_suffix="lab.test")[twice])
        # A Caddy reached over the network only: the site that serves the log has to list the directory.
        site = "admin.lab.test {\n\thandle_path /caddyman-logs/* {\n\t\troot * /var/log/caddy\n\t\tfile_server\n\t}\n}\n"
        up = mock.Mock(return_value=mock.Mock(status_code=200, content=b""))
        listed = "Rotated logs are listed"
        self.assertFalse(self.checks(site, admin=up, storage="managed", id="h1")[listed])
        self.assertTrue(self.checks(site.replace("file_server", "file_server browse"), admin=up, storage="managed", id="h1")[listed])
        self.assertNotIn(listed, self.checks("admin.lab.test {\n\trespond 200\n}\n", admin=up, storage="managed", id="h1"))
        self.assertNotIn(listed, self.checks(site))  # next door the files are read directly

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


class RouteTest(AppTest):
    def setUp(self):
        super().setUp()
        self.setup_admin()
        main.AUDIT_FILE.unlink(missing_ok=True)
        main.ROOT_CA_CACHE.clear()
        main.PROBE_CACHE.clear()
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
        self.real_reachable = main.target_reachable
        self.patch(main, "target_reachable", mock.Mock(return_value=True))
        self.served = self.patch(main, "served_certificate", mock.Mock(side_effect=OSError("offline")))

    def form(self, **overrides):
        return {"type": "reverse_proxy", "host": "pdf", "upstream": "10.0.0.5:9005", "tls": "acme_ca", **overrides}

    def create(self, **overrides):
        return self.client.post("/routes/new", data=self.form(**overrides))

    def read(self, name):
        with open(os.path.join(self.sites, name), encoding="utf-8") as handle:
            return handle.read()

    def put(self, name, text, mode="w"):
        with open(os.path.join(self.sites, name), mode, encoding="utf-8", newline="\n") as handle:
            handle.write(text)

    def reach(self, upstream):
        """Where Caddy reaches Caddyman, saved with the Caddy settings."""
        return self.client.post("/hosts/h1/edit", data={**{key: self.host[key] for key in main.HOST_DEFAULTS}, "reach": upstream})

    def reject(self):
        self.load.return_value = mock.Mock(status_code=400, json=lambda: {"error": "unknown directive"})


class TestRoutes(RouteTest):
    def test_only_over_https(self):
        # Over plain HTTP the switch cannot be set: the answer to that very request would be refused.
        self.client.post("/settings/security", data={"https_only_on": "1"})
        self.assertFalse(main.https_only())
        main.resolve_addresses.return_value = {"testclient"}
        main.CADDY_ADDRESSES["until"] = 0.0
        through = {"x-forwarded-proto": "https"}
        self.client.post("/settings/security", data={"https_only_on": "1"}, headers=through)
        self.assertTrue(main.https_only())
        self.assertEqual(self.client.get("/", headers=through).status_code, 200)
        self.assertEqual(self.client.get("/").status_code, 403)
        # What Caddy fetches itself and the health check stay open.
        self.assertEqual(self.client.get("/healthz").status_code, 200)
        self.assertEqual(self.client.get("/error/502").status_code, 502)
        self.assertNotEqual(self.client.get("/root-ca.crt").status_code, 403)
        # With a route to Caddyman the browser is sent there.
        self.client.post("/routes/new", data=self.form(host="caddyman", upstream=f"caddyman:{main.OWN_PORT}"), headers=through)
        self.assertEqual(self.client.get("/status").headers["location"], "https://caddyman.lab.test/status")
        # The way back in: the variable switches it off at the next start.
        with mock.patch.object(main, "RESET_HTTPS_ONLY", True):
            main.reset_https_only()
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_status_keeps_its_checks_for_a_moment(self):
        get = self.patch(main.httpx, "get", mock.Mock(side_effect=main.httpx.ConnectError("down")))
        self.client.get("/status")
        asked = get.call_count
        self.assertGreater(asked, 0)
        self.client.get("/status")
        self.assertEqual(get.call_count, asked)  # reloading the page asks nobody again
        # A change to the routes does.
        self.create()
        self.client.get("/status")
        self.assertGreater(get.call_count, asked)

    def test_error_pages_and_own_route_agree_where_caddyman_is(self):
        self.assertIn(f"<code>caddyman:{main.OWN_PORT}</code>", self.client.get("/error-pages").text)
        # The route to Caddyman knows better than the guess.
        self.create(host="caddyman", upstream=f"10.0.0.7:{main.OWN_PORT}")
        self.assertIn(f"<code>10.0.0.7:{main.OWN_PORT}</code>", self.client.get("/error-pages").text)
        self.assertIn(f'name="reach" value="10.0.0.7:{main.OWN_PORT}"', self.client.get("/hosts/h1/edit").text)
        self.create(host="pdf", errors="on")
        self.assertIn(f'"errors":"10.0.0.7:{main.OWN_PORT}"', self.read("pdf.caddy"))
        # What was typed under Error pages comes first, for the own route too.
        self.reach("192.168.1.9:5052")
        self.assertIn('name="upstream" value="192.168.1.9:5052"', self.client.get("/routes/new?own=1").text)

    def test_status_offers_a_route_for_caddyman_itself(self):
        hint = 'href="/routes/new?own=1"'
        self.assertIn(hint, self.client.get("/status").text)
        form = self.client.get("/routes/new?own=1").text
        self.assertIn('name="host" value="caddyman"', form)
        self.assertIn(f'name="upstream" value="caddyman:{main.OWN_PORT}"', form)
        self.assertNotIn('name="upstream" value="caddyman', self.client.get("/routes/new").text)
        self.create(host="caddyman", upstream=f"caddyman:{main.OWN_PORT}")
        status = self.client.get("/status").text
        self.assertNotIn(hint, status)
        # The box stays while this page still comes in unencrypted: now it points at the route.
        self.assertIn("Caddyman is reached without HTTPS", status)
        self.assertIn('href="https://caddyman.lab.test">Open https://caddyman.lab.test<', status)
        self.assertNotIn("HTTPS in front of Caddyman", status)  # nothing to say about HTTPS that is not there
        # Through Caddy over HTTPS, but Caddyman was not told to believe Caddy: the cookie is not Secure.
        unseen = self.client.get("/status", headers={"x-forwarded-proto": "https"}).text
        self.assertNotIn("Caddyman is reached without HTTPS", unseen)
        self.assertIn("HTTPS in front of Caddyman is recognised", unseen)
        self.assertIn("CADDYMAN_FORWARDED_ALLOW_IPS=testclient", unseen)
        # The Caddy from the settings is believed by itself: the address behind the name in the admin URL.
        main.resolve_addresses.return_value = {"testclient"}
        main.CADDY_ADDRESSES["until"] = 0.0
        through = {"x-forwarded-proto": "https", "x-forwarded-for": "198.51.100.7, 203.0.113.9"}
        trusted = self.client.get("/status", headers=through).text
        self.assertEqual(main.resolve_addresses.call_args.args, ("caddy",))
        self.assertNotIn("Caddyman is reached without HTTPS", trusted)
        self.assertNotIn("CADDYMAN_FORWARDED_ALLOW_IPS=", trusted)
        self.assertIn("HTTPS in front of Caddyman is recognised", trusted)
        # Then the session cookie is marked Secure, and the login limit counts the visitor, not Caddy.
        guest = self.guest()
        answer = guest.post("/login", data={"username": "admin", "password": "wrong"}, headers=through)
        self.assertEqual(list(main.LOGIN_FAILS), ["203.0.113.9", "login:admin"])
        answer = guest.post("/login", data={"username": "admin", "password": PASSWORD}, headers=through)
        self.assertIn("Secure", answer.headers["set-cookie"])
        # The same headers from anywhere else change nothing.
        main.resolve_addresses.return_value = {"10.9.9.9"}
        main.CADDY_ADDRESSES["until"] = 0.0
        main.LOGIN_FAILS.clear()
        answer = guest.post("/login", data={"username": "admin", "password": PASSWORD}, headers=through)
        self.assertNotIn("Secure", answer.headers["set-cookie"])
        self.assertIn("10.9.9.9", self.client.get("/status", headers=through).text)  # the hint names where Caddy was looked for
        # Deleting or switching off that route comes with a word of warning, the others are asked as before.
        self.create()
        page = self.client.get("/").text
        self.assertEqual(page.count("This route leads to Caddyman itself. Without it"), 2)
        # Coming in through it makes that plain.
        self.assertIn("and you are using it right now. Without it", self.client.get("/", headers={"host": "caddyman.lab.test"}).text)

    def test_reverse_proxy_file(self):
        self.assertEqual(self.create().headers["location"], "/")
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
        # The mark of the open tab reaches the page as an attribute, not as escaped text.
        self.assertIn('<a href="/" aria-current="page">Routes</a>', self.client.get("/").text)

    def test_groups(self):
        plain = '# caddyman {"type":"reverse_proxy","host":"pdf.lab.test","port":"","tls":"acme_ca","upstream":"10.0.0.5:9005"}'
        self.create()
        self.assertNotIn('name="group"', self.client.get("/routes/new").text)  # nothing to pick yet
        self.assertEqual(self.client.post("/groups", data={"name": "Media"}).headers["location"], "/groups")
        self.client.post("/groups", data={"name": "media"})  # the same name again
        self.client.post("/groups", data={"name": "bad\"name"})
        self.assertEqual(main.stored_groups(), ["Media"])
        self.assertIn('<option value="Media"', self.client.get("/routes/new").text)
        # The group stands in the route file, right after the keys every route has.
        self.create(host="wiki", group="Media")
        self.assertTrue(self.read("wiki.caddy").startswith(
            '# caddyman {"type":"reverse_proxy","host":"wiki.lab.test","port":"","tls":"acme_ca","group":"Media","upstream"'))
        self.assertIn('<option value="Media" selected', self.client.get("/routes/wiki/edit").text)
        self.assertEqual(self.create(host="bad", group="{}").status_code, 400)
        page = self.client.get("/").text
        self.assertLess(page.index('colspan="7">Media<'), page.index("wiki.lab.test"))
        self.assertLess(page.index('colspan="7">No group<'), page.index("pdf.lab.test"))
        # The box that shows the list without its groups is there as long as there are groups.
        self.assertIn('name="flat"', page)
        # A rejected rename leaves file and list alone, a good one rewrites the file and stays editable.
        self.reject()
        self.client.post("/groups/rename", data={"old": "Media", "new": "Films"})
        self.assertIn('"group":"Media"', self.read("wiki.caddy"))
        self.assertEqual(main.stored_groups(), ["Media"])
        self.load.return_value = mock.Mock(status_code=200)
        self.client.post("/groups/rename", data={"old": "Media", "new": "Films"})
        self.assertIn('"group":"Films","upstream"', self.read("wiki.caddy"))
        self.assertEqual(main.stored_groups(), ["Films"])
        self.assertIn('<option value="Films" selected', self.client.get("/routes/wiki/edit").text)
        # Deleting a group keeps its routes and leaves the file as if it never had one.
        self.client.post("/groups/delete", data={"name": "Films"})
        self.assertEqual(self.read("wiki.caddy").replace("wiki", "pdf"), self.read("pdf.caddy"))
        self.assertEqual(self.read("pdf.caddy").splitlines()[0], plain)
        self.assertEqual(main.stored_groups(), [])
        self.assertNotIn('colspan="7">', self.client.get("/").text)
        self.assertNotIn('name="flat"', self.client.get("/").text)

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
            # A line break at the end is no part of a name either.
            {"host": "a.b\n."},
            {"type": "redirect", "target": "http://a.b\n/", "code": "301"},
            {"allow": "fe80::1%{env.X}"},
            {"host": "x {\nrespond 200\n}"},
            {"host": ""},
            {"port": "70000"},
            {"port": "80 {"},
            {"upstream": "10.0.0.5:"},
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
        # The same holds for a save that got past the form at the very same moment.
        self.load.reset_mock()
        path = main.Path(self.sites) / "pdf.caddy"
        self.assertIn("already exists", main.apply_route(self.host, {path: "other"}, "create", "pdf", fresh=path))
        self.assertEqual(self.read("pdf.caddy"), before)
        self.load.assert_not_called()

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
        for name in ("..", "../x", "a/b", ".hidden", "", "x\n"):
            self.assertIsNone(main.route_path(self.host, name))
        self.client.post("/routes/..%2FCaddyfile/delete")
        self.assertTrue(os.path.exists(self.caddyfile))

    def test_hand_edited_file_is_no_longer_ours(self):
        self.create()
        path = main.Path(self.sites) / "pdf.caddy"
        self.assertEqual(main.read_route(path, self.host)["upstream"], "10.0.0.5:9005")
        self.put("pdf.caddy", "# tweaked\n", "a")
        self.assertIsNone(main.read_route(path, self.host))
        self.put("legacy.caddy", "legacy.lab.test {\n\trespond 200\n}\n")
        self.assertIn("legacy.caddy", self.client.get("/").text)

    def test_the_message_for_the_next_page_is_no_session(self):
        answer = self.client.post("/groups", data={"name": "Media"})
        self.assertNotIn("Secure", answer.headers["set-cookie"])
        with self.assertRaises(main.BadSignature):
            main.SESSIONS.loads(answer.cookies["caddyman_flash"])
        self.assertIn("Media was added", self.client.get("/groups").text)
        # Through Caddy over HTTPS it is marked Secure like the session cookie.
        main.resolve_addresses.return_value = {"testclient"}
        main.CADDY_ADDRESSES["until"] = 0.0
        answer = self.client.post("/groups", data={"name": "Films"}, headers={"x-forwarded-proto": "https"})
        self.assertIn("Secure", answer.headers["set-cookie"])

    def test_a_metadata_line_with_a_number_for_text_is_not_ours(self):
        # It renders to the very same file, so only its shape tells.
        route = {"type": "reverse_proxy", "host": "pdf.lab.test", "port": "", "tls": "default", "upstream": 123}
        self.put("pdf.caddy", main.render_route(route, self.host))
        self.assertIsNone(main.read_route(main.Path(self.sites) / "pdf.caddy", self.host))
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_route_list_carries_the_hidden_game(self):
        self.create()
        self.assertIn('<script src="/static/game.js" defer>', self.client.get("/").text)
        self.assertNotIn("game.js", self.client.get("/routes/new").text)
        self.assertEqual(self.client.get("/static/game.js").status_code, 200)
        # The name itself stays an ordinary hostname for the server: the game lives in the browser.
        self.assertEqual(self.create(host="candyman").headers["location"], "/")

    def test_unreachable_target_only_warns(self):
        main.target_reachable.return_value = False
        self.assertEqual(self.create().headers["location"], "/")
        self.assertIn("does not answer yet", self.client.get("/").text)
        self.assertTrue(os.path.exists(os.path.join(self.sites, "pdf.caddy")))

    def test_target_without_port(self):
        self.assertEqual(self.create(upstream="http://10.0.0.5").headers["location"], "/")
        self.assertIn("reverse_proxy 10.0.0.5\n", self.read("pdf.caddy"))  # http:// says nothing Caddy needs
        # The reachability test falls back to the port Caddy would take.
        connect = self.patch(main.socket, "create_connection", mock.MagicMock())
        for upstream, port in (("10.0.0.5", 80), ("http://10.0.0.5", 80), ("https://10.0.0.5", 443), ("10.0.0.5:9005", 9005)):
            self.assertTrue(self.real_reachable(upstream))
            self.assertEqual(connect.call_args.args[0], ("10.0.0.5", port))

    def test_list_links_host_and_target(self):
        links = lambda **route: main.route_links({"host": "pdf.lab.test", "port": "", "tls": "acme_ca", **route})  # noqa: E731
        self.assertEqual(links(type="reverse_proxy", upstream="10.0.0.5:9005"), ("https://pdf.lab.test", "http://10.0.0.5:9005"))
        self.assertEqual(links(type="reverse_proxy", upstream="https://10.0.0.5", tls="none", port="8080"),
                         ("http://pdf.lab.test:8080", "https://10.0.0.5"))
        # A container name or a loopback address is only reachable from Caddy, so there is no link to wait on.
        for upstream in ("caddyman:5052", "http://whoami", "localhost:8080", "127.0.0.1:3000"):
            self.assertEqual(links(type="reverse_proxy", upstream=upstream), ("https://pdf.lab.test", ""))
        self.assertEqual(links(type="reverse_proxy", upstream="nas.lab.test:5000")[1], "http://nas.lab.test:5000")
        self.assertEqual(links(type="redirect", target="https://x.test/a")[1], "https://x.test/a")
        self.assertEqual(links(type="redirect", target="javascript:alert(1)")[1], "")
        self.assertEqual(links(type="static", root="/srv/www")[1], "")
        self.create()
        self.assertIn('href="https://pdf.lab.test"', self.client.get("/").text)

    def test_list_marks_unreachable_target(self):
        self.create()
        self.create(type="static", host="docs", root="/srv/www", tls="none")
        self.assertNotIn("Not reachable", self.client.get("/").text)
        main.target_reachable.return_value = False
        main.PROBE_CACHE.clear()
        page = self.client.get("/").text
        self.assertEqual(page.count("Not reachable"), 1)  # reverse proxies only
        # What "Only problems" in routes.js goes by.
        self.assertEqual(page.count(" data-problem>"), 1)
        self.assertIn('src="/static/routes.js"', page)

    def test_list_keeps_what_it_found_for_a_while(self):
        self.create()
        asked = lambda: (main.target_reachable.call_count, self.served.call_count)  # noqa: E731
        main.target_reachable.reset_mock()  # saving a route looks at its target once as well
        self.client.get("/")
        first = asked()
        self.assertEqual(first, (1, 1))
        self.client.get("/")
        self.assertEqual(asked(), first)  # the second look costs nothing
        # Good news is kept longer than bad news, so something just fixed shows soon.
        kept = {key[0]: until - main.time.monotonic() for key, (until, _) in main.PROBE_CACHE.items()}
        self.assertGreater(kept["target"], 50)
        self.assertLess(kept["certificate"], 20)  # the handshake failed in this test
        # Every change to the routes forgets all of it.
        self.create(host="wiki", upstream="10.0.0.7:3000")
        main.target_reachable.reset_mock()
        self.client.get("/")
        self.assertEqual(asked(), (2, first[1] + 2))

    def test_list_does_not_wait_for_a_check_that_hangs(self):
        self.create()
        self.patch(main, "PROBE_BUDGET", 0.2)
        release = main.threading.Event()
        self.addCleanup(release.set)
        main.target_reachable.side_effect = lambda upstream: release.wait(5) and True
        self.served.side_effect = lambda *args: release.wait(5) and (_ for _ in ()).throw(OSError("late"))
        started = main.time.monotonic()
        page = self.client.get("/").text
        self.assertLess(main.time.monotonic() - started, 2)
        # A target that still does not answer counts as not reachable, the certificate as not looked at yet.
        self.assertIn("Not reachable", page)
        self.assertIn("Still checking", page)
        # What finishes later is there on the next load.
        release.set()
        main.time.sleep(0.3)
        page = self.client.get("/").text
        self.assertNotIn("Not reachable", page)
        self.assertNotIn("Still checking", page)


class TestUsers(RouteTest):
    def add_user(self, name="viewer", **fields):
        form = {"username": name, "password": PASSWORD, "repeat": PASSWORD, **fields}
        return self.client.post("/settings/users/new", data=form)

    def log_in(self, name, password=PASSWORD):
        client = self.guest()
        response = client.post("/login", data={"username": name, "password": password})
        return client, response

    def test_invitation_by_mail(self):
        new = lambda **fields: self.client.post("/settings/users/new", data={"username": "eve", **fields})  # noqa: E731
        # Without mail a password is a must, as before.
        self.assertEqual(new(email="eve@lab.test").status_code, 400)
        self.assertNotIn("invitation", self.client.get("/settings/users/new").text)
        main.write_private(main.MAIL_FILE, '{"public_url": "https://caddyman.lab.test", "host": "smtp.lab.test", "sender": "c@lab.test"}')
        self.assertIn("Leave empty to send an invitation", self.client.get("/settings/users/new").text)
        mail = self.patch(main, "send_mail", mock.Mock(return_value=None))
        self.assertEqual(new().status_code, 400)  # nowhere to send it
        self.assertEqual(new(email="eve@lab.test", password=PASSWORD, repeat="other").status_code, 400)  # a typed password still counts
        self.assertEqual(mail.call_count, 0)
        self.assertEqual(new(email="eve@lab.test").headers["location"], "/settings/users")
        to, _, body = mail.call_args.args
        self.assertEqual(to, "eve@lab.test")
        link = main.re.search(r"https://caddyman\.lab\.test(/reset\?token=\S+)", body).group(1)
        # The list shows who has not answered yet and can send the mail again.
        self.assertIn(">Invited<", self.client.get("/settings/users").text)
        self.assertEqual(self.client.post("/settings/users/eve/invite").headers["location"], "/settings/users")
        self.assertEqual(mail.call_count, 2)
        self.client.post("/settings/users/admin/invite")  # not invited: nothing goes out
        self.assertEqual(mail.call_count, 2)
        # Until the link is used nobody gets in, and there is no page to sign up on one's own.
        self.assertEqual(self.log_in("eve", "")[1].status_code, 401)
        guest = self.guest()
        self.assertEqual(guest.get("/register").headers["location"], "/login")
        with mock.patch.object(main, "INVITE_SECONDS", -1):
            self.assertEqual(guest.get(link).status_code, 400)  # too old
        self.assertEqual(guest.get(link).status_code, 200)
        form = {"token": link.split("token=")[1], "password": "her own horse", "repeat": "her own horse"}
        self.assertEqual(guest.post("/reset", data=form).headers["location"], "/login")
        self.assertEqual(guest.get(link).status_code, 400)  # once
        self.assertEqual(self.log_in("eve", "her own horse")[1].headers["location"], "/")
        self.assertNotIn(">Invited<", self.client.get("/settings/users").text)
        # A mail that does not go out leaves the account, and says so.
        mail.return_value = "connection refused"
        failed = self.client.post("/settings/users/new", data={"username": "bob", "email": "bob@lab.test"})
        self.assertIn("connection refused", self.client.get(failed.headers["location"]).text)
        self.assertIsNotNone(main.find_user(main.load_users(), "bob"))
        # A link stands for the address it went to: once that is corrected, the first mail opens nothing.
        mail.return_value = None
        self.client.post("/settings/users/bob/invite")
        first = main.re.search(r"(/reset\?token=\S+)", mail.call_args.args[2]).group(1)
        self.assertEqual(guest.get(first).status_code, 200)
        main.update_user("bob", email="robert@lab.test")
        self.assertEqual(guest.get(first).status_code, 400)
        self.client.post("/settings/users/bob/invite")
        self.assertEqual(guest.get(main.re.search(r"(/reset\?token=\S+)", mail.call_args.args[2]).group(1)).status_code, 200)

    def test_account_from_before_there_were_users_keeps_every_right(self):
        main.write_private(main.AUTH_FILE, '{"username": "admin", "password_hash": "%s"}' % main.hash_password(PASSWORD))
        self.assertEqual(main.load_users()[0]["permissions"], list(main.PERMISSIONS))
        client, response = self.log_in("admin")
        self.assertEqual(response.headers["location"], "/")
        self.assertEqual(client.get("/settings/users").status_code, 200)

    def test_rights_are_checked_for_every_area(self):
        self.assertEqual(self.add_user().headers["location"], "/settings/users")
        viewer, _ = self.log_in("viewer")
        for path in ("/", "/status", "/profile"):
            self.assertEqual(viewer.get(path).status_code, 200, path)
        for path in ("/settings/users", "/settings/users/new", "/groups", "/backup", "/backup/download", "/logs", "/ca", "/ca/root-ca.crt", "/hosts/h1/edit", "/routes/new",
                     "/settings", "/settings/caddy", "/settings/mail", "/settings/security"):
            self.assertEqual(viewer.get(path).status_code, 403, path)
        self.assertEqual(viewer.post("/routes/new", data=self.form()).status_code, 403)
        self.assertEqual(viewer.post("/hosts/h1/push").status_code, 403)
        self.assertEqual(viewer.post("/hosts/h1/delete").status_code, 403)
        self.assertEqual(viewer.post("/settings/users/admin/delete").status_code, 403)
        self.assertEqual(os.listdir(self.sites), [])
        self.assertEqual(len(main.load_hosts()), 1)
        # Nothing to click that would be refused anyway.
        self.assertNotIn("Add route", viewer.get("/").text)
        self.assertNotIn('href="/settings"', viewer.get("/").text)
        # One right more, and exactly that area opens.
        self.client.post("/settings/users/viewer/edit", data={"right_routes": "1"})
        self.assertEqual(viewer.post("/routes/new", data=self.form()).headers["location"], "/")
        self.assertEqual(main.read_audit()[0]["user"], "viewer")
        self.assertEqual(viewer.post("/hosts/h1/push").status_code, 303)
        self.assertEqual(viewer.get("/hosts/h1/edit").status_code, 403)

    def test_users_are_validated_and_one_manager_always_remains(self):
        bad = [{"name": ""}, {"name": "admin"}, {"email": "not an address"}, {"repeat": "different"}, {"password": "short", "repeat": "short"}]
        for fields in bad:
            with self.subTest(fields):
                self.assertEqual(self.add_user(**fields).status_code, 400)
        self.assertEqual(len(main.load_users()), 1)
        self.add_user("eve", email="eve@lab.test", right_users="1")
        self.assertEqual(self.add_user("bob", email="EVE@lab.test").status_code, 400)  # one account per address
        self.assertNotIn(PASSWORD, main.AUTH_FILE.read_text())
        # Nobody removes themselves, by deleting or by dropping the right.
        self.assertIn("cannot delete your own", self.client.get(self.client.post("/settings/users/admin/delete").headers["location"]).text)
        self.assertEqual(self.client.post("/settings/users/admin/edit", data={"right_routes": "1"}).status_code, 400)
        self.assertEqual(len(main.load_users()), 2)
        eve, _ = self.log_in("eve")
        self.assertEqual(eve.post("/settings/users/admin/delete").headers["location"], "/settings/users")
        self.assertEqual([user["username"] for user in main.load_users()], ["eve"])
        self.assertEqual(self.client.get("/").headers["location"], "/login")  # a deleted account is logged out

    def test_settings_tab_shows_each_account_its_own_blocks(self):
        self.assertEqual(self.client.get("/settings").headers["location"], "/settings/caddy")
        self.assertEqual(self.client.get("/settings/caddy").headers["location"], "/hosts/h1/edit")
        everything = self.client.get("/hosts/h1/edit").text
        for block in ("/settings/caddy", "/settings/mail", "/settings/users", "/settings/security"):
            self.assertIn(f'href="{block}"', everything)
        # Managing users does not open the connection to Caddy.
        self.add_user("eve", right_users="1")
        eve, _ = self.log_in("eve")
        self.assertIn('href="/settings"', eve.get("/").text)
        self.assertEqual(eve.get("/settings").headers["location"], "/settings/users")
        page = eve.get("/settings/users")
        self.assertEqual(page.status_code, 200)
        self.assertNotIn('href="/settings/mail"', page.text)
        for path in ("/settings/mail", "/settings/security", "/hosts/h1/edit"):
            self.assertEqual(eve.get(path).status_code, 403, path)

    def test_second_factor_can_be_required_for_everybody(self):
        self.add_user()
        viewer, _ = self.log_in("viewer")
        self.assertEqual(viewer.get("/").status_code, 200)
        self.assertIn("viewer", self.client.get("/settings/security").text)  # named as being without one
        self.client.post("/settings/security", data={"require_2fa": "1"})
        # Nothing but the profile until it is set up, for the one who switched it on as well.
        for client in (viewer, self.client):
            self.assertEqual(client.get("/").headers["location"], "/profile#two-factor")
            self.assertEqual(client.get("/status").headers["location"], "/profile#two-factor")
            self.assertIn("is required here", client.get("/profile").text)
        self.assertEqual(self.client.post("/routes/new", data=self.form()).headers["location"], "/profile#two-factor")
        self.assertEqual(os.listdir(self.sites), [])
        viewer.post("/profile/2fa/start", data={"current": PASSWORD})
        secret = main.totp_secret(main.find_user(main.load_users(), "viewer"), "totp_pending")
        viewer.post("/profile/2fa/confirm", data={"code": main.totp_code(secret, int(main.time.time()) // main.TOTP_SECONDS)})
        self.assertEqual(viewer.get("/").status_code, 200)
        self.assertEqual(self.client.get("/").status_code, 303)

    def test_changing_the_password_ends_the_other_sessions(self):
        other, _ = self.log_in("admin")
        self.assertEqual(other.get("/").status_code, 200)
        form = {"current": "wrong", "password": "another horse", "repeat": "another horse"}
        self.assertEqual(self.client.post("/profile/password", data=form).status_code, 400)
        self.assertEqual(self.client.post("/profile/password", data={**form, "current": PASSWORD}).headers["location"], "/profile")
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(other.get("/").headers["location"], "/login")
        self.assertEqual(self.log_in("admin")[1].status_code, 401)
        self.assertEqual(self.log_in("admin", "another horse")[1].headers["location"], "/")

    def test_two_factor_login(self):
        # A session alone does not set it up: that takes the password, like switching it off.
        self.assertEqual(self.client.post("/profile/2fa/start").status_code, 400)
        self.assertNotIn("totp_pending", main.load_users()[0])
        self.client.post("/profile/2fa/start", data={"current": PASSWORD})
        secret = main.totp_secret(main.load_users()[0], "totp_pending")
        self.assertIn(secret, self.client.get("/profile").text)
        self.assertIn("<svg", self.client.get("/profile").text)
        self.assertEqual(self.client.post("/profile/2fa/confirm", data={"code": "000000"}).status_code, 400)
        step = int(main.time.time()) // main.TOTP_SECONDS
        done = self.client.post("/profile/2fa/confirm", data={"code": main.totp_code(secret, step)})
        codes = main.re.findall(r"[0-9a-f]{5}-[0-9a-f]{5}", done.text)
        self.assertEqual(len(codes), main.RECOVERY_CODES)
        self.assertNotIn(secret, main.AUTH_FILE.read_text())  # encrypted at rest
        self.assertNotIn(codes[0].replace("-", ""), main.AUTH_FILE.read_text())
        # One that is on is not replaced, neither by a new start nor by a key left pending.
        kept = main.load_users()[0]["totp"]
        self.client.post("/profile/2fa/start", data={"current": PASSWORD})
        self.assertNotIn("totp_pending", main.load_users()[0])
        other = main.base64.b32encode(b"another key of 20 by").decode()
        main.update_user("admin", totp_pending=main.seal(other))
        self.assertEqual(self.client.post("/profile/2fa/confirm", data={"code": main.totp_code(other, step)}).status_code, 400)
        self.assertEqual(main.load_users()[0]["totp"], kept)
        main.update_user("admin", totp_pending=None)

        client, response = self.log_in("admin")
        self.assertEqual(response.headers["location"], "/login/code")
        self.assertEqual(client.get("/").headers["location"], "/login")  # the password alone opens nothing
        self.assertEqual(client.post("/login/code", data={"code": "123456"}).status_code, 401)
        # The code that switched it on was used once already and is not taken a second time.
        self.assertEqual(client.post("/login/code", data={"code": main.totp_code(secret, step)}).status_code, 401)
        self.assertEqual(client.post("/login/code", data={"code": main.totp_code(secret, step + 1)}).headers["location"], "/")
        self.assertEqual(client.get("/").status_code, 200)

        # A recovery code works in place of the app, once.
        for expected in (303, 401):
            main.LOGIN_FAILS.clear()
            client, _ = self.log_in("admin")
            self.assertEqual(client.post("/login/code", data={"code": codes[0].upper()}).status_code, expected)
        # Without having passed the password there is no second step.
        self.assertEqual(self.guest().post("/login/code", data={"code": codes[1]}).headers["location"], "/login")
        # Wrong codes count against the account as well, so another address is no way around the limit.
        main.LOGIN_FAILS.clear()
        client, _ = self.log_in("admin")
        for _ in range(main.MAX_LOGIN_FAILS):
            client.post("/login/code", data={"code": "000000"})
        main.LOGIN_FAILS.pop("testclient")
        self.assertEqual(client.post("/login/code", data={"code": codes[1]}).status_code, 429)
        main.LOGIN_FAILS.clear()
        # A code is used up where it is checked: an account read a moment earlier does not pass it twice.
        stale = main.find_user(main.load_users(), "admin")
        self.assertTrue(main.second_factor_ok(stale, codes[2]))
        self.assertFalse(main.second_factor_ok(stale, codes[2]))

        self.assertEqual(self.client.post("/profile/2fa/disable", data={"current": "wrong"}).status_code, 400)
        self.client.post("/profile/2fa/disable", data={"current": PASSWORD})
        self.assertEqual(self.log_in("admin")[1].headers["location"], "/")
        self.assertNotIn("totp", main.load_users()[0])

    def test_light_look_is_a_choice_of_the_account(self):
        self.assertNotIn("data-theme", self.client.get("/").text)
        # The button in the bar switches and leads back to where it was pressed.
        self.assertIn('title="Switch to the light look"', self.client.get("/status").text)
        self.assertIn('name="back" value="/logs?level=error"', self.client.get("/logs?level=error").text)
        self.assertEqual(self.client.post("/profile/theme", data={"back": "/status"}).headers["location"], "/status")
        self.assertEqual(main.load_users()[0]["theme"], "light")
        page = self.client.get("/").text
        self.assertIn('<html lang="en" data-theme="light">', page)
        self.assertIn('title="Switch to the dark look"', page)
        # Saving the profile leaves the choice alone.
        self.client.post("/profile", data={"realname": "", "email": "", "current": PASSWORD})
        self.assertEqual(main.load_users()[0]["theme"], "light")
        # Another account and the pages before the login keep the dark one.
        self.add_user()
        self.assertNotIn("data-theme", self.log_in("viewer")[0].get("/").text)
        self.assertNotIn("data-theme", self.guest().get("/login").text)
        # Dark again is simply not stored, and the way back never leaves this site.
        for elsewhere in ("https://evil.example", "//evil.example", ""):  # three presses: dark, light, dark
            self.assertEqual(self.client.post("/profile/theme", data={"back": elsewhere}).headers["location"], "/")
        self.assertNotIn("theme", main.load_users()[0])
        self.assertNotIn("data-theme", self.client.get("/").text)

    def test_changing_the_email_address_takes_the_password(self):
        self.assertEqual(self.client.post("/profile", data={"realname": "Ada", "email": "ada@lab.test"}).status_code, 400)
        self.assertEqual(main.load_users()[0].get("email", ""), "")
        self.client.post("/profile", data={"realname": "Ada", "email": "ada@lab.test", "current": PASSWORD})
        self.assertEqual(main.load_users()[0]["email"], "ada@lab.test")
        # The name alone needs none.
        self.assertEqual(self.client.post("/profile", data={"realname": "Ada A.", "email": "ada@lab.test"}).headers["location"], "/profile")

    def test_what_caddy_said_is_only_for_who_may_change_routes(self):
        self.reject()
        self.create()
        self.assertIn("unknown directive", self.client.get("/changes").text)
        self.add_user("viewer")
        viewer, _ = self.log_in("viewer")
        page = viewer.get("/changes").text
        self.assertNotIn("unknown directive", page)
        self.assertIn("<code>rejected</code>", page)

    def test_import_takes_the_right_for_routes_too(self):
        self.add_user("keeper", right_backup="1")
        keeper, _ = self.log_in("keeper")
        # The archive holds the route files, with the hashes of their logins: the same two rights.
        self.assertEqual(keeper.get("/backup/download").status_code, 403)
        self.assertNotIn('href="/backup/download"', keeper.get("/backup").text)
        self.assertNotIn('action="/backup/import"', keeper.get("/backup").text)
        self.assertEqual(keeper.post("/backup/import", data={"payload": ""}).status_code, 403)
        self.add_user("both", right_backup="1", right_routes="1")
        both, _ = self.log_in("both")
        self.assertIn('action="/backup/import"', both.get("/backup").text)
        self.assertEqual(both.get("/backup/download").status_code, 200)
        self.assertNotEqual(both.post("/backup/import", data={"payload": ""}).status_code, 403)

    def test_trust_page_switched_off_is_part_of_the_root_ca_right(self):
        self.add_user("viewer")
        viewer, _ = self.log_in("viewer")
        self.assertNotEqual(viewer.get("/trust").status_code, 403)
        self.client.post("/settings/security", data={"login_ca_hint": "1"})  # the box for the open page unticked
        self.assertEqual(self.guest().get("/trust").headers["location"], "/login")
        for path in ("/trust", "/root-ca.crt"):
            self.assertEqual(viewer.get(path).status_code, 403)
            self.assertNotEqual(self.client.get(path).status_code, 403)

    def test_mail_settings_take_the_right_to_manage_users_too(self):
        # The reset links of all accounts travel through the mail server.
        mail = {"host": "smtp.lab.test", "port": "25", "sender": "c@lab.test", "security": "none", "public_url": "https://caddyman.lab.test"}
        self.add_user("ops", right_settings="1")
        ops, _ = self.log_in("ops")
        self.assertEqual(ops.get("/settings/mail").status_code, 200)
        self.assertEqual(ops.post("/settings/mail", data=mail).status_code, 403)
        self.assertEqual(main.load_mail()["host"], "")
        self.add_user("both", right_settings="1", right_users="1")
        both, _ = self.log_in("both")
        self.assertEqual(both.post("/settings/mail", data=mail).headers["location"], "/settings/mail")
        self.assertEqual(main.load_mail()["host"], "smtp.lab.test")

    def test_forgotten_password_by_mail(self):
        self.client.post("/profile", data={"realname": "Ada Admin", "email": "ada@lab.test", "current": PASSWORD})
        self.assertIn(">AA<", self.client.get("/profile").text)  # initials stand in for a picture
        guest = self.guest()
        self.assertEqual(guest.get("/forgot").status_code, 404)  # no mail server, no offer
        self.assertNotIn("/forgot", guest.get("/login").text)
        settings = {"public_url": "https://caddyman.lab.test/", "host": "smtp.lab.test", "port": "587", "security": "starttls",
                    "user": "caddyman", "password": "mail-secret", "sender": "caddyman@lab.test"}
        for wrong in ({"sender": "nobody"}, {"port": "0"}, {"public_url": "caddyman.lab.test"}, {"security": "magic"}):
            self.assertEqual(self.client.post("/settings/mail", data={**settings, **wrong}).status_code, 400)
        self.assertEqual(self.client.post("/settings/mail", data=settings).headers["location"], "/settings/mail")
        self.assertNotIn("mail-secret", main.MAIL_FILE.read_text())  # encrypted at rest
        self.assertNotIn("mail-secret", self.client.get("/settings/mail").text)
        # An empty password field keeps the stored one.
        self.client.post("/settings/mail", data={**settings, "password": ""})
        self.assertEqual(main.VAULT.decrypt(main.load_mail()["password_enc"].encode()), b"mail-secret")
        # A mail server with a certificate from a private CA: its root is pasted in and used for the check.
        from cryptography.hazmat.primitives.serialization import Encoding

        pem = make_certificate("Lab Root CA").public_bytes(Encoding.PEM).decode().strip()
        self.assertEqual(self.client.post("/settings/mail", data={**settings, "ca": "not a certificate"}).status_code, 400)
        self.assertEqual(main.load_mail()["ca"], "")
        self.client.post("/settings/mail", data={**settings, "password": "", "ca": f"copied from somewhere\n{pem}\n"})
        self.assertEqual(main.load_mail()["ca"], pem)
        self.assertIn("Check code of what is stored", self.client.get("/settings/mail").text)
        with mock.patch.object(main.ssl, "create_default_context") as context, mock.patch.object(main.smtplib, "SMTP"):
            self.assertIsNone(main.send_mail("ada@lab.test", "subject", "body"))
        context.return_value.load_verify_locations.assert_called_once_with(cadata=pem)
        mail = self.patch(main, "send_mail", mock.Mock(return_value="connection refused"))
        self.assertIn("connection refused", self.client.get(self.client.post("/settings/mail/test").headers["location"]).text)
        mail.return_value = None
        thread = self.patch(main.threading, "Thread", mock.Mock())
        self.assertIn("/forgot", guest.get("/login").text)
        # The answer is the same for an account that does not exist, and no mail goes out.
        unknown = guest.post("/forgot", data={"account": "nobody"})
        known = guest.post("/forgot", data={"account": "ADA@lab.test"}, headers={"host": "evil.test"})
        self.assertEqual(unknown.text, known.text)
        self.assertEqual(thread.call_count, 1)
        thread.call_args.kwargs["target"](*thread.call_args.kwargs["args"])
        to, _, body = mail.call_args.args
        self.assertEqual(to, "ada@lab.test")
        # The link points at the configured address, whatever host the request named.
        link = main.re.search(r"https://caddyman\.lab\.test(/reset\?token=\S+)", body).group(1)
        self.assertEqual(guest.get(link).status_code, 200)
        token = link.split("token=")[1]
        form = {"token": token, "password": "another horse", "repeat": "another horse"}
        self.assertEqual(guest.post("/reset", data={**form, "repeat": "x"}).status_code, 400)
        self.assertEqual(guest.post("/reset", data=form).headers["location"], "/login")
        self.assertEqual(self.log_in("admin", "another horse")[1].headers["location"], "/")
        # Used once, the link is dead, and so is a made-up one.
        self.assertEqual(guest.post("/reset", data=form).status_code, 400)
        self.assertEqual(guest.get("/reset?token=forged").status_code, 400)


class TestCa(RouteTest):
    # Not a real certificate: the page only needs something that decodes from PEM.
    PEM = "-----BEGIN CERTIFICATE-----\ndGVzdA==\n-----END CERTIFICATE-----"
    SHA256 = "9F:86:D0:81:88:4C:7D:65:9A:2F:EA:A0:C5:5A:D0:15:A3:BF:4F:1B:2B:0B:82:2C:D1:5D:6C:15:B0:F0:0A:08"

    def answer(self, status_code=200, text="", json=None):
        reply = mock.Mock(status_code=status_code, text=text)
        reply.json = mock.Mock(return_value=json) if json is not None else mock.Mock(side_effect=ValueError("no json"))
        self.get = self.patch(main.httpx, "get", mock.Mock(return_value=reply))

    def test_external_source(self):
        main.save_hosts([{**self.host, "root_ca_url": "https://ca.lab.test:9001/roots.pem"}])
        self.answer(text=f"junk before\n{self.PEM}\ntrailing junk")
        page = self.client.get("/ca").text
        self.assertIn(self.SHA256, page)
        self.assertNotIn("Caddy's internal CA:", page)
        self.assertEqual(self.get.call_args.args[0], "https://ca.lab.test:9001/roots.pem")
        download = self.client.get("/ca/root-ca.crt")
        self.assertEqual(download.text, self.PEM + "\n")  # only the certificate, nothing around it
        self.assertIn("attachment", download.headers["content-disposition"])

    def test_falls_back_to_caddys_internal_ca(self):
        self.answer(json={"root_certificate": self.PEM + "\n"})
        page = self.client.get("/ca").text
        self.assertIn(self.SHA256, page)
        self.assertIn("Caddy's internal CA:", page)
        self.assertTrue(self.get.call_args.args[0].endswith("/pki/ca/local"))

    def test_unusable_source_is_reported_and_not_served(self):
        main.save_hosts([{**self.host, "root_ca_url": "https://ca.lab.test:9001/roots.pem"}])
        for reply in ({"text": "<html>not found</html>", "status_code": 404}, {"text": "no certificate here"}):
            with self.subTest(reply):
                self.answer(**reply)
                self.assertIn("did not answer with a certificate", self.client.get("/ca").text)
                self.assertEqual(self.client.get("/ca/root-ca.crt").status_code, 502)
        self.patch(main.httpx, "get", mock.Mock(side_effect=main.httpx.ConnectError("refused")))
        self.assertIn("refused", self.client.get("/ca").text)

    def test_several_certificates_each_get_their_own_round(self):
        other = "-----BEGIN CERTIFICATE-----\nb3RoZXI=\n-----END CERTIFICATE-----"
        main.save_hosts([{**self.host, "root_ca_url": "https://ca.lab.test:9001/roots.pem"}])
        # One certificate: nothing carries a number.
        self.answer(text=self.PEM)
        page = self.client.get("/trust").text
        self.assertIn('href="/root-ca.crt">Download root-ca.crt<', page)
        self.assertNotIn("cert=", page)
        main.ROOT_CA_CACHE.clear()
        self.answer(text=f"{self.PEM}\n{other}")
        # The admin sees a check code for each.
        page = self.client.get("/ca").text
        self.assertIn("9F86 D081 884C", page)
        digest = main.hashlib.sha256(b"other").hexdigest().upper()
        self.assertIn(f"{digest[:4]} {digest[4:8]} {digest[8:12]}", page)
        # A device takes only the first certificate out of a file: the second has its own page, file and command.
        first, second = self.client.get("/trust").text, self.client.get("/trust?cert=2&os=linux").text
        self.assertIn("<strong>2 certificates</strong>", first)
        self.assertIn('FromBase64String("dGVzdA==")', first)
        self.assertIn('href="/root-ca.crt?cert=1">Download root-ca-1.crt<', first)
        self.assertIn('href="?os=macos&amp;cert=1"', first)
        self.assertIn("sudo cp root-ca-2.crt /usr/local/share/ca-certificates/root-ca-2.crt", second)
        self.assertIn('FromBase64String("b3RoZXI=")', self.client.get("/trust?cert=2").text)
        self.assertIn('FromBase64String("dGVzdA==")', self.client.get("/trust?cert=9").text)  # no such one: the first
        # The plain address still hands out everything, a number just that one.
        self.assertEqual(self.client.get("/root-ca.crt").text, f"{self.PEM}\n{other}\n")
        one = self.client.get("/root-ca.crt?cert=2")
        self.assertEqual(one.text, other + "\n")
        self.assertIn('filename="root-ca-2.crt"', one.headers["content-disposition"])
        self.assertEqual(self.client.get("/ca/root-ca.crt?cert=1").text, self.PEM + "\n")
        self.assertEqual(self.client.get("/root-ca.crt?cert=3").status_code, 404)

    def test_needs_a_session(self):
        self.client.cookies.clear()
        self.assertEqual(self.client.get("/ca/root-ca.crt").headers["location"], "/login")
        self.assertEqual(self.client.get("/ca").headers["location"], "/login")

    def test_open_page_and_download_without_a_session(self):
        self.answer(json={"root_certificate": self.PEM})
        self.assertIn("9F86 D081 884C", self.client.get("/ca").text)  # the admin sees the check code
        self.client.cookies.clear()
        page = self.client.get("/trust")
        self.assertEqual(page.status_code, 200)
        # Nothing a forged copy of the page could lie about, and nothing about the setup behind it.
        for hidden in ("9F86 D081 884C", self.SHA256, "/pki/ca/local", "Back up the CA"):
            self.assertNotIn(hidden, page.text)
        self.assertIn('FromBase64String("dGVzdA==")', page.text)
        # One system at a time: Windows first, the others from the list at the left edge.
        self.assertIn("<h2>Windows</h2>", page.text)
        self.assertNotIn("<h2>macOS</h2>", page.text)
        for key, system in (("macos", "macOS"), ("linux", "Debian and Ubuntu"), ("ios", "iPhone and iPad"),
                            ("android", "Android"), ("chrome", "Chrome and Edge"), ("firefox", "Firefox"),
                            ("nonsense", "Windows")):
            self.assertIn(f'href="?os={key}"' if key != "nonsense" else "<aside", page.text)
            self.assertIn(f"<h2>{system}</h2>", self.client.get(f"/trust?os={key}").text)
        self.assertEqual(self.client.get("/root-ca.crt").text, self.PEM + "\n")
        # Anyone can call these, so the source is not asked again for every request.
        self.assertEqual(self.get.call_count, 2)  # once for /ca, once for the open pages
        main.ROOT_CA_CACHE.clear()
        self.answer(text="gone", status_code=500)
        self.assertEqual(self.client.get("/root-ca.crt").status_code, 503)
        failed = self.client.get("/trust")
        self.assertEqual(failed.status_code, 503)
        self.assertNotIn("did not answer", failed.text)  # the full message names the admin API

    def test_open_page_and_login_hint_can_be_switched_off(self):
        self.answer(json={"root_certificate": self.PEM})
        guest = self.guest()
        self.assertIn('href="/trust"', guest.get("/login").text)
        self.client.post("/settings/security", data={"public_ca": "1"})
        self.assertNotIn('href="/trust"', guest.get("/login").text)
        self.assertEqual(guest.get("/trust").status_code, 200)  # only the card is gone
        self.assertIn("For people without a login", self.client.get("/ca").text)
        self.client.post("/settings/security", data={"login_ca_hint": "1"})
        # With the open page switched off the admin page says so instead of sending people to it.
        closed = self.client.get("/ca").text
        self.assertIn("<h2>Check code</h2>", closed)
        self.assertNotIn("For people without a login", closed)
        self.assertNotIn('href="/trust"', guest.get("/login").text)
        for path in main.PUBLIC_PATHS:
            self.assertEqual(guest.get(path).headers["location"], "/login")
        self.assertEqual(self.client.get("/settings/security").text.count(" checked"), 1)

    def test_switches_from_the_old_caddy_settings_are_kept(self):
        # Up to 0.9.0 the two switches were stored with the host. Saving the Caddy form must not open the page again.
        self.answer(json={"root_certificate": self.PEM})
        main.save_hosts([{**self.host, "public_ca": "", "login_ca_hint": "1"}])
        guest = self.guest()
        self.assertEqual(guest.get("/trust").headers["location"], "/login")
        self.assertEqual(self.client.post("/hosts/h1/edit", data=self.host).headers["location"], "/status")
        self.assertNotIn("public_ca", main.load_hosts()[0])
        self.assertEqual(guest.get("/trust").headers["location"], "/login")


class TestManaged(AppTest):
    BASE = "{\n\temail a@lab.test\n}\n\n(stepca) {\n\ttls internal\n}\n\n:2020 {\n\treverse_proxy localhost:2019\n}"

    def setUp(self):
        super().setUp()
        self.setup_admin()
        shutil.rmtree(main.DATA_DIR / "hosts", ignore_errors=True)
        self.post = self.patch(main.httpx, "post", mock.Mock(return_value=mock.Mock(status_code=200)))
        self.get = self.patch(main.httpx, "get", mock.Mock(return_value=mock.Mock(status_code=200, content=b"running")))
        self.patch(main, "target_reachable", mock.Mock(return_value=True))
        self.patch(main, "served_certificate", mock.Mock(side_effect=OSError("offline")))

    def form(self, **overrides):
        return {
            **main.HOST_DEFAULTS,
            "name": "remote",
            "storage": "managed",
            "admin_url": "https://admin.lab.test",
            "base_caddyfile": self.BASE,
            "admin_user": "caddyman",
            "admin_password": "admin-secret",
            "tls_snippet": "stepca",
            "domain_suffix": "lab.test",
            **overrides,
        }

    def add_host(self, **overrides):
        response = self.client.post("/hosts/new", data=self.form(**overrides))
        return response, (main.load_hosts() or [None])[0]

    def add_route(self):
        data = {"type": "reverse_proxy", "host": "pdf", "upstream": "10.0.0.5:9005", "tls": "acme_ca"}
        return self.client.post("/routes/new", data=data)

    def test_ca_of_an_https_admin_api_is_remembered(self):
        from cryptography.hazmat.primitives.serialization import Encoding

        pem = make_certificate("Caddy Local Authority").public_bytes(Encoding.PEM).decode()
        self.get.return_value = mock.Mock(status_code=200, content=b"running", json=lambda: {"root_certificate": pem})
        _, host = self.add_host()
        # A private CA is the normal case for this address, and the container does not know it.
        self.assertIn("BEGIN CERTIFICATE", host["admin_ca"])
        self.assertIsInstance(main.admin_verify(host), main.ssl.SSLContext)
        self.add_route()
        self.assertIs(self.post.call_args.kwargs["verify"], main.admin_verify(host))
        self.assertIn("CA of the admin API is remembered", [check["label"] for check in main.preflight(host)])
        # From then on the login only goes to a server that shows this CA, also when the open
        # page fetches the root certificate.
        main.ROOT_CA_CACHE.clear()
        self.guest().get("/trust")
        self.assertTrue(self.get.call_args.args[0].endswith("/pki/ca/local"))
        self.assertIs(self.get.call_args.kwargs["verify"], main.admin_verify(host))
        # Saving again while the CA cannot be fetched keeps what is there.
        self.get.return_value = mock.Mock(status_code=500, content=b"")
        self.client.post(f"/hosts/{host['id']}/edit", data=self.form(admin_password=""))
        self.assertEqual(main.load_hosts()[0]["admin_ca"], host["admin_ca"])
        # The login that was kept went out checked against that CA, not to whoever answered.
        self.assertIs(self.get.call_args.kwargs["verify"], main.admin_verify(host))
        # And it is not kept for another address: that would send it wherever the form points.
        moved = self.client.post(f"/hosts/{host['id']}/edit", data=self.form(admin_password="", admin_url="http://caddy2:2020"))
        self.assertEqual(moved.status_code, 400)
        self.assertEqual(main.load_hosts()[0]["admin_url"], "https://admin.lab.test")
        # Plain http has no certificate to check.
        self.client.post(f"/hosts/{host['id']}/edit", data=self.form(admin_url="http://caddy2:2020"))
        self.assertNotIn("admin_ca", main.load_hosts()[0])
        self.assertIs(main.admin_verify(main.load_hosts()[0]), True)

    def test_ca_of_the_admin_api_can_be_entered_instead_of_fetched(self):
        from cryptography.hazmat.primitives.serialization import Encoding

        fetched = make_certificate("Caddy Local Authority").public_bytes(Encoding.PEM).decode()
        own = make_certificate("Lab Root CA").public_bytes(Encoding.PEM).decode().strip()
        self.get.return_value = mock.Mock(status_code=200, content=b"running", json=lambda: {"root_certificate": fetched})
        self.assertEqual(self.add_host(admin_ca="not a certificate")[0].status_code, 400)
        _, host = self.add_host(admin_ca=f"a note\n{own}\n")
        # What was pasted is taken as it stands; whoever sits on the wire has no say in it.
        self.assertEqual((host["admin_ca"], host["admin_ca_pasted"]), (own, "1"))
        self.assertIn("entered in the settings", next(c["detail"] for c in main.preflight(host) if "remembered" in c["label"]))
        form = self.client.get(f"/hosts/{host['id']}/edit").text
        self.assertIn(own.splitlines()[1], form)
        # Saving the form as it is keeps it; emptying the field goes back to fetching.
        self.client.post(f"/hosts/{host['id']}/edit", data=self.form(admin_password="", admin_ca=own))
        self.assertEqual(main.load_hosts()[0]["admin_ca"], own)
        self.client.post(f"/hosts/{host['id']}/edit", data=self.form(admin_password=""))
        saved = main.load_hosts()[0]
        self.assertNotIn("admin_ca_pasted", saved)
        self.assertEqual(saved["admin_ca"].strip(), fetched.strip())
        self.assertNotIn(own.splitlines()[1], self.client.get(f"/hosts/{host['id']}/edit").text)  # a fetched one is not put into the field

    def test_unknown_ca_is_explained_on_the_status_page(self):
        _, host = self.add_host()
        refused = main.httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")
        with mock.patch.object(main.httpx, "get", mock.Mock(side_effect=refused)):
            check = next(check for check in main.preflight(host) if check["label"] == "Admin API is reachable")
        self.assertFalse(check["ok"])
        self.assertIn("Save and check", check["hint"])

    def test_host_keeps_its_files_in_the_data_directory(self):
        response, host = self.add_host()
        self.assertEqual(response.headers["location"], "/status")
        directory = main.DATA_DIR / "hosts" / host["id"]
        self.assertEqual((directory / "Caddyfile").read_text(), self.BASE + "\n")
        self.assertTrue((directory / "sites").is_dir())
        self.assertEqual(host["sites_dir"], str(directory / "sites"))
        # Whatever the form says about paths is ignored for this layout.
        self.client.post(f"/hosts/{host['id']}/edit", data=self.form(admin_password="", sites_dir="/etc"))
        self.assertEqual(main.load_hosts()[0]["sites_dir"], str(directory / "sites"))

    def test_password_is_stored_encrypted_and_sent_as_login(self):
        _, host = self.add_host()
        stored = main.HOSTS_FILE.read_text()
        self.assertNotIn("admin-secret", stored)
        self.assertEqual(main.admin_auth(host), ("caddyman", "admin-secret"))
        self.add_route()
        self.assertEqual(self.post.call_args.kwargs["auth"], ("caddyman", "admin-secret"))
        self.assertNotIn("admin-secret", self.client.get(f"/hosts/{host['id']}/edit").text)

    def test_empty_password_keeps_the_old_one(self):
        _, host = self.add_host()
        self.client.post(f"/hosts/{host['id']}/edit", data=self.form(admin_password=""))
        self.assertEqual(main.admin_auth(main.load_hosts()[0]), ("caddyman", "admin-secret"))
        self.assertEqual(self.client.post(f"/hosts/{host['id']}/edit", data=self.form(admin_user="eve", admin_password="")).status_code, 400)
        # The layout of an existing host cannot be switched through the form.
        self.client.post(f"/hosts/{host['id']}/edit", data=self.form(admin_password="", storage="mounted"))
        self.assertEqual(main.load_hosts()[0]["storage"], "managed")

    def test_missing_pieces_are_refused(self):
        self.assertEqual(self.add_host(base_caddyfile="  ")[0].status_code, 400)
        self.assertEqual(self.add_host(admin_password="")[0].status_code, 400)
        self.assertEqual(self.add_host(admin_user="a b")[0].status_code, 400)
        self.assertEqual(self.add_host(storage="elsewhere")[0].status_code, 400)
        self.assertEqual(main.load_hosts(), [])

    def test_push_carries_base_and_routes_inline(self):
        _, host = self.add_host()
        self.assertEqual(self.add_route().headers["location"], "/")
        route_file = main.Path(host["sites_dir"]) / "pdf.caddy"
        body = self.post.call_args.kwargs["content"].decode()
        self.assertEqual(body, self.BASE + "\n\n" + route_file.read_text())
        self.assertEqual(self.post.call_args.kwargs["headers"], {"Content-Type": "text/caddyfile"})
        self.assertNotIn("import /", body)

    def test_status_notices_when_caddy_lost_the_pushed_config(self):
        _, host = self.add_host()
        label = "Caddy runs what Caddyman pushed"
        checks = lambda: {check["label"]: check["ok"] for check in main.preflight(main.load_hosts()[0])}  # noqa: E731
        self.assertFalse(checks()[label])  # nothing pushed yet
        self.assertEqual(self.client.post(f"/hosts/{host['id']}/push").headers["location"], f"/status#host-{host['id']}")
        self.assertTrue(checks()[label])
        self.patch(main, "fetch_root_ca", mock.Mock(return_value=("pem", "source", True)))
        self.assertEqual(set(checks().values()), {True})
        # Caddy restarted without --resume and serves something else now.
        self.get.return_value = mock.Mock(status_code=200, content=b"its own file")
        self.assertFalse(checks()[label])

    def test_disconnect_removes_the_copies_caddyman_kept(self):
        _, host = self.add_host()
        self.add_route()
        kept = main.managed_dir(host["id"])
        self.assertTrue((kept / "sites" / "pdf.caddy").is_file())
        # The question before it says what goes, and how much.
        self.assertIn("DELETES its copies with it: the base Caddyfile and 1 route files", self.client.get(f"/hosts/{host['id']}/edit").text)
        self.assertEqual(self.client.post(f"/hosts/{host['id']}/delete").headers["location"], "/hosts/new")
        self.assertFalse(kept.exists())

    def test_file_import_in_the_base_is_flagged(self):
        self.add_host(base_caddyfile=self.BASE + "\nimport /etc/caddy/sites/*.caddy")
        checks = {check["label"]: check["ok"] for check in main.preflight(main.load_hosts()[0])}
        self.assertFalse(checks["Base Caddyfile imports no files"])
        self.assertTrue(checks["TLS snippet 'stepca' exists"])  # importing a snippet is fine

    def test_password_from_another_key_is_reported_not_sent(self):
        _, host = self.add_host()
        self.patch(main, "VAULT", main.Fernet(main.Fernet.generate_key()))
        self.assertIsNone(main.admin_auth(host))
        checks = {check["label"]: check["ok"] for check in main.preflight(host)}
        self.assertFalse(checks["Admin API password is readable"])

    def test_rejected_login_is_explained(self):
        self.add_host()
        self.post.return_value = mock.Mock(status_code=401)
        response = self.add_route()
        self.assertIn("refused the login", response.text)
        self.assertEqual(list(main.Path(main.load_hosts()[0]["sites_dir"]).iterdir()), [])

    def test_backup_leaves_the_login_out_and_restores_the_base(self):
        _, host = self.add_host()
        self.add_route()
        archive = self.client.get("/backup/download").content
        with zipfile.ZipFile(io.BytesIO(archive)) as packed:
            everything = b"".join(packed.read(name) for name in packed.namelist())
            self.assertEqual(packed.read("Caddyfile").decode(), self.BASE + "\n")
        self.assertNotIn(b"admin_password_enc", everything)
        self.assertNotIn(b"caddyman", everything.replace(b"# caddyman", b"").replace(b"Caddyman", b""))
        # Into an empty install: host, base copy and route come back; the login has to be re-entered.
        main.save_hosts([])
        shutil.rmtree(main.DATA_DIR / "hosts")
        self.client.post("/backup/import", data={"payload": base64.b64encode(archive).decode()})
        restored = main.load_hosts()[0]
        self.assertEqual((restored["id"], restored["storage"], restored.get("admin_user", "")), (host["id"], "managed", ""))
        self.assertEqual(main.Path(restored["caddyfile"]).read_text(), self.BASE + "\n")
        self.assertTrue((main.Path(restored["sites_dir"]) / "pdf.caddy").exists())


def make_certificate(issuer, hours=24):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    name = lambda value: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])  # noqa: E731
    builder = x509.CertificateBuilder().subject_name(name("pdf.lab.test")).issuer_name(name(issuer))
    builder = builder.public_key(key.public_key()).serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(now - timedelta(hours=48)).not_valid_after(now + timedelta(hours=hours))
    return builder.sign(key, hashes.SHA256())


class TestCertificates(RouteTest):
    def status(self, served, **fields):
        self.served.side_effect = None if isinstance(served, x509.Certificate) else served
        self.served.return_value = served
        route = {"type": "reverse_proxy", "host": "pdf.lab.test", "port": "", "tls": "acme_ca", **fields}
        return main.certificate_status(self.host, route)

    def test_issuer_and_expiry(self):
        status = self.status(make_certificate("Lab CA Intermediate", hours=30))
        self.assertEqual(status["level"], "ok")
        self.assertIn("Lab CA Intermediate", status["text"])
        self.assertRegex(status["text"], r"(29|30) h left")
        # The handshake goes to Caddy itself, with the route's hostname as SNI.
        self.assertEqual(self.served.call_args.args, ("caddy", 443, "pdf.lab.test"))
        self.assertIn("days left", self.status(make_certificate("Lab CA", hours=24 * 80))["text"])
        self.status(make_certificate("Lab CA"), port="8443")
        self.assertEqual(self.served.call_args.args[1], 8443)

    def test_internal_ca_on_an_acme_route_is_flagged(self):
        internal = make_certificate("Caddy Local Authority - ECC Intermediate")
        self.assertEqual(self.status(internal)["level"], "warn")
        self.assertIn("internal CA instead", self.status(internal)["detail"])
        # Where the internal CA was asked for, it is the expected issuer.
        self.assertEqual(self.status(internal, tls="internal")["level"], "ok")

    def test_expired_missing_and_unreachable(self):
        self.assertEqual(self.status(make_certificate("Lab CA", hours=-1))["text"], "Expired - Lab CA")
        self.assertEqual(self.status(main.ssl.SSLError("tlsv1 alert internal error"))["text"], "No certificate")
        self.assertEqual(self.status(OSError("refused"))["level"], "unknown")

    def test_nothing_to_check_without_tls_or_metadata(self):
        self.assertIsNone(self.status(OSError("x"), tls="none"))
        self.assertIsNone(main.certificate_status(self.host, None))
        self.served.assert_not_called()

    def test_list_shows_the_status(self):
        self.create()
        self.served.side_effect = None
        self.served.return_value = make_certificate("Caddy Local Authority - ECC Intermediate")
        page = self.client.get("/").text
        self.assertIn('class="cert warn"', page)
        # The explanation is the tooltip only, so the row stays one line.
        self.assertEqual(page.count("internal CA instead of your ACME CA"), 1)
        self.assertIn("Caddy Local Authority - ECC Intermediate - ", page)
        # A good one only says how long it lasts, the label next to it names the CA already.
        self.served.return_value = make_certificate("Lab CA Intermediate", hours=30)
        main.PROBE_CACHE.clear()
        page = self.client.get("/").text
        self.assertRegex(page, r'class="cert ok" title="Issued by Lab CA Intermediate\. Expires [^"]+">(29|30) h left<')

    def test_list_shows_the_status_of_a_hand_written_route(self):
        files = {
            "hand.caddy": "# a note\nhand.lab.test:8443 {\n\trespond 200\n}\n",
            "plain.caddy": "http://plain.lab.test {\n\trespond 200\n}\n",
            "two.caddy": "a.lab.test, b.lab.test {\n\trespond 200\n}\n",
            "far.caddy": "far.lab.test:99999 {\n\trespond 200\n}\n",
        }
        for name, text in files.items():
            self.put(name, text)
        self.served.side_effect = None
        self.served.return_value = make_certificate("Caddy Local Authority - ECC Intermediate")
        page = self.client.get("/").text
        # Only the one file whose first line is a single address with TLS is asked about.
        self.assertEqual([call.args[1:] for call in self.served.call_args_list], [(8443, "hand.lab.test")])
        # Who issued it is shown, without a verdict: nobody said which CA was meant.
        self.assertEqual(page.count("Caddy Local Authority"), 1)
        self.assertNotIn('class="cert warn"', page)


class TestLogs(RouteTest):
    LINES = [
        '{"level":"info","ts":1791500000.5,"logger":"admin.api","msg":"received request","uri":"/config/"}',
        '{"level":"info","ts":1791500001,"logger":"tls.obtain","msg":"acquiring lock","identifier":"pdf.lab.test"}',
        '{"level":"error","ts":1791500002,"logger":"tls.obtain","msg":"will retry","error":"pdf.lab.test: no challenge"}',
        '{"level":"warn","ts":1791500003,"logger":"http","msg":"HTTP/2 skipped"}',
        "not json at all <script>alert(1)</script>",
    ]

    def setUp(self):
        super().setUp()
        self.logs = os.path.join(self.dir.name, "logs")
        os.mkdir(self.logs)
        os.mkdir(os.path.join(self.logs, "sub.log"))  # a directory, not a log
        self.write("old.log", ['{"level":"info","ts":1,"logger":"old","msg":"from the rotated file"}'], mtime=1000)
        self.write("notes.txt", ["never listed"])
        self.write("caddy.log", self.LINES, mtime=2000)
        # Found where the log directory is mounted, without any setting.
        self.patch(main, "LOG_DIR", main.Path(self.logs))

    def write(self, name, lines, mtime=None):
        path = os.path.join(self.logs, name)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("\n".join(lines) + "\n")
        if mtime:
            os.utime(path, (mtime, mtime))

    def test_tokens_of_mailed_links_are_not_shown(self):
        line = (
            '{"level":"info","ts":1791500004,"logger":"http.log.access.log0","msg":"handled request","request":{"method":"GET",'
            '"uri":"/reset?token=WyJhZG1pbiJd.abc-DEF_1","host":"caddyman.lab.test","remote_ip":"10.0.0.9"},"status":200}'
        )
        self.write("access-caddyman.log", [line], mtime=3000)
        page = self.client.get("/logs", params={"file": "access-caddyman.log"}).text
        self.assertIn("GET /reset?token=[hidden] - 200", page)
        self.assertNotIn("WyJhZG1pbiJd", page)
        # The download hides them just the same.
        got = self.client.get("/logs/download", params={"file": "access-caddyman.log"})
        self.assertIn('filename="access-caddyman.log"', got.headers["content-disposition"])
        self.assertIn("/reset?token=[hidden]", got.text)
        self.assertNotIn("WyJhZG1pbiJd", got.text)

    def test_a_log_can_be_downloaded_whole(self):
        self.assertIn('href="/logs/download?file=caddy.log"', self.client.get("/logs").text)
        # In the columns of the page, oldest first, the time in the chosen zone.
        got = self.client.get("/logs/download", params={"file": "caddy.log"}).text.splitlines()
        self.assertEqual(len(got), len(self.LINES))
        self.assertTrue(got[2].endswith('\tERROR\ttls.obtain\twill retry\t{"error": "pdf.lab.test: no challenge"}'), got[2])
        self.assertTrue(got[2].startswith(main.parse_log_line(self.LINES[2])["time"]))
        self.assertEqual(got[4], "\t-\t\tnot json at all <script>alert(1)</script>")
        # A packed one comes unpacked, a name that is not listed not at all.
        with gzip.open(os.path.join(self.logs, "older.log.gz"), "wt", encoding="utf-8") as handle:
            handle.write("packed line\n")
        got = self.client.get("/logs/download", params={"file": "older.log.gz"})
        self.assertEqual((got.text, got.headers["content-disposition"]), ("\t-\t\tpacked line\n", 'attachment; filename="older.log"'))
        for name in ("notes.txt", "../caddy.log", "sub.log"):
            self.assertEqual(self.client.get("/logs/download", params={"file": name}).status_code, 303, name)

    def test_newest_file_newest_line_first(self):
        page = self.client.get("/logs").text
        self.assertNotIn("from the rotated file", page)
        self.assertNotIn("notes.txt", page)
        self.assertNotIn("sub.log", page)
        self.assertLess(page.index("HTTP/2 skipped"), page.index("acquiring lock"))
        self.assertIn("2026-10-08", page)  # the epoch time as a date
        self.assertIn("&lt;script&gt;", page)  # a line that is not JSON is shown, escaped
        self.assertNotIn("<script>alert", page)
        self.assertIn("from the rotated file", self.client.get("/logs?file=old.log").text)

    def test_filters(self):
        errors = self.client.get("/logs?level=error").text
        self.assertIn("will retry", errors)
        self.assertNotIn("acquiring lock", errors)
        self.assertNotIn("not json at all", errors)
        warnings = self.client.get("/logs?level=warn").text
        self.assertIn("will retry", warnings)
        self.assertIn("HTTP/2 skipped", warnings)
        named = self.client.get("/logs?q=PDF.lab.test").text
        self.assertIn("acquiring lock", named)
        self.assertNotIn("HTTP/2 skipped", named)
        self.assertNotIn("received request", self.client.get("/logs?quiet=1").text)
        self.assertIn("Nothing matches", self.client.get("/logs?q=nowhere").text)

    def test_only_files_from_the_listing_are_opened(self):
        for name in ("../Caddyfile", "notes.txt", "/etc/passwd", "sub.log"):
            page = self.client.get("/logs", params={"file": name}).text
            self.assertIn("HTTP/2 skipped", page)  # falls back to the newest log
            self.assertNotIn("never listed", page)
            self.assertNotIn("stepca", page)

    def test_only_the_end_of_a_large_file_is_read(self):
        self.patch(main, "LOG_TAIL_BYTES", 200)
        filler = ['{"level":"info","ts":2,"logger":"x","msg":"filler line number %04d"}' % i for i in range(50)]
        self.write("caddy.log", ["FIRST LINE OF THE FILE", *filler, '{"level":"info","ts":3,"logger":"x","msg":"the last one"}'])
        lines, older = main.read_log_tail(main.Path(self.logs) / "caddy.log")
        self.assertEqual(main.parse_log_line(lines[-1])["msg"], "the last one")
        # Times are shown in the zone from TZ; the change log keeps UTC and is converted for the page.
        with mock.patch.object(main, "TIME_ZONE", main.ZoneInfo("Europe/Berlin")):
            self.assertEqual(main.parse_log_line('{"ts":0}')["time"], "1970-01-01 01:00:00")
            self.assertEqual(main.local_time("2026-07-01 12:00:00", main.time_zone()), "2026-07-01 14:00:00")
        # A zone chosen under Settings comes before the variable; one that does not exist is refused.
        self.client.post("/settings/general", data={"zone": "Nowhere/City"})
        self.assertEqual(main.time_zone().key, "UTC")
        self.client.post("/settings/general", data={"zone": "Europe/Berlin"})
        self.assertEqual(main.parse_log_line('{"ts":0}')["time"], "1970-01-01 01:00:00")
        self.assertIn("Time (Europe/Berlin)", self.client.get("/changes").text)
        self.assertIn('name="zone" value="Europe/Berlin"', self.client.get("/settings/security").text)
        self.assertIn("Recent changes", self.client.get("/changes").text)
        self.assertNotIn("Recent changes", self.client.get("/status").text)
        self.assertLess(len(lines), 5)
        self.assertTrue(all(line.startswith("{") for line in lines))  # no half line at the start
        # Piece by piece backwards through the file: every line comes up exactly once, none cut in two.
        seen, steps = list(lines), 0
        while older:
            lines, older = main.read_log_tail(main.Path(self.logs) / "caddy.log", older)
            seen, steps = lines + seen, steps + 1
        self.assertEqual(seen, ["FIRST LINE OF THE FILE", *filler, '{"level":"info","ts":3,"logger":"x","msg":"the last one"}'])
        self.assertGreater(steps, 10)
        # The page offers the way back and the way on.
        page = self.client.get("/logs").text
        self.assertIn("Older entries", page)
        self.assertNotIn("Back to the newest", page)
        end = main.re.search(r"end=(\d+)", page).group(1)
        older_page = self.client.get(f"/logs?end={end}").text
        self.assertIn("Back to the newest", older_page)
        self.assertNotIn("the last one", older_page)

    def test_a_route_can_write_its_own_access_log(self):
        self.create(log="1")
        self.assertIn(
            "\tlog {\n\t\toutput file /var/log/caddy/access-pdf.log {\n\t\t\troll_size 10MiB\n\t\t\troll_keep 3\n\t\t}\n\t}\n}\n",
            self.read("pdf.caddy"),
        )
        self.assertIn('"tls":"acme_ca","log":true,"upstream"', self.read("pdf.caddy"))
        # It still opens in the form, with the box ticked, and the list leads to its log.
        self.assertIn('name="log" value="1" checked', self.client.get("/routes/pdf/edit").text)
        self.assertIn('href="/logs?file=access-pdf.log">Log</a>', self.client.get("/").text)
        # A request reads as one line, and "Hide admin API requests" does not hide it in a route's own log.
        line = ('{"level":"info","ts":5,"logger":"http.log.access.log0","msg":"handled request","status":200,"size":12,"duration":0.0042,'
                '"request":{"method":"GET","uri":"/print?x=1","host":"pdf.lab.test","remote_ip":"10.0.0.9"}}')
        self.write("access-pdf.log", [line], mtime=3000)
        for query in ("file=access-pdf.log", "file=access-pdf.log&quiet=1"):
            page = self.client.get(f"/logs?{query}").text
            self.assertIn("GET /print?x=1 - 200", page)
            self.assertIn("pdf.lab.test, from 10.0.0.9, 12 bytes, 0.004 s", page)
        # In Caddy's own log the same line is noise and goes with the box.
        self.write("caddy.log", [*self.LINES, line], mtime=4000)
        self.assertNotIn("GET /print", self.client.get("/logs?file=caddy.log&quiet=1").text)
        # A file written before the option existed stays as it is and stays in the form.
        self.create(host="wiki", upstream="10.0.0.7:3000")
        self.assertNotIn("log", self.read("wiki.caddy").split("\n", 1)[0])
        self.assertIsNotNone(main.read_route(main.Path(self.sites) / "wiki.caddy", self.host))

    def test_caddy_elsewhere_lists_its_rotated_logs(self):
        import gzip

        packed = gzip.compress(b"FIRST\n" + self.LINES[2].encode() + b"\n")
        listing = [
            {"name": "sub/", "is_dir": True, "mod_time": "2026-10-03T00:00:00Z"},
            {"name": "notes.txt", "is_dir": False, "mod_time": "2026-10-04T00:00:00Z"},
            {"name": "caddy-2026-10-01.log.gz", "is_dir": False, "mod_time": "2026-10-01T00:00:00Z"},
            {"name": "caddy.log", "is_dir": False, "mod_time": "2026-10-02T00:00:00Z"},
        ]

        def answer(url, **kwargs):
            if url.endswith("/caddyman-logs/"):
                return mock.Mock(status_code=200, json=lambda: listing)
            if url.endswith(".gz"):
                return mock.Mock(status_code=206, content=packed, headers={})
            return mock.Mock(status_code=206, content=self.LINES[1].encode(), headers={"content-range": "bytes 0-9/10"})

        self.remote()
        get = self.patch(main.httpx, "get", mock.Mock(side_effect=answer))
        names, chosen, lines, _ = main.load_log(main.load_hosts()[0], "")
        self.assertEqual((names, chosen, lines), (["caddy.log", "caddy-2026-10-01.log.gz"], "caddy.log", [self.LINES[1]]))
        page = self.client.get("/logs", params={"file": "caddy-2026-10-01.log.gz"}).text
        self.assertIn("will retry", page)
        self.assertEqual(get.call_args.args[0], "https://admin.lab.test/caddyman-logs/caddy-2026-10-01.log.gz")
        # A name that is not in the listing is never asked for.
        self.client.get("/logs", params={"file": "../Caddyfile"})
        self.assertEqual(get.call_args.args[0], "https://admin.lab.test/caddyman-logs/caddy.log")

    def test_a_packed_log_from_a_rotation_is_listed_and_read(self):
        import gzip

        packed = os.path.join(self.logs, "caddy-2026-10-01T00-00-00.000.log.gz")
        filler = ['{"level":"info","ts":2,"logger":"x","msg":"filler line number %04d"}' % i for i in range(50)]
        with gzip.open(packed, "wt", encoding="utf-8") as handle:
            handle.write("\n".join(["FIRST LINE OF THE FILE", *filler, '{"level":"warn","ts":3,"logger":"x","msg":"from the packed file"}']) + "\n")
        os.utime(packed, (500, 500))
        self.assertIn("caddy-2026-10-01T00-00-00.000.log.gz", self.client.get("/logs").text)  # offered, the newest still opens
        page = self.client.get("/logs", params={"file": "caddy-2026-10-01T00-00-00.000.log.gz"}).text
        self.assertIn("from the packed file", page)
        self.assertIn("FIRST LINE OF THE FILE", page)
        # Only its end, like any other log, and never a half line.
        self.patch(main, "LOG_TAIL_BYTES", 200)
        lines, _ = main.read_log_tail(main.Path(packed))
        self.assertEqual(main.parse_log_line(lines[-1])["msg"], "from the packed file")
        self.assertLess(len(lines), 5)
        self.assertTrue(all(line.startswith("{") for line in lines))
        # Something that only carries the name is shown as empty, not as an error.
        with open(os.path.join(self.logs, "broken.log.gz"), "wb") as handle:
            handle.write(b"not gzip at all")
        self.assertEqual(self.client.get("/logs", params={"file": "broken.log.gz"}).status_code, 200)

    def test_without_log_files_the_page_explains_the_setup(self):
        self.patch(main, "LOG_DIR", main.Path(self.dir.name) / "missing")
        page = self.client.get("/logs").text
        self.assertIn("log caddyman", page)
        self.assertIn("/missing:ro", page)
        self.assertIn("/static/logs.js", page)  # keeps looking, and shows the log once it is there

    def test_live_view_has_what_the_script_swaps(self):
        page = self.client.get("/logs").text
        self.assertIn('<tbody id="log-entries">', page)
        self.assertIn('id="live" checked', page)
        self.assertEqual(self.client.get("/static/logs.js").status_code, 200)

    def remote(self, **answer):
        main.save_hosts([{**self.host, "storage": "managed", "admin_url": "https://admin.lab.test",
                          "admin_user": "caddyman", "admin_password_enc": main.VAULT.encrypt(b"pw").decode()}])
        (main.managed_dir("h1") / "sites").mkdir(parents=True, exist_ok=True)
        reply = mock.Mock(status_code=206, headers={"content-range": "bytes 0-99/100"}, content=b"")
        reply.configure_mock(**answer)
        return self.patch(main.httpx, "get", mock.Mock(return_value=reply))

    def test_caddy_elsewhere_is_asked_for_the_end_of_its_log(self):
        body = "\n".join(self.LINES).encode()
        get = self.remote(content=body)
        page = self.client.get("/logs?level=error").text
        self.assertIn("will retry", page)
        self.assertNotIn("from the rotated file", page)  # the local directory is not this Caddy's
        call = get.call_args
        self.assertEqual(call.args[0], "https://admin.lab.test/caddyman-logs/caddy.log")
        self.assertEqual(call.kwargs["headers"], {"Range": f"bytes=-{main.LOG_TAIL_BYTES}"})
        self.assertEqual(call.kwargs["auth"], ("caddyman", "pw"))

    def test_partial_answer_loses_its_first_half_line(self):
        self.remote(content=b'half a line"}\n' + self.LINES[1].encode(), headers={"content-range": "bytes 500-999/1000"})
        names, chosen, lines, older = main.load_log(main.load_hosts()[0], "")
        self.assertEqual((names, chosen, lines), (["caddy.log"], "caddy.log", [self.LINES[1]]))
        self.assertEqual(older, 500 + len(b'half a line"}\n'))  # the piece before ends behind that line, so it gets it whole

    def test_caddy_elsewhere_without_the_log_site_shows_how_to_add_it(self):
        self.remote(status_code=404)
        page = self.client.get("/logs").text
        self.assertIn("handle_path /caddyman-logs/*", page)
        self.patch(main.httpx, "get", mock.Mock(side_effect=main.httpx.ConnectError("down")))
        self.assertIn("handle_path /caddyman-logs/*", self.client.get("/logs").text)

    def test_failed_certificate_links_to_its_log(self):
        self.create()
        self.served.side_effect = main.ssl.SSLError("alert")
        self.assertIn("/logs?q=pdf.lab.test", self.client.get("/").text)


class TestBackup(RouteTest):
    def setUp(self):
        super().setUp()
        self.create()
        self.create(host="wiki", upstream="10.0.0.7:3000")
        self.archive = self.client.get("/backup/download").content
        self.pdf, self.wiki = self.read("pdf.caddy"), self.read("wiki.caddy")

    def make_zip(self, members):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, content in members.items():
                archive.writestr(name, content)
        return buffer.getvalue()

    def upload(self, data):
        return self.client.post("/backup/import", files={"archive": ("backup.zip", data, "application/zip")})

    def confirm(self, data, query=""):
        return self.client.post(f"/backup/import{query}", data={"payload": base64.b64encode(data).decode()})

    def test_export_holds_routes_and_settings_but_no_secrets(self):
        with zipfile.ZipFile(io.BytesIO(self.archive)) as archive:
            self.assertEqual(
                sorted(archive.namelist()),
                ["Caddyfile", "README.txt", "backup.json", "errors.json", "groups.json", "hosts.json", "mail.json",
                 "settings.json", "sites/pdf.caddy", "sites/wiki.caddy"],
            )
            self.assertIn("NOT IN HERE: the accounts", archive.read("README.txt").decode())
            self.assertEqual(archive.read("sites/pdf.caddy").decode(), self.pdf)
            self.assertIn("NOT IN HERE: the root CA", archive.read("README.txt").decode())
            everything = b"".join(archive.read(name) for name in archive.namelist())
        self.assertNotIn(b"password_hash", everything)
        self.assertNotIn(main.SECRET_KEY.encode(), everything)

    def test_preview_changes_nothing_and_confirm_restores(self):
        os.remove(os.path.join(self.sites, "wiki.caddy"))
        self.put("pdf.caddy", "# edited\n", "a")
        self.put("extra.caddy", "extra.lab.test {\n}\n")
        self.load.reset_mock()
        preview = self.upload(self.archive)
        self.assertIn("Overwritten", preview.text)
        self.assertIn("Created", preview.text)
        self.assertFalse(os.path.exists(os.path.join(self.sites, "wiki.caddy")))
        self.load.assert_not_called()
        self.assertEqual(self.confirm(self.archive).headers["location"], "/")
        self.assertEqual((self.read("pdf.caddy"), self.read("wiki.caddy")), (self.pdf, self.wiki))
        self.assertTrue(os.path.exists(os.path.join(self.sites, "extra.caddy")))  # not in the archive, kept
        self.assertEqual(self.load.call_count, 1)  # one reload for the whole restore
        self.assertEqual(main.read_audit()[0]["action"], "import")

    def test_rejected_restore_undoes_every_file(self):
        os.remove(os.path.join(self.sites, "wiki.caddy"))
        self.put("pdf.caddy", "changed\n")
        self.reject()
        self.confirm(self.archive)
        self.assertEqual(os.listdir(self.sites), ["pdf.caddy"])
        self.assertEqual(self.read("pdf.caddy"), "changed\n")

    def test_an_archive_that_does_not_unpack_is_refused(self):
        data = self.make_zip({"sites/pdf.caddy": "x"})
        with mock.patch.object(zipfile.ZipFile, "read", side_effect=main.zlib.error("invalid stored block lengths")):
            self.assertEqual(self.upload(data).status_code, 400)

    def test_archive_cannot_write_outside_the_sites_directory(self):
        evil = self.make_zip(
            {
                "sites/../../escaped.caddy": "x",
                "../escaped.caddy": "x",
                "/etc/escaped.caddy": "x",
                "sites/sub/nested.caddy": "x",
                "sites/ok.caddy": "ok.lab.test {\n}\n",
                "Caddyfile": "must never be written",
            }
        )
        preview = self.upload(evil).text
        self.assertIn("escaped.caddy", preview)  # listed as ignored
        self.confirm(evil)
        self.assertEqual(sorted(os.listdir(self.sites)), ["ok.caddy", "pdf.caddy", "wiki.caddy"])
        self.assertEqual(sorted(os.listdir(self.dir.name)), ["Caddyfile", "sites"])
        with open(self.caddyfile, encoding="utf-8") as handle:
            self.assertNotIn("must never", handle.read())

    def test_unreadable_uploads_are_refused(self):
        for data in (b"not a zip", b"", b"x" * (main.BACKUP_MAX_BYTES + 1)):
            self.assertEqual(self.upload(data).status_code, 400)
        bomb = self.make_zip({"sites/a.caddy": "x"})
        with mock.patch.object(main, "BACKUP_MAX_UNPACKED", 0):
            self.assertEqual(self.upload(bomb).status_code, 400)
        self.assertEqual(self.client.post("/backup/import", data={"payload": "@@not base64@@"}).status_code, 400)

    def test_restore_into_an_empty_install_brings_the_host_back(self):
        main.save_hosts([])
        for name in os.listdir(self.sites):
            os.remove(os.path.join(self.sites, name))
        self.assertIn("host settings from the archive are imported", self.upload(self.archive).text)
        self.assertEqual(main.load_hosts(), [])  # the preview restores nothing
        self.confirm(self.archive)
        self.assertEqual([(h["domain_suffix"], h["sites_dir"]) for h in main.load_hosts()], [("lab.test", self.sites)])
        self.assertEqual(sorted(os.listdir(self.sites)), ["pdf.caddy", "wiki.caddy"])

    MAIL = {"public_url": "https://caddyman.lab.test", "host": "smtp.lab.test", "port": "587", "security": "starttls",
            "user": "caddyman", "password": "mail-secret", "sender": "caddyman@lab.test"}

    def test_groups_switches_and_mail_travel_without_secrets(self):
        self.client.post("/groups", data={"name": "Media"})
        self.client.post("/settings/security", data={"public_ca": "1"})  # the hint on the login page goes off
        self.client.post("/settings/mail", data=self.MAIL)
        self.client.post("/error-pages/502", data={"design": "ghost"})
        self.reach("192.168.1.9:5052")
        self.client.post("/settings/general", data={"zone": "Europe/Berlin"})
        # "Only over HTTPS" is never part of a backup: restored without its route, it would lock everybody out.
        main.save_settings(https_only="1")
        archive = main.build_backup(main.pick_host())
        main.save_settings(https_only="")
        with zipfile.ZipFile(io.BytesIO(archive)) as packed:
            everything = b"".join(packed.read(name) for name in packed.namelist())
        self.assertIn(b"smtp.lab.test", everything)
        for secret in (b"mail-secret", b"password_enc", b"password_hash", b"admin_password"):
            self.assertNotIn(secret, everything)
        # Into an install that has its Caddy: the groups come back, the switches and the mail settings stay as they are.
        main.GROUPS_FILE.unlink()
        main.MAIL_FILE.unlink()
        main.SETTINGS_FILE.unlink()
        main.ERRORS_FILE.unlink()
        self.assertIn("1 route groups", self.upload(archive).text)
        self.confirm(archive)
        self.assertEqual(main.stored_groups(), ["Media"])
        self.assertEqual((main.load_mail()["host"], main.flag("login_ca_hint"), main.load_errors()["designs"]), ("", True, {}))
        # Into an empty install everything comes back, the mail password excepted.
        main.save_hosts([])
        for name in os.listdir(self.sites):
            os.remove(os.path.join(self.sites, name))
        # Unless Caddy rejects the routes: then nothing of the archive stays, the connection to Caddy included.
        self.reject()
        self.assertEqual(self.confirm(archive).headers["location"], "/backup")
        self.assertEqual((main.load_hosts(), main.load_mail()["host"], os.listdir(self.sites)), ([], "", []))
        self.load.return_value = mock.Mock(status_code=200)
        preview = self.upload(archive).text
        self.assertIn("the switches under Settings, General", preview)
        self.assertIn("the mail settings, without the password", preview)
        self.assertEqual(main.load_mail()["host"], "")  # the preview restores nothing
        self.confirm(archive)
        self.assertEqual((main.load_mail()["host"], main.load_mail()["user"]), ("smtp.lab.test", "caddyman"))
        self.assertNotIn("password_enc", main.load_mail())
        self.assertEqual((main.flag("public_ca"), main.flag("login_ca_hint")), (True, False))
        self.assertEqual(main.load_errors()["designs"], {"502": "ghost"})
        self.assertEqual((main.time_zone().key, main.https_only()), ("Europe/Berlin", False))
        self.assertEqual(main.load_errors()["upstream"], "192.168.1.9:5052")

    def test_only_who_may_change_settings_restores_them(self):
        # The connection to Caddy and the mail settings decide who gets in and where reset links go:
        # the right to restore routes must not be enough to set them.
        evil = {**self.MAIL, "public_url": "https://evil.example", "host": "evil.example"}
        evil.pop("password")
        archive = self.make_zip({"hosts.json": main.json.dumps([self.host]), "mail.json": main.json.dumps(evil),
                                 "settings.json": '{"public_ca": ""}', "groups.json": '["ok", "bad\\nname", 7]'})
        self.client.post("/settings/security", data={"public_ca": "1", "login_ca_hint": "1"})
        self.client.post("/settings/users/new", data={"username": "keeper", "password": PASSWORD, "repeat": PASSWORD, "right_backup": "1"})
        keeper = self.guest()
        keeper.post("/login", data={"username": "keeper", "password": PASSWORD})
        main.save_hosts([])
        payload = {"payload": base64.b64encode(archive).decode()}
        self.assertEqual(keeper.post("/backup/import", files={"archive": ("b.zip", archive, "application/zip")}).status_code, 403)
        self.assertEqual(keeper.post("/backup/import", data=payload).status_code, 403)
        self.assertEqual((main.load_hosts(), main.load_mail()["host"], main.flag("public_ca"), main.stored_groups()), ([], "", True, []))
        # Somebody who may change the settings restores all of it.
        self.client.post("/backup/import", data=payload)
        self.assertEqual((len(main.load_hosts()), main.load_mail()["host"], main.flag("public_ca")), (1, "evil.example", False))
        self.assertEqual(main.stored_groups(), ["ok"])  # names only, and only usable ones

    def test_hosts_in_the_archive_never_replace_existing_ones(self):
        tampered = self.make_zip({"hosts.json": '[{"id":"h1","name":"evil","admin_url":"http://evil:2019"}]'})
        self.confirm(tampered)
        self.assertEqual(main.load_hosts()[0]["admin_url"], self.host["admin_url"])


class TestEdit(RouteTest):
    def setUp(self):
        super().setUp()
        self.create()
        self.original = self.read("pdf.caddy")

    def mtime(self, name="pdf.caddy"):
        return str(os.stat(os.path.join(self.sites, name)).st_mtime_ns)

    def edit(self, name="pdf", mtime=None, **overrides):
        data = {"mode": "form", "mtime": mtime or self.mtime(f"{name}.caddy"), **self.form(**overrides)}
        return self.client.post(f"/routes/{name}/edit", data=data)

    def test_a_save_that_breaks_off_leaves_the_file_whole(self):
        real, calls = main.os.replace, []

        def fail_once(*paths):
            calls.append(paths)
            if len(calls) == 1:
                raise OSError("No space left on device")
            return real(*paths)

        with mock.patch.object(main.os, "replace", fail_once):
            self.assertEqual(self.edit(upstream="10.0.0.9:1").status_code, 400)
        # Never cut short on the way, and nothing left lying next to it.
        self.assertEqual(self.read("pdf.caddy"), self.original)
        self.assertEqual(os.listdir(self.sites), ["pdf.caddy"])

    def test_own_route_opens_in_the_form_and_saves(self):
        page = self.client.get("/routes/pdf/edit").text
        self.assertIn('name="mode" value="form"', page)
        self.assertIn("10.0.0.5:9005", page)
        self.assertEqual(self.edit(upstream="10.0.0.6:80").headers["location"], "/")
        self.assertIn("reverse_proxy 10.0.0.6:80\n", self.read("pdf.caddy"))
        self.assertEqual(main.read_audit()[0]["action"], "update")

    def test_changing_the_hostname_renames_the_file(self):
        self.edit(host="scan")
        self.assertEqual(os.listdir(self.sites), ["scan.caddy"])
        self.assertIn("scan.lab.test {", self.read("scan.caddy"))
        self.assertEqual(main.read_audit()[0]["route"], "pdf -> scan")

    def test_rename_never_overwrites_another_route(self):
        self.create(host="scan")
        self.assertEqual(self.edit(host="scan").status_code, 400)
        self.assertEqual(self.read("pdf.caddy"), self.original)

    def test_rejected_rename_restores_both_files(self):
        self.reject()
        self.assertEqual(self.edit(host="scan").status_code, 400)
        self.assertEqual(os.listdir(self.sites), ["pdf.caddy"])
        self.assertEqual(self.read("pdf.caddy"), self.original)

    def test_change_on_disk_is_shown_instead_of_overwritten(self):
        stale = self.mtime()
        self.put("pdf.caddy", "pdf.lab.test {\n\trespond 418\n}\n")
        os.utime(os.path.join(self.sites, "pdf.caddy"), ns=(1, 1))
        response = self.edit(mtime=stale, upstream="10.0.0.6:80")
        self.assertEqual(response.status_code, 409)
        self.assertIn("respond 418", response.text)  # what is on disk
        self.assertIn("10.0.0.6:80", response.text)  # what was about to be saved
        self.assertIn("respond 418", self.read("pdf.caddy"))
        # The page now carries the new time, so saving again is a deliberate overwrite.
        self.assertIn('name="mtime" value="1"', response.text)
        self.assertEqual(self.edit(mtime="1", upstream="10.0.0.6:80").headers["location"], "/")
        self.assertIn("10.0.0.6:80", self.read("pdf.caddy"))

    def test_foreign_file_opens_as_text_and_saves(self):
        self.put("legacy.caddy", "legacy.lab.test {\n\trespond 200\n}\n")
        page = self.client.get("/routes/legacy/edit").text
        self.assertIn("<textarea", page)
        self.assertNotIn("Adopt this route", page)
        data = {"mode": "raw", "mtime": self.mtime("legacy.caddy"), "content": "legacy.lab.test {\r\n\trespond 204\r\n}"}
        self.assertEqual(self.client.post("/routes/legacy/edit", data=data).headers["location"], "/")
        self.assertEqual(self.read("legacy.caddy"), "legacy.lab.test {\n\trespond 204\n}\n")

    def test_rejected_text_is_put_back(self):
        before = "legacy.lab.test {\n\trespond 200\n}\n"
        self.put("legacy.caddy", before)
        self.reject()
        data = {"mode": "raw", "mtime": self.mtime("legacy.caddy"), "content": "legacy.lab.test {\n\tnonsense\n}\n"}
        response = self.client.post("/routes/legacy/edit", data=data)
        self.assertEqual(response.status_code, 400)
        self.assertIn("nonsense", response.text)  # the attempt stays in the editor
        self.assertEqual(self.read("legacy.caddy"), before)

    def test_own_route_can_be_opened_as_text(self):
        self.assertIn("<textarea", self.client.get("/routes/pdf/edit?raw=1").text)

    def test_basic_auth_stores_only_the_hash(self):
        self.edit(auth_user="max", auth_password="open sesame")
        text = self.read("pdf.caddy")
        self.assertNotIn("open sesame", text)
        route = main.read_route(main.Path(self.sites) / "pdf.caddy", self.host)
        self.assertTrue(main.check_password("open sesame", route["auth_hash"]))
        self.assertIn(
            f"\timport stepca\n\tbasic_auth {{\n\t\tmax {route['auth_hash']}\n\t}}\n\treverse_proxy 10.0.0.5:9005\n}}\n", text
        )
        self.assertNotIn("open sesame", self.client.get("/routes/pdf/edit").text)
        # An empty password keeps the hash, a new username needs a new password.
        self.edit(auth_user="max", upstream="10.0.0.6:80")
        self.assertIn(route["auth_hash"], self.read("pdf.caddy"))
        self.assertEqual(self.edit(auth_user="eve").status_code, 400)
        self.assertIn(f"max {route['auth_hash']}", self.read("pdf.caddy"))
        # Another type could not ask for the login: it is not dropped along the way.
        self.assertEqual(self.edit(type="static", root="/srv/www").status_code, 400)
        self.assertIn(f"max {route['auth_hash']}", self.read("pdf.caddy"))
        # An empty username takes the login away again.
        self.edit()
        self.assertEqual(self.read("pdf.caddy"), self.original)

    def test_basic_auth_input_is_validated(self):
        self.assertEqual(self.edit(auth_user="max").status_code, 400)  # no password yet
        self.assertEqual(self.edit(auth_user="a b", auth_password="secret").status_code, 400)
        self.assertEqual(self.edit(auth_user="x {\n\trespond", auth_password="secret").status_code, 400)
        self.assertEqual(self.edit(auth_user="max", auth_password="x" * 73).status_code, 400)
        self.assertEqual(self.edit(auth_user="max", auth_password="short").status_code, 400)
        self.assertEqual(self.read("pdf.caddy"), self.original)

    def test_host_header_option(self):
        self.edit(host_header="1")
        self.assertIn(
            "\treverse_proxy 10.0.0.5:9005 {\n\t\theader_up Host {upstream_hostport}\n\t}\n}\n", self.read("pdf.caddy")
        )
        self.assertIn('name="host_header" value="1" checked', self.client.get("/routes/pdf/edit").text)

    def test_route_is_switched_off_and_on_again(self):
        self.assertEqual(self.client.post("/routes/pdf/toggle").headers["location"], "/")
        text = self.read("pdf.caddy")
        # Nothing but comments is left for Caddy, and the file still opens in the form.
        self.assertTrue(all(line.startswith("#") for line in text.splitlines()), text)
        self.assertIn("# \treverse_proxy 10.0.0.5:9005\n", text)
        self.assertIn('name="off" value="1"', self.client.get("/routes/pdf/edit").text)
        self.assertIn(">Enable<", self.client.get("/").text)
        # Saving the form keeps it off.
        self.edit(upstream="10.0.0.6:80", off="1")
        self.assertIn("# \treverse_proxy 10.0.0.6:80\n", self.read("pdf.caddy"))
        self.edit(off="1")
        self.client.post("/routes/pdf/toggle")
        self.assertEqual(self.read("pdf.caddy"), self.original)
        # A file written by hand is left alone.
        self.put("hand.caddy", "hand.lab.test {\n\trespond 200\n}\n")
        self.client.post("/routes/hand/toggle")
        self.assertEqual(self.read("hand.caddy"), "hand.lab.test {\n\trespond 200\n}\n")

    def test_allowed_networks_wrap_the_route(self):
        self.edit(allow="192.168.2.5/24, private  10.0.0.9", auth_user="max", auth_password="open sesame")
        text = self.read("pdf.caddy")
        route = main.read_route(main.Path(self.sites) / "pdf.caddy", self.host)
        self.assertEqual(route["allow"], "192.168.2.0/24 private 10.0.0.9")
        # The refusal comes first, before the login: outside of a route block Caddy would sort it behind.
        self.assertIn(
            "\timport stepca\n\t@outside not client_ip 192.168.2.0/24 private_ranges 10.0.0.9\n\troute {\n"
            "\t\trespond @outside 403\n\t\tbasic_auth {\n\t\t\tmax " + route["auth_hash"] + "\n\t\t}\n"
            "\t\treverse_proxy 10.0.0.5:9005\n\t}\n}\n",
            text,
        )
        form = self.client.get("/routes/pdf/edit").text
        for network in ("192.168.2.0/24", "private", "10.0.0.9"):
            self.assertIn(f'<input name="allow" value="{network}"', form)
        taken, reason = main.adopt_route(text, self.host)
        self.assertEqual(taken and taken["allow"], route["allow"], reason)
        # Nothing but addresses reaches the file.
        for bad in ("lan", "10.0.0.0/33", "10.0.0.1 {\n\trespond", "1.1.1.1 " * 21):
            self.assertEqual(self.edit(allow=bad).status_code, 400, bad)
        self.assertEqual(self.read("pdf.caddy"), text)
        self.edit()
        self.assertEqual(self.read("pdf.caddy"), self.original)

    def test_more_hostnames_share_one_route(self):
        self.edit(aliases=["Docs", "wiki.lab.test,pdf", "", "docs"])
        text = self.read("pdf.caddy")
        route = main.read_route(main.Path(self.sites) / "pdf.caddy", self.host)
        # Short names get the suffix, the main name and doubles drop out, the file keeps its name.
        self.assertEqual(route["aliases"], ["docs.lab.test", "wiki.lab.test"])
        self.assertIn("\npdf.lab.test, docs.lab.test, wiki.lab.test {\n", text)
        page = self.client.get("/routes/pdf/edit").text
        self.assertIn('<input name="aliases" value="docs.lab.test"', page)
        self.assertIn('<input name="aliases" value="wiki.lab.test"', page)
        self.assertIn("<small>wiki.lab.test</small>", self.client.get("/").text)
        taken, reason = main.adopt_route(text, self.host)
        self.assertEqual(taken and taken["aliases"], route["aliases"], reason)
        # Port and plain HTTP go for every name.
        self.edit(aliases="docs", tls="none", port="8080")
        self.assertIn("\nhttp://pdf.lab.test:8080, http://docs.lab.test:8080 {\n", self.read("pdf_8080.caddy"))
        for bad in ("docs {", "a_b", " ".join(f"n{number}" for number in range(21))):
            self.assertEqual(self.edit(name="pdf_8080", aliases=bad).status_code, 400, bad)

    def test_paths_go_to_targets_of_their_own(self):
        self.edit(path=["/api/*", "", "/api/v2/*"], path_upstream=["10.0.0.8:3000", "", "https://10.0.0.9"], skip_verify="1")
        text = self.read("pdf.caddy")
        route = main.read_route(main.Path(self.sites) / "pdf.caddy", self.host)
        # Longest path first, the certificate check is skipped only where TLS is spoken.
        self.assertEqual(route["paths"], [["/api/v2/*", "https://10.0.0.9"], ["/api/*", "10.0.0.8:3000"]])
        self.assertIn(
            "\treverse_proxy /api/v2/* https://10.0.0.9 {\n\t\ttransport http {\n\t\t\ttls_insecure_skip_verify\n\t\t}\n\t}\n"
            "\treverse_proxy /api/* 10.0.0.8:3000\n\treverse_proxy 10.0.0.5:9005\n}\n",
            text,
        )
        page = self.client.get("/routes/pdf/edit").text
        self.assertIn('<input name="path" value="/api/v2/*"', page)
        self.assertIn('<input name="path_upstream" value="10.0.0.8:3000"', page)
        taken, reason = main.adopt_route(text, self.host)
        self.assertEqual(taken and taken["paths"], route["paths"], reason)
        for path, target in (("/", "10.0.0.8"), ("api", "10.0.0.8"), ("/a {", "10.0.0.8"), ("/api/*", ""), ("/api/*", "10.0.0.8 {")):
            self.assertEqual(self.edit(path=[path], path_upstream=[target]).status_code, 400, (path, target))
        self.assertEqual(self.edit(path=["/a", "/a"], path_upstream=["10.0.0.8", "10.0.0.9"]).status_code, 400)
        self.assertEqual(self.read("pdf.caddy"), text)

    def test_single_sign_on_imports_the_snippet(self):
        # Without a snippet there is nothing to import, and the tick cannot be set.
        self.assertEqual(self.edit(sso="1").status_code, 400)
        self.assertIn('name="sso" value="1"  disabled', self.client.get("/routes/pdf/edit").text)
        with open(self.caddyfile, "a", encoding="utf-8") as handle:
            handle.write("\n(sso) {\n\tforward_auth authelia:9091 {\n\t\turi /api/authz/forward-auth\n\t}\n}\n")
        self.host["sso_snippet"] = "sso"
        main.save_hosts([self.host])
        self.edit(sso="1", allow="private")
        text = self.read("pdf.caddy")
        # The login service is asked after the refusal by address and before the target.
        self.assertIn("\troute {\n\t\trespond @outside 403\n\t\timport sso\n\t\treverse_proxy 10.0.0.5:9005\n\t}\n}\n", text)
        self.assertIn('name="sso" value="1" checked', self.client.get("/routes/pdf/edit").text)
        self.assertIn(">SSO<", self.client.get("/").text)
        taken, reason = main.adopt_route(text, self.host)
        self.assertEqual(taken and taken.get("sso"), True, reason)
        # With the snippet gone the tick still travels with the form, so a save is refused
        # instead of dropping the login without a word.
        with open(self.caddyfile, encoding="utf-8") as handle:
            base = handle.read()
        with open(self.caddyfile, "w", encoding="utf-8") as handle:
            handle.write(base.replace("(sso) {", "(other) {"))
        self.assertIn('name="sso" value="1" checked >', self.client.get("/routes/pdf/edit").text)
        self.assertEqual(self.edit(sso="1", allow="private", upstream="10.0.0.6:80").status_code, 400)
        self.assertEqual(self.read("pdf.caddy"), text)
        with open(self.caddyfile, "w", encoding="utf-8") as handle:
            handle.write(base)
        # A redirect has nothing to protect.
        self.edit(type="redirect", target="https://b.lab.test", code="302", sso="1")
        self.assertNotIn("sso", self.read("pdf.caddy"))

    def test_hsts_header(self):
        self.edit(hsts="1", allow="private")
        text = self.read("pdf.caddy")
        # Outside of the route block, so the refusal by address carries it as well.
        self.assertIn('\timport stepca\n\theader Strict-Transport-Security "max-age=31536000"\n\t@outside not', text)
        self.assertIn('name="hsts" value="1" checked', self.client.get("/routes/pdf/edit").text)
        taken, reason = main.adopt_route(text, self.host)
        self.assertEqual(taken and taken.get("hsts"), True, reason)
        # Without TLS there is nothing to insist on.
        self.edit(hsts="1", tls="none")
        self.assertNotIn("Strict-Transport-Security", self.read("pdf.caddy"))

    def test_error_pages_on_a_route(self):
        self.edit(errors="1", allow="private")
        text = self.read("pdf.caddy")
        # An error instead of a plain answer, or the refusal by address would never reach the page.
        self.assertIn(
            "\t\terror @outside 403\n\t\treverse_proxy 10.0.0.5:9005\n\t}\n"
            "\thandle_errors 400 403 404 405 500 502 503 504 {\n\t\trewrite * /error/{err.status_code}\n"
            f"\t\treverse_proxy caddyman:{main.OWN_PORT}\n\t}}\n}}\n",
            text,
        )
        self.assertIn('name="errors" value="1" checked', self.client.get("/routes/pdf/edit").text)
        self.assertIn(">Errors<", self.client.get("/").text)
        taken, reason = main.adopt_route(text, self.host)
        self.assertEqual(taken and taken.get("errors"), f"caddyman:{main.OWN_PORT}", reason)
        # Fetching a page is not a route that leads to Caddyman.
        self.assertFalse(main.own_route_address(self.host)[0])
        # A new address goes into the routes that use it, and they stay files of Caddyman.
        self.reach("bad {")
        self.assertEqual(self.read("pdf.caddy"), text)
        self.reach("192.168.1.9:5052")
        self.assertIn("\t\treverse_proxy 192.168.1.9:5052\n\t}\n}\n", self.read("pdf.caddy"))
        self.assertEqual(main.read_route(main.Path(self.sites) / "pdf.caddy", self.host)["errors"], "192.168.1.9:5052")
        # A redirect has no error to show.
        self.edit(type="redirect", target="https://b.lab.test", code="302", errors="1")
        self.assertNotIn("handle_errors", self.read("pdf.caddy"))

    def test_error_page_is_open_and_carries_its_code(self):
        for design in main.ERROR_DESIGNS:
            self.assertEqual(self.client.get(f"/error/504?design={design}").status_code, 504, design)
        self.assertIn("/error/502?design=ghost", self.client.get("/error-pages/502").text)
        self.client.post("/error-pages/502", data={"design": "ghost"})
        self.assertEqual(main.load_errors()["designs"], {"502": "ghost"})
        self.client.post("/logout")
        # Any method, as Caddy passes the request on. The design in the address is the preview of an account.
        answer = self.client.post("/error/502?design=terminal", headers={"host": "pdf.lab.test"})
        self.assertEqual(answer.status_code, 502)
        self.assertIn("<svg", answer.text)
        self.assertIn("pdf.lab.test", answer.text)
        blocked = self.client.get("/error/blocked", headers={"host": "<b>x"})
        self.assertEqual(blocked.status_code, 403)
        self.assertNotIn("<b>x", blocked.text)
        self.assertEqual(self.client.get("/error/nonsense").status_code, 404)
        self.assertEqual(self.client.get("/error/599").status_code, 404)
        self.assertEqual(self.client.get("/error-pages").status_code, 303)

    def test_error_page_takes_its_own_wording(self):
        self.client.post("/error-pages/502", data={"design": "minimal", "title": "Kaputt", "text": "<b>Gleich wieder da</b>"})
        self.assertEqual(main.load_errors()["texts"], {"502": {"title": "Kaputt", "text": "<b>Gleich wieder da</b>"}})
        self.assertIn('value="Kaputt"', self.client.get("/error-pages/502").text)
        page = self.client.get("/error/502").text
        self.assertIn("Kaputt", page)
        self.assertIn("&lt;b&gt;Gleich wieder da", page)
        self.assertIn(main.ERROR_PAGES["504"][0], self.client.get("/error/504").text)  # the others keep theirs
        # It travels with a backup, and empty fields bring the shipped wording back.
        with zipfile.ZipFile(io.BytesIO(main.build_backup(main.pick_host()))) as packed:
            self.assertIn(b"Kaputt", packed.read("errors.json"))
        self.client.post("/error-pages/502", data={"design": "minimal", "title": "", "text": " "})
        self.assertEqual(main.load_errors()["texts"], {})
        self.assertIn(main.ERROR_PAGES["502"][1], self.client.get("/error/502").text)

    def test_catch_all_route_for_a_dns_blocker(self):
        self.client.post("/error-pages/catch-all", data={"on": "1"})
        written = f"http:// {{\n\trewrite * /error/blocked\n\treverse_proxy caddyman:{main.OWN_PORT}\n}}\n"
        self.assertEqual(self.read("catch-all.caddy").split("\n", 1)[1], written)
        # Switched on and off under Error pages only: the route list leaves it out.
        self.assertNotIn("/routes/catch-all/", self.client.get("/").text)
        self.assertIn("Switch off and reload Caddy", self.client.get("/error-pages").text)
        # One an older version switched off in the list comes back with the same button.
        self.client.post("/routes/catch-all/toggle")
        self.assertIn("Answer unknown names", self.client.get("/error-pages").text)
        self.client.post("/error-pages/catch-all", data={"on": "1"})
        self.assertEqual(self.read("catch-all.caddy").split("\n", 1)[1], written)
        # It has no form of its own.
        self.assertEqual(self.client.get("/routes/catch-all/edit").headers["location"], "/error-pages")
        # Only that one file is left out: the same type under another name is somebody's own file.
        self.put("evil.caddy", self.read("catch-all.caddy"))
        self.assertIsNone(main.read_route(main.Path(self.sites) / "evil.caddy", self.host))
        self.assertIn("evil.caddy", self.client.get("/").text)
        os.remove(os.path.join(self.sites, "evil.caddy"))
        self.client.post("/error-pages/catch-all")
        self.assertFalse(os.path.exists(os.path.join(self.sites, "catch-all.caddy")))
        # A file somebody else put there is left alone.
        self.put("catch-all.caddy", "http:// {\n\trespond 200\n}\n")
        self.client.post("/error-pages/catch-all", data={"on": "1"})
        self.assertEqual(self.read("catch-all.caddy"), "http:// {\n\trespond 200\n}\n")

    def test_dns_challenge_imports_the_snippet(self):
        self.assertEqual(self.edit(tls="dns").status_code, 400)  # no snippet yet
        with open(self.caddyfile, "a", encoding="utf-8") as handle:
            handle.write("\n(dns) {\n\ttls {\n\t\tdns cloudflare {env.TOKEN}\n\t}\n}\n")
        self.host["dns_snippet"] = "dns"
        main.save_hosts([self.host])
        self.edit(tls="dns")
        text = self.read("pdf.caddy")
        self.assertIn("pdf.lab.test {\n\timport dns\n\treverse_proxy 10.0.0.5:9005\n}\n", text)
        self.assertIn('<option value="dns" selected', self.client.get("/routes/pdf/edit").text)
        self.assertIn(">DNS challenge<", self.client.get("/").text)
        self.assertEqual(main.adopt_route(text, self.host)[0]["tls"], "dns")

    def test_settings_show_what_caddy_needs_per_dns_provider(self):
        self.host["dns_snippet"] = "le-dns"
        main.save_hosts([self.host])
        page = self.client.get("/hosts/h1/edit").text
        for part in ("xcaddy build --with github.com/caddy-dns/netcup", "      NETCUP_API_KEY: &lt;from your provider&gt;",
                     "(le-dns) {\n\ttls {\n\t\tdns netcup {\n\t\t\tcustomer_number {env.NETCUP_CUSTOMER_NUMBER}"):
            self.assertIn(part, page)
        # Every snippet is a block of its own with balanced braces.
        for guide in main.dns_guides("dns"):
            self.assertEqual(guide["snippet"].count("{") - guide["snippet"].count("{env."), guide["snippet"].count("}") - guide["snippet"].count("{env."), guide["name"])

    def test_list_checks_the_target_of_every_path(self):
        self.edit(path=["/api/*"], path_upstream=["10.0.0.8:3000"])
        main.target_reachable.side_effect = lambda upstream: upstream != "10.0.0.8:3000"
        self.assertIn("No TCP connection from Caddyman to 10.0.0.8:3000.", self.client.get("/").text)

    def test_wildcard_names(self):
        # Not over HTTP: neither the own ACME CA nor Caddy's default can prove a wildcard that way.
        self.assertEqual(self.create(host="*.apps.lab.test").status_code, 400)
        self.assertEqual(self.create(host="*.apps.lab.test", tls="default").status_code, 400)
        self.assertEqual(self.create(host="docs", aliases="*.docs.lab.test").status_code, 400)
        for bad in ("a.*.lab.test", "*apps.lab.test", "*.*.lab.test"):
            self.assertEqual(self.create(host=bad, tls="internal").status_code, 400, bad)
        self.assertEqual(self.create(host="*.apps.lab.test", tls="internal").headers["location"], "/")
        # The star cannot be part of a file name, and there is nothing to open behind it.
        text = self.read("wildcard.apps.caddy")
        self.assertIn("\n*.apps.lab.test {\n\ttls internal\n", text)
        page = self.client.get("/").text
        self.assertIn("<strong>*.apps.lab.test</strong>", page)
        self.assertNotIn('href="https://*', page)
        self.assertIn('value="*.apps.lab.test"', self.client.get("/routes/wildcard.apps/edit").text)
        # The certificate is asked for under a name the wildcard covers.
        self.assertEqual(self.served.call_args.args[2], "wildcard-check.apps.lab.test")
        self.assertEqual(main.adopt_route(text, self.host)[0]["host"], "*.apps.lab.test")

    def test_skip_verify_option(self):
        block = "\t\ttransport http {\n\t\t\ttls_insecure_skip_verify\n\t\t}\n"
        self.edit(upstream="https://10.0.0.5:8006", skip_verify="1")
        self.assertIn("\treverse_proxy https://10.0.0.5:8006 {\n" + block + "\t}\n}\n", self.read("pdf.caddy"))
        self.assertIn('name="skip_verify" value="1" checked', self.client.get("/routes/pdf/edit").text)
        # Together with the Host header, in a fixed order, and it can be taken over again.
        self.edit(upstream="https://10.0.0.5:8006", skip_verify="1", host_header="1")
        text = self.read("pdf.caddy")
        self.assertIn("{\n\t\theader_up Host {upstream_hostport}\n" + block + "\t}\n}\n", text)
        route, reason = main.adopt_route(text, self.host)
        self.assertEqual((route.get("host_header"), route.get("skip_verify")), (True, True), reason)
        # A plain target has no certificate: the tick is dropped and the file stays as it was.
        self.edit(skip_verify="1")
        self.assertEqual(self.read("pdf.caddy"), self.original)

    def test_adopt_a_newsite_file(self):
        self.put("wiki.caddy", "wiki.lab.test {\n    reverse_proxy 10.0.0.7:3000\n    import stepca\n}\n")
        self.assertIn("Adopt this route", self.client.get("/routes/wiki/edit").text)
        self.client.post("/routes/wiki/adopt")
        route = main.read_route(main.Path(self.sites) / "wiki.caddy", self.host)
        self.assertEqual((route["type"], route["upstream"], route["tls"]), ("reverse_proxy", "10.0.0.7:3000", "acme_ca"))
        self.assertIn('name="mode" value="form"', self.client.get("/routes/wiki/edit").text)

    def test_adopt_recognises_every_type(self):
        cases = {
            "http://a.lab.test:8080 {\n\troot * /srv/www\n\tfile_server\n}\n": ("static", "none"),
            "a.lab.test {\n\ttls internal\n\tredir https://b.lab.test{uri} 302\n}\n": ("redirect", "internal"),
            "a.lab.test {\n\treverse_proxy https://10.0.0.7:8443\n}\n": ("reverse_proxy", "default"),
        }
        for text, expected in cases.items():
            route, reason = main.adopt_route(text, self.host)
            self.assertEqual((route["type"], route["tls"]), expected, reason)

    def test_adopt_takes_basic_auth_and_host_header(self):
        bcrypt_hash = main.hash_password("secret")
        text = (
            "a.lab.test {\n\timport stepca\n\tbasic_auth {\n\t\tada " + bcrypt_hash + "\n\t}\n"
            "\treverse_proxy 10.0.0.7:3000 {\n\t\theader_up Host {upstream_hostport}\n\t}\n}\n"
        )
        route, reason = main.adopt_route(text, self.host)
        self.assertEqual((route["auth_user"], route["auth_hash"], route["host_header"]), ("ada", bcrypt_hash, True), reason)
        # What it writes back is the same block, hash untouched, and it opens in the form.
        self.put("a.caddy", text)
        self.client.post("/routes/a/adopt")
        self.assertEqual(self.read("a.caddy").split("\n", 1)[1], text)
        self.assertIn('name="auth_user" value="ada"', self.client.get("/routes/a/edit").text)
        # Only in the shape Caddyman writes itself.
        for odd in (text.replace(bcrypt_hash, "plaintext"), text.replace("ada ", "ada bob "),
                    text.replace("header_up Host {upstream_hostport}", "header_up X-Real-IP {remote_host}"),
                    text.replace("\t\tada " + bcrypt_hash + "\n", "")):
            self.assertIsNone(main.adopt_route(odd, self.host)[0], odd)

    def test_adopt_refuses_what_it_does_not_fully_understand(self):
        refused = [
            "a.lab.test {\n\treverse_proxy 10.0.0.7:3000\n\theader X-Frame-Options DENY\n}\n",
            "a.lab.test {\n\treverse_proxy 10.0.0.7:3000 10.0.0.8:3000\n}\n",
            "a.lab.test, b.lab.test:8443 {\n\treverse_proxy 10.0.0.7:3000\n}\n",
            "a.lab.test {\n\timport other\n\treverse_proxy 10.0.0.7:3000\n}\n",
            "a.lab.test {\n\treverse_proxy 10.0.0.7:3000\n}\nb.lab.test {\n\trespond 200\n}\n",
            "a.lab.test {\n\ttls internal\n}\n",
            "a.lab.test {\n\t# keep\n\treverse_proxy 10.0.0.7:3000\n}\n",
        ]
        for text in refused:
            with self.subTest(text):
                self.assertIsNone(main.adopt_route(text, self.host)[0])
        self.put("odd.caddy", refused[0])
        self.client.post("/routes/odd/adopt")
        self.assertEqual(self.read("odd.caddy"), refused[0])
        self.assertIn("left as it is", self.client.get("/").text)


class TestHardening(RouteTest):
    def test_lock_on_the_second_factor_grows(self):
        for expected in (main.LOCK_SECONDS, main.LOCK_SECONDS * 2, main.LOCK_SECONDS * 4):
            main.LOGIN_FAILS.clear()
            for _ in range(main.MAX_LOGIN_FAILS):
                main.record_fail("198.51.100.1", "2fa:admin")
            self.assertEqual(main.locked_seconds("2fa:admin"), expected)
            self.assertEqual(main.locked_seconds("198.51.100.1"), main.LOCK_SECONDS)  # an address is not an account
        main.LOCK_ROUNDS["2fa:admin"][0] = 20
        main.LOGIN_FAILS.clear()
        for _ in range(main.MAX_LOGIN_FAILS):
            main.record_fail("2fa:admin")
        self.assertEqual(main.locked_seconds("2fa:admin"), main.LOCK_MAX_SECONDS)

    def test_the_own_password_is_not_guessed_from_a_session(self):
        form = {"password": "another horse", "repeat": "another horse"}
        for _ in range(main.MAX_LOGIN_FAILS):
            self.assertEqual(self.client.post("/profile/password", data={**form, "current": "nope"}).status_code, 400)
        answer = self.client.post("/profile/password", data={**form, "current": PASSWORD})
        self.assertEqual(answer.status_code, 400)
        self.assertIn("Too many attempts", answer.text)
        self.assertEqual(self.client.post("/profile/2fa/start", data={"current": PASSWORD}).status_code, 400)

    def test_a_broken_host_header_is_no_error(self):
        for path in ("/", "/status", "/error-pages", "/routes/new?own=1", "/profile"):
            self.assertEqual(self.client.get(path, headers={"host": "["}).status_code, 200, path)
            self.assertEqual(self.client.get(path, headers={"host": "caddyman:x"}).status_code, 200, path)

    def test_a_forwarded_address_has_to_be_one(self):
        main.resolve_addresses.return_value = {"testclient"}
        main.CADDY_ADDRESSES["until"] = 0.0
        guest = self.guest()
        guest.post("/login", data={"username": "admin", "password": "nope"}, headers={"x-forwarded-for": "<b>, not an address"})
        self.assertEqual(list(main.LOGIN_FAILS), ["testclient", "login:admin"])

    def test_turning_the_second_factor_on_ends_the_other_sessions(self):
        other = self.guest()
        other.post("/login", data={"username": "admin", "password": PASSWORD})
        self.assertEqual(other.get("/").status_code, 200)
        self.client.post("/profile/2fa/start", data={"current": PASSWORD})
        secret = main.totp_secret(main.load_users()[0], "totp_pending")
        self.client.post("/profile/2fa/confirm", data={"code": main.totp_code(secret, int(main.time.time()) // main.TOTP_SECONDS)})
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(other.get("/").headers["location"], "/login")

    def test_recovery_codes_are_stored_keyed_and_old_ones_still_work(self):
        self.assertNotEqual(main.recovery_digest("abcde-12345"), main.recovery_digest("abcde-12345", keyed=False))
        main.update_user("admin", totp=main.seal("JBSWY3DPEHPK3PXP"), recovery=[main.recovery_digest("abcde12345", keyed=False), main.recovery_digest("fffff00000")])
        user = main.load_users()[0]
        self.assertTrue(main.second_factor_ok(user, "ABCDE-12345"))
        self.assertFalse(main.second_factor_ok(user, "abcde-12345"))
        self.assertTrue(main.second_factor_ok(user, "fffff-00000"))
        self.assertEqual(main.load_users()[0]["recovery"], [])

    def test_the_page_of_a_mailed_link_sends_no_referrer(self):
        self.assertEqual(self.guest().get("/reset?token=x").headers["referrer-policy"], "no-referrer")

    def test_groups_and_error_pages_do_not_overwrite_a_change_made_meanwhile(self):
        self.create(group="Media", errors="1")
        before = self.read("pdf.caddy")
        real = main.list_routes

        def slow(host):
            found = real(host)
            path = os.path.join(self.sites, "pdf.caddy")
            os.utime(path, ns=(1, os.stat(path).st_mtime_ns + 5_000_000_000))  # somebody saves it right now
            return found

        with mock.patch.object(main, "list_routes", slow):
            self.client.post("/groups/rename", data={"old": "Media", "new": "Films"})
            self.reach("192.168.1.9:5052")
        self.assertEqual(self.read("pdf.caddy"), before)
        self.client.post("/groups/rename", data={"old": "Media", "new": "Films"})
        self.assertIn('"group":"Films"', self.read("pdf.caddy"))

    def test_log_directory_is_no_place_for_the_caddyfile(self):
        self.assertTrue(main.is_own_ground(str(main.LOG_DIR / "caddy.log")))
        self.assertFalse(main.is_own_ground("/etc/caddy/Caddyfile"))

    def test_a_short_secret_key_is_named_on_the_status_page(self):
        labels = lambda: [check["label"] for check in main.preflight(self.host)]  # noqa: E731
        self.assertNotIn("Secret key is long enough", labels())
        with mock.patch.object(main, "SECRET_KEY", "short"):
            self.assertIn("Secret key is long enough", labels())

    def test_mail_password_is_kept_only_for_the_same_server(self):
        mail = {"public_url": "https://caddyman.lab.test", "host": "smtp.lab.test", "port": "587", "security": "starttls", "user": "caddyman", "sender": "c@lab.test"}
        self.client.post("/settings/mail", data={**mail, "password": "mail-secret"})
        self.client.post("/settings/mail", data={**mail, "sender": "d@lab.test"})
        self.assertIn("password_enc", main.read_json(main.MAIL_FILE, {}))
        for change in ({"host": "smtp.evil.test"}, {"security": "none", "port": "25"}):
            self.client.post("/settings/mail", data={**mail, "password": "mail-secret"})
            self.client.post("/settings/mail", data={**mail, **change})
            self.assertNotIn("password_enc", main.read_json(main.MAIL_FILE, {}), change)

    def test_import_takes_no_broken_ca_and_no_caddy_without_its_base(self):
        def archive(host):
            data = io.BytesIO()
            with zipfile.ZipFile(data, "w") as packed:
                packed.writestr("hosts.json", main.json.dumps([host]))
            return data.getvalue()

        broken = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"
        host = {**main.HOST_DEFAULTS, "id": "0123abcd", "storage": "managed", "admin_ca": broken}
        self.assertNotIn("admin_ca", main.read_backup(archive(host))["hosts"][0])
        # Into an empty install: a Caddy elsewhere without its base Caddyfile would be pushed the routes alone.
        main.HOSTS_FILE.unlink()
        payload = base64.b64encode(archive(host)).decode()
        self.assertEqual(self.client.post("/backup/import", data={"payload": payload}).status_code, 400)
        self.assertEqual(main.load_hosts(), [])

    def test_an_unknown_https_admin_api_gets_no_login_from_a_page_view(self):
        host = {**self.host, "admin_url": "https://admin.lab.test", "admin_user": "caddyman", "admin_password_enc": main.seal("pw")}
        get = self.patch(main.httpx, "get", mock.Mock(return_value=mock.Mock(status_code=401, text="")))
        with self.assertRaises(ValueError):
            main.fetch_root_ca(host)
        self.assertIsNone(get.call_args.kwargs["auth"])
        with self.assertRaises(ValueError):
            main.fetch_root_ca(host, first=True)  # saving the settings: trust on first use
        self.assertIsNotNone(get.call_args.kwargs["auth"])


class TestComfort(RouteTest):
    def test_a_target_copied_from_the_browser_is_taken(self):
        for typed, kept in (("http://10.0.0.5:9005/", "10.0.0.5:9005"), ("HTTP://nas", "nas"), ("HTTPS://nas:5001/", "https://nas:5001"), (" 10.0.0.5:9005 ", "10.0.0.5:9005")):
            self.assertEqual(main.typed_target(typed), kept)
        self.create(upstream="http://10.0.0.5:9005/", path=["/api/*"], path_upstream=["https://10.0.0.8:8443/"])
        text = self.read("pdf.caddy")
        self.assertIn("\treverse_proxy 10.0.0.5:9005", text)
        self.assertIn("https://10.0.0.8:8443", text)
        self.assertNotIn("http://", text)
        # A path is not dropped without a word: Caddy would send the requests somewhere else.
        self.assertEqual(self.create(host="other", upstream="http://10.0.0.5:9005/admin").status_code, 400)

    def test_further_names_are_folded_in_the_route_list(self):
        self.create(aliases=["docs", "files"])
        page = self.client.get("/").text
        self.assertIn('<details class="more"><summary>2 more names</summary>', page)
        self.assertIn("<small>docs.lab.test</small>", page)


if __name__ == "__main__":
    unittest.main()
