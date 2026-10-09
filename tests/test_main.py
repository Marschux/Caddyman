import base64
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
os.environ["CADDYMAN_SECRET_KEY"] = "test-key"
os.environ.pop("CADDYMAN_ADMIN_USER", None)

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
        # The icon is linked from every page and has to load before anyone is logged in.
        self.assertIn('rel="icon" type="image/svg+xml" href="/static/favicon.svg"', self.client.get("/setup").text)
        self.assertEqual(self.client.get("/static/favicon.svg").headers["content-type"], "image/svg+xml")
        # License and source are named on every page, also before login.
        footer = self.client.get("/setup").text.split("<footer>")[1]
        self.assertIn("AGPL-3.0-or-later", footer)
        self.assertIn(f'href="{main.SOURCE_URL}"', footer)

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

    def checks(self, caddyfile_text, admin=None, **fields):
        if caddyfile_text is not None:
            with open(self.caddyfile, "w", encoding="utf-8") as handle:
                handle.write(caddyfile_text)
        admin = admin or mock.Mock(return_value=mock.Mock(status_code=200))
        with mock.patch.object(main.httpx, "get", admin):
            host = self.host(caddyfile=self.caddyfile, sites_dir=self.sites, **fields)
            if fields.get("admin_user"):
                host["admin_password_enc"] = main.VAULT.encrypt(b"pw").decode()
            result = main.preflight(host)
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
        host_id = main.load_hosts()[0]["id"]
        # There is one Caddy: a second one cannot be added, the old list leads to its settings.
        self.assertEqual(self.client.post("/hosts/new", data=self.host(name="second")).headers["location"], "/hosts")
        self.assertEqual(self.client.get("/hosts").headers["location"], f"/hosts/{host_id}/edit")
        self.assertEqual(self.client.get("/hosts/new").headers["location"], f"/hosts/{host_id}/edit")
        self.assertEqual(len(main.load_hosts()), 1)
        self.client.post(f"/hosts/{host_id}/edit", data=self.host(name="renamed", admin_url="http://caddy:2019/"))
        self.assertEqual(
            [(h["id"], h["name"], h["admin_url"]) for h in main.load_hosts()],
            [(host_id, "renamed", "http://caddy:2019")],
        )
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


class RouteTest(AppTest):
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
        self.real_reachable = main.target_reachable
        self.patch(main, "target_reachable", mock.Mock(return_value=True))
        self.served = self.patch(main, "served_certificate", mock.Mock(side_effect=OSError("offline")))

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


class TestRoutes(RouteTest):
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

    def test_form_hands_the_real_routes_to_the_game(self):
        self.create()
        self.create(type="static", host="docs", root="/srv/www", tls="none")
        page = self.client.get("/routes/new").text
        self.assertIn("""data-game='[["pdf.lab.test", "10.0.0.5:9005"]]'""", page)  # reverse proxies only
        self.assertIn('<script src="/static/game.js" defer>', page)
        self.assertEqual(self.client.get("/static/game.js").status_code, 200)
        # The name itself stays an ordinary hostname for the server: the game lives in the browser.
        self.assertEqual(self.create(host="candyman").headers["location"], "/?host=h1")

    def test_unreachable_target_only_warns(self):
        main.target_reachable.return_value = False
        self.assertEqual(self.create().headers["location"], "/?host=h1")
        self.assertIn("does not answer yet", self.client.get("/").text)
        self.assertTrue(os.path.exists(os.path.join(self.sites, "pdf.caddy")))

    def test_target_without_port(self):
        self.assertEqual(self.create(upstream="http://10.0.0.5").headers["location"], "/?host=h1")
        self.assertIn("reverse_proxy http://10.0.0.5\n", self.read("pdf.caddy"))
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
        self.assertEqual(links(type="redirect", target="https://x.test/a")[1], "https://x.test/a")
        self.assertEqual(links(type="redirect", target="javascript:alert(1)")[1], "")
        self.assertEqual(links(type="static", root="/srv/www")[1], "")
        self.create()
        self.assertIn('href="https://pdf.lab.test"', self.client.get("/").text)

    def test_route_icon(self):
        png = b"\x89PNG fake"

        def target(request):
            if request.url.path == "/":
                return main.httpx.Response(200, html='<link rel="shortcut icon" href="/static/app.png">')
            if request.url.path == "/static/app.png":
                return main.httpx.Response(200, content=png, headers={"content-type": "image/png"})
            return main.httpx.Response(200, html="<script>alert(1)</script>")  # /favicon.ico answered with a page

        client = main.httpx.Client
        self.patch(main.httpx, "Client", lambda **_: client(transport=main.httpx.MockTransport(target)))
        self.assertEqual(main.fetch_icon("10.0.0.5:9005"), (png, "image/png"))
        self.create()
        response = self.client.get("/routes/pdf/icon")
        self.assertEqual((response.content, response.headers["content-type"]), (png, "image/png"))
        self.assertIn("sandbox", response.headers["content-security-policy"])
        self.assertIn("/routes/pdf/icon", self.client.get("/").text)
        # Nothing that is not a picture gets through, and other route types have no icon.
        self.patch(main.httpx, "Client", lambda **_: client(transport=main.httpx.MockTransport(
            lambda request: main.httpx.Response(200, html="<script>alert(1)</script>"))))
        self.assertEqual(self.client.get("/routes/pdf/icon").status_code, 404)
        self.create(type="static", host="docs", root="/srv/www", tls="none")
        self.assertEqual(self.client.get("/routes/docs/icon").status_code, 404)

    def test_list_marks_unreachable_target(self):
        self.create()
        self.create(type="static", host="docs", root="/srv/www", tls="none")
        self.assertNotIn("Not reachable", self.client.get("/").text)
        main.target_reachable.return_value = False
        self.assertEqual(self.client.get("/").text.count("Not reachable"), 1)  # reverse proxies only


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
        self.assertNotIn("internal CA, because", page)
        self.assertEqual(self.get.call_args.args[0], "https://ca.lab.test:9001/roots.pem")
        download = self.client.get("/ca/root-ca.crt")
        self.assertEqual(download.text, self.PEM + "\n")  # only the certificate, nothing around it
        self.assertIn("attachment", download.headers["content-disposition"])

    def test_falls_back_to_caddys_internal_ca(self):
        self.answer(json={"root_certificate": self.PEM + "\n"})
        page = self.client.get("/ca").text
        self.assertIn(self.SHA256, page)
        self.assertIn("internal CA, because", page)
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

    def test_needs_a_session(self):
        self.client.cookies.clear()
        self.assertEqual(self.client.get("/ca/root-ca.crt").headers["location"], "/login")


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

    def patch(self, target, name, value):
        patcher = mock.patch.object(target, name, value)
        self.addCleanup(patcher.stop)
        return patcher.start()

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
        self.client.post(f"/hosts/{host['id']}/edit", data=self.form(admin_password="", name="renamed"))
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
        self.assertEqual(self.add_route().headers["location"], f"/?host={host['id']}")
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
        self.assertEqual(set(checks().values()), {True})
        # Caddy restarted without --resume and serves something else now.
        self.get.return_value = mock.Mock(status_code=200, content=b"its own file")
        self.assertFalse(checks()[label])

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
        self.client.post("/backup/restore", data={"payload": base64.b64encode(archive).decode()})
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
        self.assertIn("internal CA instead of your ACME CA", page)


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
        lines = main.read_log_tail(main.Path(self.logs) / "caddy.log")
        self.assertEqual(main.parse_log_line(lines[-1])["msg"], "the last one")
        self.assertLess(len(lines), 5)
        self.assertTrue(all(line.startswith("{") for line in lines))  # no half line at the start

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
        names, chosen, lines = main.load_log(main.load_hosts()[0], "")
        self.assertEqual((names, chosen, lines), (["caddy.log"], "caddy.log", [self.LINES[1]]))

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
        return self.client.post("/backup/restore", files={"archive": ("backup.zip", data, "application/zip")})

    def confirm(self, data, query=""):
        return self.client.post(f"/backup/restore{query}", data={"payload": base64.b64encode(data).decode()})

    def test_export_holds_routes_and_settings_but_no_secrets(self):
        with zipfile.ZipFile(io.BytesIO(self.archive)) as archive:
            self.assertEqual(
                sorted(archive.namelist()),
                ["Caddyfile", "README.txt", "backup.json", "hosts.json", "sites/pdf.caddy", "sites/wiki.caddy"],
            )
            self.assertEqual(archive.read("sites/pdf.caddy").decode(), self.pdf)
            self.assertIn("NOT IN HERE: the root CA", archive.read("README.txt").decode())
            everything = b"".join(archive.read(name) for name in archive.namelist())
        self.assertNotIn(b"password_hash", everything)
        self.assertNotIn(main.SECRET_KEY.encode(), everything)

    def test_preview_changes_nothing_and_confirm_restores(self):
        os.remove(os.path.join(self.sites, "wiki.caddy"))
        with open(os.path.join(self.sites, "pdf.caddy"), "a", encoding="utf-8") as handle:
            handle.write("# edited\n")
        with open(os.path.join(self.sites, "extra.caddy"), "w", encoding="utf-8") as handle:
            handle.write("extra.lab.test {\n}\n")
        self.load.reset_mock()
        preview = self.upload(self.archive)
        self.assertIn("Overwritten", preview.text)
        self.assertIn("Created", preview.text)
        self.assertFalse(os.path.exists(os.path.join(self.sites, "wiki.caddy")))
        self.load.assert_not_called()
        self.assertEqual(self.confirm(self.archive).headers["location"], "/?host=h1")
        self.assertEqual((self.read("pdf.caddy"), self.read("wiki.caddy")), (self.pdf, self.wiki))
        self.assertTrue(os.path.exists(os.path.join(self.sites, "extra.caddy")))  # not in the archive, kept
        self.assertEqual(self.load.call_count, 1)  # one reload for the whole restore
        self.assertEqual(main.read_audit()[0]["action"], "restore")

    def test_rejected_restore_undoes_every_file(self):
        os.remove(os.path.join(self.sites, "wiki.caddy"))
        with open(os.path.join(self.sites, "pdf.caddy"), "w", encoding="utf-8") as handle:
            handle.write("changed\n")
        self.reject()
        self.confirm(self.archive)
        self.assertEqual(os.listdir(self.sites), ["pdf.caddy"])
        self.assertEqual(self.read("pdf.caddy"), "changed\n")

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
        self.assertEqual(self.client.post("/backup/restore", data={"payload": "@@not base64@@"}).status_code, 400)

    def test_restore_into_an_empty_install_brings_the_host_back(self):
        main.save_hosts([])
        for name in os.listdir(self.sites):
            os.remove(os.path.join(self.sites, name))
        self.assertIn("host settings from the archive are restored", self.upload(self.archive).text)
        self.assertEqual(main.load_hosts(), [])  # the preview restores nothing
        self.confirm(self.archive)
        self.assertEqual([(h["name"], h["sites_dir"]) for h in main.load_hosts()], [("lab", self.sites)])
        self.assertEqual(sorted(os.listdir(self.sites)), ["pdf.caddy", "wiki.caddy"])

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

    def write(self, name, text):
        with open(os.path.join(self.sites, name), "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)

    def test_own_route_opens_in_the_form_and_saves(self):
        page = self.client.get("/routes/pdf/edit").text
        self.assertIn('name="mode" value="form"', page)
        self.assertIn("10.0.0.5:9005", page)
        self.assertEqual(self.edit(upstream="10.0.0.6:80").headers["location"], "/?host=h1")
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
        self.write("pdf.caddy", "pdf.lab.test {\n\trespond 418\n}\n")
        os.utime(os.path.join(self.sites, "pdf.caddy"), ns=(1, 1))
        response = self.edit(mtime=stale, upstream="10.0.0.6:80")
        self.assertEqual(response.status_code, 409)
        self.assertIn("respond 418", response.text)  # what is on disk
        self.assertIn("10.0.0.6:80", response.text)  # what was about to be saved
        self.assertIn("respond 418", self.read("pdf.caddy"))
        # The page now carries the new time, so saving again is a deliberate overwrite.
        self.assertIn('name="mtime" value="1"', response.text)
        self.assertEqual(self.edit(mtime="1", upstream="10.0.0.6:80").headers["location"], "/?host=h1")
        self.assertIn("10.0.0.6:80", self.read("pdf.caddy"))

    def test_foreign_file_opens_as_text_and_saves(self):
        self.write("legacy.caddy", "legacy.lab.test {\n\trespond 200\n}\n")
        page = self.client.get("/routes/legacy/edit").text
        self.assertIn("<textarea", page)
        self.assertNotIn("Adopt this route", page)
        data = {"mode": "raw", "mtime": self.mtime("legacy.caddy"), "content": "legacy.lab.test {\r\n\trespond 204\r\n}"}
        self.assertEqual(self.client.post("/routes/legacy/edit", data=data).headers["location"], "/?host=h1")
        self.assertEqual(self.read("legacy.caddy"), "legacy.lab.test {\n\trespond 204\n}\n")

    def test_rejected_text_is_put_back(self):
        before = "legacy.lab.test {\n\trespond 200\n}\n"
        self.write("legacy.caddy", before)
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
        # An empty username takes the login away again.
        self.edit()
        self.assertEqual(self.read("pdf.caddy"), self.original)

    def test_basic_auth_input_is_validated(self):
        self.assertEqual(self.edit(auth_user="max").status_code, 400)  # no password yet
        self.assertEqual(self.edit(auth_user="a b", auth_password="secret").status_code, 400)
        self.assertEqual(self.edit(auth_user="x {\n\trespond", auth_password="secret").status_code, 400)
        self.assertEqual(self.edit(auth_user="max", auth_password="x" * 73).status_code, 400)
        self.assertEqual(self.read("pdf.caddy"), self.original)

    def test_host_header_option(self):
        self.edit(host_header="1")
        self.assertIn(
            "\treverse_proxy 10.0.0.5:9005 {\n\t\theader_up Host {upstream_hostport}\n\t}\n}\n", self.read("pdf.caddy")
        )
        self.assertIn('name="host_header" value="1" checked', self.client.get("/routes/pdf/edit").text)

    def test_adopt_a_newsite_file(self):
        self.write("wiki.caddy", "wiki.lab.test {\n    reverse_proxy 10.0.0.7:3000\n    import stepca\n}\n")
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

    def test_adopt_refuses_what_it_does_not_fully_understand(self):
        refused = [
            "a.lab.test {\n\treverse_proxy 10.0.0.7:3000\n\theader X-Frame-Options DENY\n}\n",
            "a.lab.test {\n\treverse_proxy 10.0.0.7:3000 10.0.0.8:3000\n}\n",
            "a.lab.test, b.lab.test {\n\treverse_proxy 10.0.0.7:3000\n}\n",
            "a.lab.test {\n\timport other\n\treverse_proxy 10.0.0.7:3000\n}\n",
            "a.lab.test {\n\treverse_proxy 10.0.0.7:3000\n}\nb.lab.test {\n\trespond 200\n}\n",
            "a.lab.test {\n\ttls internal\n}\n",
            "a.lab.test {\n\t# keep\n\treverse_proxy 10.0.0.7:3000\n}\n",
        ]
        for text in refused:
            with self.subTest(text):
                self.assertIsNone(main.adopt_route(text, self.host)[0])
        self.write("odd.caddy", refused[0])
        self.client.post("/routes/odd/adopt")
        self.assertEqual(self.read("odd.caddy"), refused[0])
        self.assertIn("left as it is", self.client.get("/").text)


if __name__ == "__main__":
    unittest.main()
