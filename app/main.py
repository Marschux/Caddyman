"""Caddyman - a web interface for Caddy routes."""

import json
import os
import re
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

import bcrypt
import httpx
from fastapi import FastAPI, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer

VERSION = "0.1.0"

BASE_DIR = Path(__file__).parent
DATA_DIR = Path(os.getenv("CADDYMAN_DATA_DIR", "/data"))
AUTH_FILE = DATA_DIR / "auth.json"
SECRET_FILE = DATA_DIR / "secret.key"
# Where Caddy is reachable, never what it is configured to do: that stays in the route files.
HOSTS_FILE = DATA_DIR / "hosts.json"
ENV_ADMIN_USER = os.getenv("CADDYMAN_ADMIN_USER", "")
ENV_ADMIN_PASSWORD_HASH = os.getenv("CADDYMAN_ADMIN_PASSWORD_HASH", "")

SESSION_COOKIE = "caddyman_session"
SESSION_SECONDS = 7 * 24 * 3600
MAX_LOGIN_FAILS = 5
LOCK_SECONDS = 30
# bcrypt reads 72 bytes and no further; a longer password would be cut silently.
MAX_PASSWORD_BYTES = 72
MIN_PASSWORD_CHARS = 8


def write_private(path: Path, text: str) -> None:
    """Write a file only the owner can read."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)


def load_secret_key() -> tuple[str, bool]:
    """Return the key and whether it came from the environment."""
    key = os.getenv("CADDYMAN_SECRET_KEY", "")
    if key:
        return key, True
    # Fallback so sessions survive a restart. A key next to the data it protects
    # is worth little, which is why the status page will warn about it.
    if not SECRET_FILE.exists():
        write_private(SECRET_FILE, secrets.token_urlsafe(32))
    return SECRET_FILE.read_text(encoding="utf-8").strip(), False


SECRET_KEY, SECRET_KEY_FROM_ENV = load_secret_key()
SESSIONS = URLSafeTimedSerializer(SECRET_KEY, salt="session")

# Set at startup while no admin exists, cleared once setup is done.
SETUP_TOKEN: str | None = None

# In memory and never pruned, one entry per failing address. Fine for a
# LAN tool with one worker; move to a bounded store if it is ever exposed publicly.
LOGIN_FAILS: dict[str, list[float]] = {}  # address -> [fail count, locked until]


def load_admin() -> dict | None:
    if ENV_ADMIN_USER and ENV_ADMIN_PASSWORD_HASH:
        return {"username": ENV_ADMIN_USER, "password_hash": ENV_ADMIN_PASSWORD_HASH}
    try:
        return json.loads(AUTH_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def check_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode()[:MAX_PASSWORD_BYTES], password_hash.encode())
    except ValueError:
        return False


def password_problem(password: str, repeat: str) -> str | None:
    if password != repeat:
        return "The passwords do not match."
    if len(password) < MIN_PASSWORD_CHARS:
        return f"The password needs at least {MIN_PASSWORD_CHARS} characters."
    if len(password.encode()) > MAX_PASSWORD_BYTES:
        return f"The password is longer than {MAX_PASSWORD_BYTES} bytes."
    return None


def client_address(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def locked_seconds(address: str) -> int:
    until = LOGIN_FAILS.get(address, [0, 0.0])[1]
    return max(0, round(until - time.monotonic()))


def record_fail(address: str) -> None:
    entry = LOGIN_FAILS.setdefault(address, [0, 0.0])
    entry[0] += 1
    if entry[0] >= MAX_LOGIN_FAILS:
        entry[0] = 0
        entry[1] = time.monotonic() + LOCK_SECONDS


def session_user(request: Request, admin: dict | None) -> str | None:
    cookie = request.cookies.get(SESSION_COOKIE)
    if not cookie or not admin:
        return None
    try:
        user = SESSIONS.loads(cookie, max_age=SESSION_SECONDS)
    except BadSignature:
        return None
    return user if user == admin["username"] else None


def start_session(response: RedirectResponse, request: Request, username: str) -> RedirectResponse:
    response.set_cookie(
        SESSION_COOKIE,
        SESSIONS.dumps(username),
        max_age=SESSION_SECONDS,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
    )
    return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    global SETUP_TOKEN
    if load_admin() is None:
        SETUP_TOKEN = secrets.token_hex(8)
        port = os.getenv("CADDYMAN_PORT", "5052")
        print(f"Setup required. Open http://<host>:{port}/setup\nToken: {SETUP_TOKEN}", flush=True)
    if not SECRET_KEY_FROM_ENV:
        print("CADDYMAN_SECRET_KEY is not set, using a generated key from the data directory.", flush=True)
    yield


app = FastAPI(title="Caddyman", version=VERSION, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


@app.middleware("http")
async def require_session(request: Request, call_next):
    path = request.url.path
    admin = load_admin()
    request.state.user = session_user(request, admin)
    if path == "/healthz" or path.startswith("/static/"):
        pass
    elif admin is None:
        if path != "/setup":
            return RedirectResponse("/setup", status_code=303)
    elif path == "/setup":
        return RedirectResponse("/", status_code=303)
    elif path != "/login" and not request.state.user:
        return RedirectResponse("/login", status_code=303)
    return await call_next(request)


def page(request: Request, name: str, status_code: int = 200, **context):
    return templates.TemplateResponse(request, name, {"version": VERSION, **context}, status_code=status_code)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/setup")
def setup_form(request: Request):
    return page(request, "setup.html")


@app.post("/setup")
def setup_submit(
    request: Request,
    token: str = Form(""),
    username: str = Form(""),
    password: str = Form(""),
    repeat: str = Form(""),
):
    global SETUP_TOKEN
    address = client_address(request)
    username = username.strip()
    if wait := locked_seconds(address):
        error = f"Too many attempts. Try again in {wait} seconds."
    elif not SETUP_TOKEN or not secrets.compare_digest(token.strip().encode(), SETUP_TOKEN.encode()):
        record_fail(address)
        error = "The token does not match the one in the container log."
    elif not username or len(username) > 64:
        error = "The username needs 1 to 64 characters."
    else:
        error = password_problem(password, repeat)
    if error:
        return page(request, "setup.html", status_code=400, error=error, username=username)
    write_private(AUTH_FILE, json.dumps({"username": username, "password_hash": hash_password(password)}))
    SETUP_TOKEN = None
    return start_session(RedirectResponse("/", status_code=303), request, username)


@app.get("/login")
def login_form(request: Request):
    if request.state.user:
        return RedirectResponse("/", status_code=303)
    return page(request, "login.html")


@app.post("/login")
def login_submit(request: Request, username: str = Form(""), password: str = Form("")):
    address = client_address(request)
    admin = load_admin()
    if wait := locked_seconds(address):
        return page(request, "login.html", status_code=429, error=f"Too many attempts. Try again in {wait} seconds.")
    # The hash is always checked, so a wrong username takes as long as a wrong password.
    password_ok = check_password(password, admin["password_hash"])
    username_ok = secrets.compare_digest(username.strip().encode(), admin["username"].encode())
    if not (password_ok and username_ok):
        record_fail(address)
        return page(request, "login.html", status_code=401, error="Wrong username or password.", username=username)
    LOGIN_FAILS.pop(address, None)
    return start_session(RedirectResponse("/", status_code=303), request, admin["username"])


@app.post("/logout")
def logout():
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response


HOST_DEFAULTS = {
    "name": "",
    "admin_url": "http://caddy:2019",
    "caddyfile": "/etc/caddy/Caddyfile",
    "sites_dir": "/etc/caddy/sites",
    "tls_snippet": "",
    "root_ca_url": "",
    "domain_suffix": "",
}
HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9-]+)*$")
SNIPPET_RE = re.compile(r"^[A-Za-z0-9_-]+$")
ADMIN_TIMEOUT = 5


def load_hosts() -> list[dict]:
    try:
        return json.loads(HOSTS_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []


def save_hosts(hosts: list[dict]) -> None:
    write_private(HOSTS_FILE, json.dumps(hosts, indent=2))


def is_http_url(value: str) -> bool:
    try:
        parts = urlsplit(value)
        return parts.scheme in ("http", "https") and bool(parts.hostname) and not parts.username
    except ValueError:
        return False


def is_clean_path(value: str) -> bool:
    return value.startswith("/") and ".." not in value.split("/") and value.isprintable()


def host_problem(host: dict) -> str | None:
    if not host["name"] or len(host["name"]) > 64:
        return "The name needs 1 to 64 characters."
    if not is_http_url(host["admin_url"]) or urlsplit(host["admin_url"]).path:
        return "The admin API has to look like http://caddy:2019."
    if not is_clean_path(host["caddyfile"]) or not is_clean_path(host["sites_dir"]):
        return "Caddyfile and sites directory have to be absolute paths without '..'."
    if host["tls_snippet"] and not SNIPPET_RE.match(host["tls_snippet"]):
        return "The snippet name may only contain letters, digits, '-' and '_'."
    if host["root_ca_url"] and not is_http_url(host["root_ca_url"]):
        return "The root CA source has to be an http or https URL."
    if host["domain_suffix"] and not HOSTNAME_RE.match(host["domain_suffix"]):
        return "The domain suffix has to be a hostname such as home.example."
    return None


def preflight(host: dict) -> list[dict]:
    """Check what a host needs before routes can be written. Reads only, writes nothing."""
    checks = []

    def add(label: str, ok, detail: str = "", hint: str = "", block: str = "") -> None:
        checks.append({"label": label, "ok": bool(ok), "detail": detail, "hint": hint, "block": block})

    caddyfile, sites, snippet = host["caddyfile"], host["sites_dir"], host["tls_snippet"]
    try:
        text = Path(caddyfile).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        text = None
        add(
            "Base Caddyfile is readable",
            False,
            str(error),
            "Mount Caddy's Caddyfile into this container at the path Caddy itself uses. In this tool's compose file:",
            f"    volumes:\n      - /opt/caddy/Caddyfile:{caddyfile}:ro",
        )
    else:
        add("Base Caddyfile is readable", True, caddyfile)

    if text is not None:
        import_line = f"import {sites}/*.caddy"
        add(
            "Base Caddyfile imports the sites directory",
            re.search(rf"^\s*{re.escape(import_line)}\s*$", text, re.MULTILINE),
            import_line,
            "Add this line at the end of the base Caddyfile:",
            import_line,
        )
        if snippet:
            add(
                f"TLS snippet '{snippet}' exists",
                re.search(rf"^\({re.escape(snippet)}\)\s*\{{", text, re.MULTILINE),
                "",
                "Add the snippet to the base Caddyfile, with the ACME directory of your CA:",
                f"({snippet}) {{\n\ttls {{\n\t\tca https://ca.example/acme/acme/directory\n"
                "\t\tca_root /etc/caddy/root_ca.crt\n\t}\n}",
            )

    try:
        response = httpx.get(f"{host['admin_url']}/config/", timeout=ADMIN_TIMEOUT)
        admin_ok, detail = response.status_code == 200, f"HTTP {response.status_code}"
    except httpx.HTTPError as error:
        admin_ok, detail = False, str(error) or type(error).__name__
    add(
        "Admin API is reachable",
        admin_ok,
        f"{host['admin_url']} - {detail}",
        "By default Caddy's admin API only listens inside its own container. To reach it from here, add "
        "this to the global options block. Do not publish port 2019, and keep in mind that every "
        "container on the same Docker network can then reconfigure Caddy.",
        "{\n\tadmin :2019\n}",
    )

    add(
        "Sites directory is writable",
        os.path.isdir(sites) and os.access(sites, os.W_OK),
        sites,
        "Mount Caddy's sites directory into this container, writable. In this tool's compose file:",
        f"    volumes:\n      - /opt/caddy/sites:{sites}",
    )
    return checks


async def host_from_form(request: Request) -> dict:
    form = await request.form()
    host = {key: str(form.get(key, "")).strip() for key in HOST_DEFAULTS}
    host["admin_url"] = host["admin_url"].rstrip("/")
    host["sites_dir"] = host["sites_dir"].rstrip("/") or "/"
    host["domain_suffix"] = host["domain_suffix"].lower().strip(".")
    return host


@app.get("/")
def index(request: Request):
    if not load_hosts():
        return RedirectResponse("/hosts/new", status_code=303)
    return page(request, "index.html")


@app.get("/hosts")
def hosts_list(request: Request):
    return page(request, "hosts.html", hosts=load_hosts())


@app.get("/hosts/new")
def host_new(request: Request):
    return page(request, "host_form.html", host=HOST_DEFAULTS, first=not load_hosts())


@app.get("/hosts/{host_id}/edit")
def host_edit(request: Request, host_id: str):
    host = next((item for item in load_hosts() if item["id"] == host_id), None)
    if host is None:
        return RedirectResponse("/hosts", status_code=303)
    return page(request, "host_form.html", host={**HOST_DEFAULTS, **host})


@app.post("/hosts/new")
@app.post("/hosts/{host_id}/edit")
async def host_save(request: Request, host_id: str | None = None):
    hosts = load_hosts()
    host = await host_from_form(request)
    error = host_problem(host)
    if not error and any(item["name"] == host["name"] and item["id"] != host_id for item in hosts):
        error = "A host with this name already exists."
    if error:
        return page(request, "host_form.html", status_code=400, error=error, host={**host, "id": host_id})
    # Only this layout exists so far; 'managed' follows later.
    host["storage"] = "mounted"
    if host_id is None:
        hosts.append({"id": secrets.token_hex(4), **host})
    else:
        hosts = [{"id": host_id, **host} if item["id"] == host_id else item for item in hosts]
    save_hosts(hosts)
    return RedirectResponse("/status", status_code=303)


@app.post("/hosts/{host_id}/delete")
def host_delete(host_id: str):
    save_hosts([item for item in load_hosts() if item["id"] != host_id])
    return RedirectResponse("/hosts", status_code=303)


@app.get("/status")
def status(request: Request):
    hosts = [{**host, "checks": preflight(host)} for host in load_hosts()]
    return page(request, "status.html", hosts=hosts)
