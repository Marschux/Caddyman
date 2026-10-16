"""Caddyman - a web interface for Caddy routes."""

import asyncio
import base64
import binascii
import contextvars
import gzip
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import secrets
import shutil
import smtplib
import socket
import ssl
import struct
import threading
import time
import zipfile
import zlib
from concurrent.futures import ThreadPoolExecutor, wait
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote, urlsplit
from zoneinfo import ZoneInfo, available_timezones

import bcrypt
import httpx
import segno
from cryptography import x509
from cryptography.fernet import Fernet, InvalidToken
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, Form, Request
from fastapi.responses import RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer

VERSION = "0.27.16"
# Shown in the footer. The AGPL asks that everyone using this over a network can get the source,
# so a modified copy has to point to its own.
SOURCE_URL = os.getenv("CADDYMAN_SOURCE_URL", "https://github.com/Marschux/Caddyman")

BASE_DIR = Path(__file__).parent
DATA_DIR = Path(os.getenv("CADDYMAN_DATA_DIR", "/data"))
AUTH_FILE = DATA_DIR / "auth.json"
SECRET_FILE = DATA_DIR / "secret.key"
# Where Caddy is reachable, never what it is configured to do: that stays in the route files.
HOSTS_FILE = DATA_DIR / "hosts.json"
AUDIT_FILE = DATA_DIR / "audit.log"
AUDIT_SHOWN = 100
# How a moment is written, in the change log and wherever one is shown.
STAMP = "%Y-%m-%d %H:%M:%S"
FLASH_COOKIE = "caddyman_flash"
# For installs where nobody gets to read the container log.
ENV_SETUP_TOKEN = os.getenv("CADDYMAN_SETUP_TOKEN", "").strip()
OWN_PORT = os.getenv("CADDYMAN_PORT", "5052")
# The way back in when "only over HTTPS" is on and the route to Caddyman is gone.
RESET_HTTPS_ONLY = os.getenv("CADDYMAN_RESET_HTTPS_ONLY", "").strip().lower() in ("1", "true", "yes", "on")
# Whoever knows the token becomes admin, so a chosen one must not be guessable.
MIN_SETUP_TOKEN_CHARS = 12

SESSION_COOKIE = "caddyman_session"
SESSION_SECONDS = 7 * 24 * 3600
MAX_LOGIN_FAILS = 5
LOCK_SECONDS = 30
# A failure counts for this long. A login that works does not wipe the count: somebody with an
# account of their own could otherwise start over between two guesses at another one.
FAIL_SECONDS = 600
# bcrypt reads 72 bytes and no further; a longer password would be cut silently.
MAX_PASSWORD_BYTES = 72
MIN_PASSWORD_CHARS = 8
MIN_SECRET_KEY_CHARS = 32
# No form of Caddyman comes near this. The largest is an import, which carries its archive of
# up to 512 KiB as text.
MAX_BODY_BYTES = 2 * 1024 * 1024


def find_zone(name) -> ZoneInfo | None:
    """The time zone of that name, or None when there is none."""
    try:
        return ZoneInfo(name) if isinstance(name, str) and name else None
    except (KeyError, ValueError, OSError):
        return None


@lru_cache
def zone_names() -> list[str]:
    """Every time zone this system knows. Collected once: gathering them walks a directory tree."""
    return sorted(available_timezones())


# The zone the times in the logs and the change log are shown in unless one is chosen under
# Settings. What is stored stays UTC.
TIME_ZONE = find_zone(os.getenv("TZ")) or ZoneInfo("UTC")


def is_number(value: str) -> bool:
    """Digits 0 to 9 only. isdigit() alone also takes "²", which int() refuses."""
    return value.isascii() and value.isdigit()


def read_json(path: Path, default):
    """What a file in the data directory holds, or the default as long as it does not exist."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default


def write_json(path: Path, data) -> None:
    write_private(path, json.dumps(data, indent=2))


def write_whole(path: Path, data: bytes, mode: int | None = None) -> None:
    """Put a file in place in one step: written next to it first, so a crash never leaves half of it.

    Without a mode, a file that is replaced keeps the one it had.
    """
    # Not a name the import of the sites directory would pick up. One per call, so two writes of
    # the same file at once do not take each other's draft away.
    draft = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    try:
        fd = os.open(draft, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode or 0o666)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        if mode is None and path.exists():
            shutil.copymode(path, draft)
        os.replace(draft, path)
    finally:
        draft.unlink(missing_ok=True)


def write_private(path: Path, text: str) -> None:
    """Write a file only the owner can read."""
    path.parent.mkdir(parents=True, exist_ok=True)
    write_whole(path, text.encode("utf-8"), 0o600)


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
# A message for the next page has the shape of a session value, so it gets a key of its own.
FLASHES = URLSafeTimedSerializer(SECRET_KEY, salt="flash")
# Encrypts the admin API passwords in hosts.json. Lose the key and they have to be typed in again.
VAULT = Fernet(base64.urlsafe_b64encode(hashlib.sha256(f"vault:{SECRET_KEY}".encode()).digest()))


def seal(text: str) -> str:
    return VAULT.encrypt(text.encode()).decode()


def unseal(text: str, ttl: int | None = None) -> str:
    """Raises InvalidToken for what another secret key encrypted, or what is older than ttl seconds."""
    return VAULT.decrypt(text.encode(), ttl).decode()


def said(error: Exception) -> str:
    """What an error says, or its name when it says nothing."""
    return str(error) or type(error).__name__


# Set at startup while no admin exists, cleared once setup is done.
SETUP_TOKEN: str | None = None

# In memory, one entry per failing address or account, dropped once it is neither locked nor
# recent. Fine for a LAN tool with one worker; move to a shared store if there are ever several.
LOGIN_FAILS: dict[str, list[float]] = {}  # address or account -> [fail count, locked until, last fail]
FAIL_SWEEP = {"next": 0.0}
# The lock on the second factor of an account doubles each time, up to an hour, and starts over
# after a day without one. At that step the password is known, so 30 seconds each time would
# leave thousands of guesses a day at a code of six digits.
LOCK_ROUNDS: dict[str, list[float]] = {}  # "2fa:<account>" -> [locks so far, last lock]
LOCK_MAX_SECONDS = 3600
LOCK_ROUND_SECONDS = 86400


# One checkbox per area. Seeing the route list, the status page and the own profile needs none.
PERMISSIONS = {
    "routes": "Change routes and reload Caddy",
    "groups": "Groups",
    "errors": "Error pages",
    "ca": "Root CA page",
    "backup": "Backup and import",
    "logs": "Logs",
    "caddy": "Settings: Caddy",
    "general": "Settings: General",
    "smtp": "Settings: SMTP",
    "alerts": "Settings: Alerts",
    "users": "Manage users",
}
# Rights that were split up: an account from before keeps what it could do (15.10.2026).
RIGHTS_VERSION = 3
SPLIT_RIGHTS = {"routes": ("groups", "errors"), "settings": ("caddy", "general", "smtp", "alerts")}
USERS_LOCK = threading.Lock()
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\Z")
# Who is acting, for the change log. Set per request by the middleware.
CURRENT_USER: contextvars.ContextVar[str] = contextvars.ContextVar("user", default="-")
# Whether the request at hand came over HTTPS, for cookies set where no request is in reach.
OVER_HTTPS: contextvars.ContextVar[bool] = contextvars.ContextVar("https", default=False)


def load_users() -> list[dict]:
    data = read_json(AUTH_FILE, [])
    if isinstance(data, dict):
        # The file of the single admin from before there were users: that account keeps every right.
        return [{**data, "permissions": list(PERMISSIONS)}]
    return [split_rights(user) for user in data]


def split_rights(user: dict) -> dict:
    """An account saved before the rights were split, with the finer rights it had in the coarse ones.

    Version 2 had the split without Alerts: whoever held every other settings block gets it too.
    """
    version = user.get("rights", 1)
    if version >= RIGHTS_VERSION or not isinstance(user.get("permissions"), list):
        return user
    had = user["permissions"]
    finer = [right for right in had if right in PERMISSIONS] + [new for old, news in SPLIT_RIGHTS.items() if old in had for new in news]
    if version == 2 and {"caddy", "general", "smtp"} <= set(had):
        finer.append("alerts")
    return {**user, "permissions": [right for right in PERMISSIONS if right in finer], "rights": RIGHTS_VERSION}


def save_users(users: list[dict]) -> None:
    # Whatever is written already has the finer rights, so they are not added again on the next read.
    write_json(AUTH_FILE, [{**user, "rights": RIGHTS_VERSION} for user in users])


def find_user(users: list[dict], username: str) -> dict | None:
    return next((user for user in users if user["username"] == username), None)


def one_more_logout(user: dict) -> int:
    """For update_user: counted under the lock, so two logouts at once both end every session."""
    return user.get("logouts", 0) + 1


def update_user(username: str, **fields) -> None:
    """Read, change and write under one lock, so two requests cannot lose each other's change.

    A field set to None is removed. A function as value gets the account as it is under the lock.
    """
    with USERS_LOCK:
        users = load_users()
        if user := find_user(users, username):
            user.update({key: value(user) if callable(value) else value for key, value in fields.items()})
            for key in [key for key, value in fields.items() if value is None]:
                user.pop(key, None)
            save_users(users)


def user_problem(user: dict, others: list[dict]) -> str | None:
    """What is wrong with the name fields of a user, checked against all other accounts."""
    name, email = user["username"], user.get("email", "")
    if not name or len(name) > 64 or name != name.strip() or not name.isprintable():
        return "The username needs 1 to 64 characters."
    # Not even in other letter case: the login lock counts names in small letters, so both would share one.
    if any(other["username"].lower() == name.lower() for other in others):
        return "This username is taken."
    if len(user.get("realname", "")) > 64:
        return "The name is longer than 64 characters."
    if email and (len(email) > 254 or not EMAIL_RE.match(email)):
        return "This does not look like an email address."
    if email and any(other.get("email", "").lower() == email.lower() for other in others):
        return "Another account already uses this email address."
    return None


def initials(user: dict) -> str:
    words = (user.get("realname") or user["username"]).split()
    return (words[0][0] + (words[-1][0] if len(words) > 1 else "")).upper()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


# Checked when the username is unknown, so that answer takes as long as a wrong password.
DUMMY_HASH = hash_password(secrets.token_hex(8))


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


def locked_seconds(*keys: str) -> int:
    until = max(LOGIN_FAILS.get(key, [0, 0.0])[1] for key in keys)
    return max(0, round(until - time.monotonic()))


def record_fail(*keys: str) -> None:
    now = time.monotonic()
    # Swept once a minute, not on every failure: many guesses would otherwise each walk the whole list.
    # An entry left over in between counts nothing, it is reset below once it is old.
    if now >= FAIL_SWEEP["next"]:
        FAIL_SWEEP["next"] = now + 60
        for key, entry in list(LOGIN_FAILS.items()):
            if entry[1] < now and now - entry[2] > FAIL_SECONDS:
                LOGIN_FAILS.pop(key, None)
    for key in keys:
        entry = LOGIN_FAILS.setdefault(key, [0, 0.0, now])
        if now - entry[2] > FAIL_SECONDS:
            entry[0] = 0
        entry[0], entry[2] = entry[0] + 1, now
        if entry[0] >= MAX_LOGIN_FAILS:
            entry[0] = 0
            entry[1] = now + LOCK_SECONDS
            if key.startswith("2fa:"):
                for name, (_, last) in list(LOCK_ROUNDS.items()):
                    if now - last > LOCK_ROUND_SECONDS:
                        LOCK_ROUNDS.pop(name, None)
                rounds = LOCK_ROUNDS.get(key, [0, now])[0]
                LOCK_ROUNDS[key] = [rounds + 1, now]
                entry[1] = now + min(LOCK_SECONDS * 2**rounds, LOCK_MAX_SECONDS)
                # Kept while the lock holds: the sweep above only drops what is no longer locked.


def own_password_problem(me: dict, current: str, wrong: str = "The current password is wrong.") -> str | None:
    """What stands against taking `current` as the password of the account that is logged in.

    Counted against the account like a login: a session somebody borrowed is no way to guess
    the password at leisure.
    """
    account = f"login:{me['username'].lower()[:64]}"
    if wait := locked_seconds(account):
        return f"Too many attempts. Try again in {wait} seconds."
    if check_password(current, me["password_hash"]):
        return None
    record_fail(account)
    return wrong


def is_https(request: Request) -> bool:
    """From the scope, not from request.url: that one parses the Host header and raises on a broken one."""
    return request.scope.get("scheme") == "https"


def asked_host(request: Request) -> tuple[str, int | None]:
    """Name and port the browser asked for. They come from the Host header: for hints only, never for a decision."""
    try:
        return request.url.hostname or "", request.url.port
    except ValueError:
        return "", None


def foreign_origin(request: Request) -> bool:
    """Whether a browser says this request was started by a page of another origin.

    A client that says nothing is no browser and brings no session somebody could borrow.
    """
    if site := request.headers.get("sec-fetch-site", ""):
        return site not in ("same-origin", "none")
    origin = request.headers.get("origin", "")
    return bool(origin) and urlsplit(origin).netloc != request.headers.get("host", "")


def session_value(user: dict, mailed: bool = False) -> list[str]:
    # A stamp made from the password hash and the number of logouts rides along: a new password
    # or a logout ends every session of that account. It is derived with the secret key, so
    # neither a cookie nor a mailed link shows anything of the hash itself.
    # A mailed link also stands for the address it went to: corrected, the old mail opens nothing.
    text = f"{user['password_hash']}:{user.get('logouts', 0)}" + (f":{user.get('email', '')}" if mailed else "")
    stamp = hmac.new(SECRET_KEY.encode(), text.encode(), "sha256").hexdigest()[:16]
    return [user["username"], stamp]


def signed_user(signer: URLSafeTimedSerializer, value: str | None, users: list[dict], max_age: int, mailed: bool = False) -> dict | None:
    """The account a signed cookie or link stands for, if it is still good for that account."""
    try:
        name, stamp = signer.loads(value or "", max_age=max_age)
    except (BadSignature, ValueError, TypeError):
        return None
    user = find_user(users, name)
    return user if user and hmac.compare_digest(session_value(user, mailed)[1], str(stamp)) else None


def session_user(request: Request, users: list[dict]) -> dict | None:
    return signed_user(SESSIONS, request.cookies.get(SESSION_COOKIE), users, SESSION_SECONDS)


def start_session(response: RedirectResponse, request: Request, user: dict) -> RedirectResponse:
    # SameSite=Lax is what foreign_origin() leans on when a request names no origin at all: a
    # form from elsewhere then comes without this cookie. Loosen it, and that check has a hole.
    response.set_cookie(
        SESSION_COOKIE,
        SESSIONS.dumps(session_value(user)),
        max_age=SESSION_SECONDS,
        httponly=True,
        samesite="lax",
        secure=is_https(request),
    )
    return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    global SETUP_TOKEN
    if not load_users():
        if setup_token_problem():
            # No fallback to a random token: whoever set one cannot read this log.
            SETUP_TOKEN = None
            print(f"Setup is blocked: {setup_token_problem()}", flush=True)
        else:
            SETUP_TOKEN = ENV_SETUP_TOKEN or secrets.token_hex(8)
            # A token somebody chose is not repeated in the log.
            shown = "the value of CADDYMAN_SETUP_TOKEN" if ENV_SETUP_TOKEN else SETUP_TOKEN
            print(f"Setup required. Open http://<host>:{OWN_PORT}/setup\nToken: {shown}", flush=True)
    if not SECRET_KEY_FROM_ENV:
        print("CADDYMAN_SECRET_KEY is not set, using a generated key from the data directory.", flush=True)
    reset_https_only()
    start_watcher()
    yield


app = FastAPI(title="Caddyman", version=VERSION, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")
templates.env.filters["initials"] = initials
templates.env.globals["PERMISSIONS"] = PERMISSIONS
# Defined below, with the settings it reads.
templates.env.globals["time_zone"] = lambda: time_zone().key
# The settings page calls it by name: defined further down, with the rest about Caddy.
templates.env.globals["dns_guides"] = lambda snippet: dns_guides(snippet)


# Open without a login: the root certificate is public by nature, and the people who
# need it are exactly those who have no account here.
PUBLIC_PATHS = {"/trust", "/root-ca.crt"}


# Switches that belong to Caddyman itself, not to the Caddy it manages. "1" or "".
SETTINGS_FILE = DATA_DIR / "settings.json"
SETTING_DEFAULTS = {"public_ca": "1", "login_ca_hint": "1", "require_2fa": ""}
# What is mailed to the accounts that ask for alerts in their profile. "1" or "", the days a number.
ALERT_DEFAULTS = {"alert_reload": "1", "alert_cert": "1", "alert_cert_days": "14", "alert_admin": "1"}
SETTING_DEFAULTS.update(ALERT_DEFAULTS)


def load_settings() -> dict:
    # Up to 0.9.0 the two root CA switches were part of the Caddy settings. What somebody
    # chose there still counts until it is saved here.
    hosts = load_hosts()
    old = {key: hosts[0][key] for key in ("public_ca", "login_ca_hint") if hosts and key in hosts[0]}
    return {**SETTING_DEFAULTS, **old, **read_json(SETTINGS_FILE, {})}


def save_settings(**changes) -> None:
    write_json(SETTINGS_FILE, {**load_settings(), **changes})


def flag(key: str) -> bool:
    return bool(load_settings()[key])


def time_zone() -> ZoneInfo:
    """The zone times are shown in: the one chosen under Settings, else the TZ variable, else UTC."""
    return find_zone(load_settings().get("time_zone")) or TIME_ZONE


def https_only() -> bool:
    """Whether Caddyman refuses plain HTTP. Not one of the defaults: it never travels in a backup."""
    return bool(load_settings().get("https_only"))


def reset_https_only() -> None:
    if RESET_HTTPS_ONLY and https_only():
        save_settings(https_only="")
        print("CADDYMAN_RESET_HTTPS_ONLY is true: plain HTTP is answered again. Set it back to false now.", flush=True)


# The way in: logging in, the second factor and a forgotten password.
LOGIN_PATHS = {"/login", "/login/code", "/forgot", "/reset"}
# The first prefix that fits decides, so the users below /settings come before /settings itself.
AREAS = (
    ("/settings/users", "users"),
    ("/settings/security", "general"),
    ("/settings/general", "general"),
    ("/settings/mail", "smtp"),
    ("/settings/alerts", "alerts"),
    ("/settings", "caddy"),
    ("/hosts", "caddy"),
    ("/routes", "routes"),
    ("/groups", "groups"),
    ("/error-pages", "errors"),
    ("/backup", "backup"),
    ("/logs", "logs"),
    ("/caddyfile", "caddy"),
    ("/ca", "ca"),
)


# Where the right for the area is not enough, and which one it takes on top. The mail server
# carries the reset link of every account; an import writes route files word for word, and a
# download hands them out, with the hashes of their logins.
SECOND_RIGHT = {("POST", "/settings/mail"): "users", ("POST", "/backup/import"): "routes", ("GET", "/backup/download"): "routes"}


# Open to every account. "/settings" only forwards to the first block this account may open.
OPEN_PATHS = {"/", "/status", "/changes", "/settings", "/logout", "/healthz", "/setup"} | LOGIN_PATHS
OPEN_PREFIXES = ("/profile/", "/static/", "/error/")


def needed_permission(path: str) -> str | None:
    """The right a request needs. Decided here by its path, so no endpoint can forget its own check.

    "" for a path that is neither open nor in AREAS: a page added and forgotten there stays shut.
    """
    if path in OPEN_PATHS or path == "/profile" or path.startswith(OPEN_PREFIXES):
        return None
    if path in PUBLIC_PATHS:
        return None if flag("public_ca") else "ca"  # switched off, they are part of the Root CA page
    if re.fullmatch(r"/hosts/[^/]+/push", path):
        return "routes"  # "Reload Caddy" lives under /hosts but is part of working with routes
    return next((right for prefix, right in AREAS if path == prefix or path.startswith(prefix + "/")), "")


@app.middleware("http")
async def require_session(request: Request, call_next):
    # The path the router goes by. request.url is put together from the Host header, which the
    # client writes: "Host: x/login?" would turn every address into /login there.
    path = request.scope["path"]
    OVER_HTTPS.set(is_https(request))
    # Switched on under Settings: nothing but HTTPS. What Caddy fetches itself and the root
    # certificate stay open, or the error pages and the way to trust the CA would be cut off.
    if not is_https(request) and path != "/healthz" and not path.startswith(("/static/", "/error/")) and path not in PUBLIC_PATHS and https_only():
        current = pick_host()
        address = own_route_address(current)[1] if current else ""
        if address:
            return RedirectResponse(address + path, status_code=307)
        return Response("Caddyman only answers over HTTPS. Open it under the name of its route.", status_code=403, media_type="text/plain")
    # A form sent from a page elsewhere would come with the visitor's session. What Caddy passes
    # on to an error page is somebody else's request and changes nothing here.
    if request.method not in ("GET", "HEAD", "OPTIONS") and not path.startswith("/error/"):
        if foreign_origin(request):
            return Response("This request was sent from another site. Open Caddyman and try again from there.", status_code=403, media_type="text/plain")
        # Refused before a byte of it is read. A body that does not say how long it is could be any size.
        length = request.headers.get("content-length", "0")
        if "transfer-encoding" in request.headers or not is_number(length) or int(length) > MAX_BODY_BYTES:
            return Response("This request is larger than anything Caddyman takes.", status_code=413, media_type="text/plain")
    users = load_users()
    me = request.state.me = session_user(request, users)
    request.state.user = me["username"] if me else None
    if path == "/healthz" or path.startswith("/static/"):
        pass
    elif not users:
        if path != "/setup":
            return RedirectResponse("/setup", status_code=303)
    elif path == "/setup":
        return RedirectResponse("/", status_code=303)
    elif not me:
        # An error page is fetched by Caddy on behalf of a visitor, who has no account here.
        if path not in LOGIN_PATHS and not path.startswith("/error/") and not (path in PUBLIC_PATHS and flag("public_ca")):
            return RedirectResponse("/login", status_code=303)
    else:
        CURRENT_USER.set(me["username"])
        right = needed_permission(path)
        if right == "":
            return Response("Not found.", status_code=404, media_type="text/plain")
        if right in me["permissions"]:
            right = SECOND_RIGHT.get((request.method, path), right)
        if right and right not in me["permissions"]:
            return page(request, "forbidden.html", status_code=403, right=PERMISSIONS[right])
        # Where the second factor is required, an account without one gets as far as its profile.
        if not me.get("totp") and path != "/logout" and not path.startswith("/profile") and flag("require_2fa"):
            return RedirectResponse("/profile#two-factor", status_code=303)
    return await call_next(request)


def page(request: Request, template: str, status_code: int = 200, **context):
    flash = None
    if cookie := request.cookies.get(FLASH_COOKIE):
        try:
            flash = FLASHES.loads(cookie, max_age=60)
        except BadSignature:
            pass
    context = {"version": VERSION, "source_url": SOURCE_URL, "flash": flash, **context}
    response = templates.TemplateResponse(request, template, context, status_code=status_code)
    # No page of Caddyman inside a frame: a route next to it could put Disable under a click of its own.
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    if template == "reset.html":
        # The link from the mail is this page's address: it is not to travel on as a Referer.
        response.headers["Referrer-Policy"] = "no-referrer"
    if cookie:
        response.delete_cookie(FLASH_COOKIE)
    return response


def redirect(url: str, kind: str = "", text: str = "") -> RedirectResponse:
    """Redirect after a POST; the message is shown once on the next page."""
    response = RedirectResponse(url, status_code=303)
    if text:
        response.set_cookie(FLASH_COOKIE, FLASHES.dumps([kind, text[:500]]), max_age=60, httponly=True, samesite="lax", secure=OVER_HTTPS.get())
    return response


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


def setup_token_problem() -> str | None:
    if ENV_SETUP_TOKEN and len(ENV_SETUP_TOKEN) < MIN_SETUP_TOKEN_CHARS:
        return (
            f"CADDYMAN_SETUP_TOKEN is too short. Set one with at least {MIN_SETUP_TOKEN_CHARS} characters "
            "and restart the container."
        )
    return None


def setup_page(request: Request, **context):
    context = {"own_token": bool(ENV_SETUP_TOKEN), "blocked": setup_token_problem(), **context}
    return page(request, "setup.html", **context)


@app.get("/setup")
def setup_form(request: Request):
    return setup_page(request)


@app.post("/setup")
def setup_submit(
    request: Request,
    token: str = Form(""),
    username: str = Form(""),
    email: str = Form(""),
    password: str = Form(""),
    repeat: str = Form(""),
):
    global SETUP_TOKEN
    address = client_address(request)
    username, email = username.strip(), email.strip()
    if error := setup_token_problem():
        pass
    elif wait := locked_seconds(address):
        error = f"Too many attempts. Try again in {wait} seconds."
    elif not SETUP_TOKEN or not secrets.compare_digest(token.strip().encode(), SETUP_TOKEN.encode()):
        record_fail(address)
        error = "The token does not match."
    else:
        error = user_problem({"username": username, "email": email}, []) or password_problem(password, repeat)
    if error:
        return setup_page(request, status_code=400, error=error, username=username, email=email)
    # The first account may do everything, including handing out rights to the next ones.
    user = {"username": username, "realname": "", "email": email, "password_hash": hash_password(password), "permissions": list(PERMISSIONS)}
    save_users([user])
    SETUP_TOKEN = None
    return start_session(RedirectResponse("/", status_code=303), request, user)


def login_page(request: Request, **context):
    # The card would lead straight back here if the open page is switched off.
    ca_hint = bool(load_hosts()) and flag("public_ca") and flag("login_ca_hint")
    return page(request, "login.html", ca_hint=ca_hint, mail_ready=mail_ready(), **context)


@app.get("/login")
def login_form(request: Request):
    if request.state.user:
        return RedirectResponse("/", status_code=303)
    return login_page(request)


@app.post("/login")
def login_submit(request: Request, username: str = Form(""), password: str = Form("")):
    address = client_address(request)
    # Counted against the name as well, whether it exists or not: where somebody gets to pick
    # the address a request seems to come from, a new one per attempt is no way around the limit.
    account = f"login:{username.strip().lower()[:64]}"
    if wait := locked_seconds(address, account):
        return login_page(request, status_code=429, error=f"Too many attempts. Try again in {wait} seconds.")
    user = find_user(load_users(), username.strip())
    # A hash is always checked, so a wrong username takes as long as a wrong password.
    password_ok = check_password(password, user["password_hash"] if user else DUMMY_HASH)
    if not (user and password_ok):
        record_fail(address, account)
        return login_page(request, status_code=401, error="Wrong username or password.", username=username)
    if user.get("totp"):
        # Half way in: a short-lived cookie remembers who passed the password, nothing more.
        response = RedirectResponse("/login/code", status_code=303)
        secure = is_https(request)
        response.set_cookie(PENDING_COOKIE, PENDING.dumps(session_value(user)), max_age=PENDING_SECONDS, httponly=True, samesite="lax", secure=secure)
        return response
    return start_session(RedirectResponse("/", status_code=303), request, user)


PENDING_COOKIE = "caddyman_2fa"
PENDING_SECONDS = 300
PENDING = URLSafeTimedSerializer(SECRET_KEY, salt="2fa")
TOTP_SECONDS = 30
# Everything a second factor leaves on an account.
TOTP_KEYS = ("totp", "totp_pending", "totp_last", "recovery")
RECOVERY_CODES = 8
# How long a started setup waits for its first code. Later the password is asked for again.
TOTP_SETUP_SECONDS = 900


def totp_code(secret: str, step: int) -> str:
    """RFC 6238 with the defaults every authenticator app uses: SHA-1, six digits, 30 seconds."""
    digest = hmac.new(base64.b32decode(secret), struct.pack(">Q", step), "sha1").digest()
    offset = digest[-1] & 15
    number = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{number % 1_000_000:06d}"


def totp_step(secret: str, code: str) -> int | None:
    """The time step a code belongs to, or None. One step of clock drift either way is accepted."""
    now = int(time.time()) // TOTP_SECONDS
    typed = re.sub(r"\s", "", code).encode()
    return next((step for step in (now, now - 1, now + 1) if secrets.compare_digest(totp_code(secret, step).encode(), typed)), None)


def totp_secret(user: dict, key: str) -> str | None:
    try:
        # The sealed text carries the time it was sealed: a setup left lying around expires.
        return unseal(user.get(key, ""), TOTP_SETUP_SECONDS if key == "totp_pending" else None)
    except (InvalidToken, ValueError):
        # Not set, or encrypted with another secret key. A recovery code or a reset by an admin gets around that.
        return None


def recovery_digest(code: str, keyed: bool = True) -> str:
    """What is stored of a recovery code. Keyed with the secret key, so a copy of the accounts alone
    is not enough to guess the codes; versions up to 0.16 stored the plain SHA-256."""
    plain = re.sub(r"[^0-9a-z]", "", code.lower()).encode()
    return hmac.new(f"recovery:{SECRET_KEY}".encode(), plain, "sha256").hexdigest() if keyed else hashlib.sha256(plain).hexdigest()


def second_factor_ok(user: dict, code: str) -> bool:
    """Check an app code or a recovery code. Either one works exactly once."""
    secret = totp_secret(user, "totp")
    step = totp_step(secret, code) if secret else None
    digests = (recovery_digest(code), recovery_digest(code, keyed=False))
    # Looked at and used up under one lock: the same code sent twice at once passes once.
    with USERS_LOCK:
        users = load_users()
        account = find_user(users, user["username"])
        if account is None:
            return False
        if step is not None and step > account.get("totp_last", 0):
            account["totp_last"] = step
        elif digest := next((digest for digest in digests if digest in account.get("recovery", [])), None):
            account["recovery"].remove(digest)
        else:
            return False
        save_users(users)
        return True


def pending_user(request: Request) -> dict | None:
    return signed_user(PENDING, request.cookies.get(PENDING_COOKIE), load_users(), PENDING_SECONDS)


@app.get("/login/code")
def login_code_form(request: Request):
    if request.state.user or not pending_user(request):
        return RedirectResponse("/login", status_code=303)
    return page(request, "login_code.html")


@app.post("/login/code")
def login_code_submit(request: Request, code: str = Form("")):
    address = client_address(request)
    user = pending_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    # Counted against the account as well: the password is known at this point, so another
    # address is no way around the limit.
    account = f"2fa:{user['username']}"
    if wait := locked_seconds(address, account):
        return page(request, "login_code.html", status_code=429, error=f"Too many attempts. Try again in {wait} seconds.")
    if not second_factor_ok(user, code):
        record_fail(address, account)
        return page(request, "login_code.html", status_code=401, error="This code is not valid.")
    LOCK_ROUNDS.pop(account, None)
    response = start_session(RedirectResponse("/", status_code=303), request, user)
    response.delete_cookie(PENDING_COOKIE)
    return response


@app.post("/logout")
def logout(request: Request):
    # Counted on the account: the cookie is worth nothing afterwards, wherever a copy of it lies.
    if me := request.state.me:
        update_user(me["username"], logouts=one_more_logout)
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response


# Mail is only for a forgotten password. It needs the public address as well: taking it from
# the request would let anyone have a reset link mailed that points at a server of theirs.
MAIL_FILE = DATA_DIR / "mail.json"
MAIL_DEFAULTS = {"public_url": "", "host": "", "port": "587", "user": "", "sender": "", "security": "starttls"}
MAIL_SECURITY = {"starttls": "STARTTLS (port 587)", "ssl": "SSL/TLS (port 465)", "none": "None - unencrypted"}
RESET_SECONDS = 3600
RESETS = URLSafeTimedSerializer(SECRET_KEY, salt="reset")
# An invitation is the same kind of link for an account that has no password yet. It is read
# later than a reset somebody just asked for, so it lasts a day.
INVITE_SECONDS = 24 * 3600
INVITES = URLSafeTimedSerializer(SECRET_KEY, salt="invite")


def load_mail() -> dict:
    return {**MAIL_DEFAULTS, **read_json(MAIL_FILE, {})}


def mail_ready(mail: dict | None = None) -> bool:
    mail = mail or load_mail()
    return bool(mail["host"] and mail["sender"] and mail["public_url"])


def mail_problem(mail: dict) -> str | None:
    if not mail["host"]:
        return None  # an empty server switches mail off, the rest does not matter then
    if not mail["host"].isprintable() or " " in mail["host"] or len(mail["host"]) > 253:
        return "The mail server has to be a hostname or an address."
    if not is_number(mail["port"]) or not 0 < int(mail["port"]) < 65536:
        return "The port has to be a number between 1 and 65535."
    if not EMAIL_RE.match(mail["sender"]):
        return "The sender has to be an email address."
    if mail["security"] not in MAIL_SECURITY:
        return "Unknown encryption."
    if not is_http_url(mail["public_url"]) or urlsplit(mail["public_url"]).path:
        return "The address of Caddyman has to look like https://caddyman.home.example."
    return None


def ca_problem(pem: str) -> str | None:
    """What is wrong with a CA certificate somebody pasted into a form."""
    try:
        ssl.create_default_context().load_verify_locations(cadata=pem)
    except (ssl.SSLError, ValueError):
        return "The CA certificate has to be a certificate as PEM text, from BEGIN CERTIFICATE to END CERTIFICATE."
    return None


def check_codes(pem: str) -> str:
    """The check codes of every certificate in a PEM text, as the Root CA page gives them."""
    return ", ".join(item["check_code"] for item in fingerprints(pem))


def send_mail(to: str, subject: str, body: str) -> str | None:
    """Send one plain-text mail. Returns the error, or None on success."""
    mail = load_mail()
    message = EmailMessage()
    message["From"], message["To"], message["Subject"] = mail["sender"], to, subject
    message.set_content(body)
    # The server's certificate is verified against the public CAs, and against the CA from the
    # mail settings for a server whose certificate comes from a private one.
    context = ssl.create_default_context()
    try:
        password = unseal(mail["password_enc"]) if mail.get("password_enc") else ""
        if mail["security"] == "ssl":
            server = smtplib.SMTP_SSL(mail["host"], int(mail["port"]), timeout=10, context=context)
        else:
            server = smtplib.SMTP(mail["host"], int(mail["port"]), timeout=10)
        with server:
            if mail["security"] == "starttls":
                server.starttls(context=context)
            if mail["user"]:
                server.login(mail["user"], password)
            server.send_message(message)
    except InvalidToken:
        return "The stored mail password was encrypted with a different CADDYMAN_SECRET_KEY. Enter it again."
    except (OSError, smtplib.SMTPException) as error:
        return said(error)
    return None


def send_reset_mail(user: dict) -> None:
    link = f"{load_mail()['public_url']}/reset?token={RESETS.dumps(session_value(user, mailed=True))}"
    body = (
        f"Somebody asked for a new password for the Caddyman account {user['username']}.\n\n"
        f"Set one here, within the next hour:\n{link}\n\n"
        "If that was not you, ignore this mail. Nothing changes until the link is used.\n"
    )
    if error := send_mail(user["email"], "Caddyman: set a new password", body):
        print(f"Reset mail for {user['username']} was not sent: {error}", flush=True)


def send_invite_mail(user: dict) -> str | None:
    """Mail a new account the link to set its first password. Returns the error, or None on success."""
    link = f"{load_mail()['public_url']}/reset?token={INVITES.dumps(session_value(user, mailed=True))}"
    body = (
        f"An account was created for you in Caddyman. Your username is {user['username']}.\n\n"
        f"Set your password here, within one day:\n{link}\n\n"
        "The link works once.\n"
    )
    return send_mail(user["email"], "Caddyman: your account", body)


def link_user(token: str, users: list[dict] | None = None) -> dict | None:
    """The account a link from a mail stands for: a reset for an hour, an invitation for a day."""
    users = load_users() if users is None else users
    return signed_user(RESETS, token, users, RESET_SECONDS, mailed=True) or signed_user(INVITES, token, users, INVITE_SECONDS, mailed=True)


@app.get("/forgot")
def forgot_form(request: Request):
    if not mail_ready():
        return Response(status_code=404)
    return page(request, "forgot.html")


@app.post("/forgot")
def forgot_submit(request: Request, account: str = Form("")):
    if not mail_ready():
        return Response(status_code=404)
    address = client_address(request)
    if wait := locked_seconds(address):
        return page(request, "forgot.html", status_code=429, error=f"Too many attempts. Try again in {wait} seconds.")
    # Every request counts, so nobody can have mails sent in a loop.
    record_fail(address)
    wanted = account.strip().lower()
    for user in load_users():
        if wanted and user.get("email") and wanted in (user["username"].lower(), user["email"].lower()):
            # In the background: the answer must not take longer for an account that exists.
            threading.Thread(target=send_reset_mail, args=(user,), daemon=True).start()
            break
    return page(request, "forgot.html", sent=True)


@app.get("/reset")
def reset_form(request: Request, token: str = ""):
    valid = link_user(token) is not None
    return page(request, "reset.html", status_code=200 if valid else 400, token=token, valid=valid, mail_ready=mail_ready())


@app.post("/reset")
def reset_submit(request: Request, token: str = Form(""), password: str = Form(""), repeat: str = Form("")):
    user = link_user(token)
    if user is None:
        return page(request, "reset.html", status_code=400, token=token, valid=False, mail_ready=mail_ready())
    if error := password_problem(password, repeat):
        return page(request, "reset.html", status_code=400, token=token, valid=True, error=error)
    hashed = hash_password(password)
    # Looked at again and used up under one lock: the same link sent twice at once works once.
    # It carries a stamp of the old hash, so it stops working with this very change.
    with USERS_LOCK:
        users = load_users()
        if user := link_user(token, users):
            user["password_hash"] = hashed
            user.pop("invited", None)
            save_users(users)
    if user is None:
        return page(request, "reset.html", status_code=400, token=token, valid=False, mail_ready=mail_ready())
    return redirect("/login", "ok", "The password is set. Log in with it.")


def profile_page(request: Request, **context):
    me = find_user(load_users(), request.state.user)
    secret = totp_secret(me, "totp_pending") if not me.get("totp") else None
    if secret:
        uri = f"otpauth://totp/Caddyman:{quote(me['username'])}?secret={secret}&issuer=Caddyman"
        context.update(pending_secret=secret, qr=segno.make(uri, error="m").svg_inline(scale=5, border=2, dark="#000", light="#fff"))
    return page(request, "profile.html", me=me, required=flag("require_2fa") and not me.get("totp"), **context)


@app.get("/profile")
def profile(request: Request):
    return profile_page(request)


@app.post("/profile")
def profile_save(request: Request, realname: str = Form(""), email: str = Form(""), current: str = Form(""), alerts: str = Form("")):
    users, me = load_users(), request.state.me
    fields = {"realname": realname.strip(), "email": email.strip()}
    others = [user for user in users if user["username"] != request.state.user]
    if error := user_problem({"username": request.state.user, **fields}, others):
        return profile_page(request, status_code=400, error=error, form=fields)
    # The reset links go to this address, so changing it takes the password, like changing that does.
    if fields["email"] != me.get("email", "") and (error := own_password_problem(me, current, "Changing the email address takes your current password.")):
        return profile_page(request, status_code=400, error=error, form=fields)
    update_user(request.state.user, **fields, alerts=True if alerts else None)
    return redirect("/profile", "ok", "Your profile is saved.")


@app.post("/profile/theme")
def profile_theme(request: Request, back: str = Form("/")):
    """The button in the bar: switch between the dark and the light look and stay on the page."""
    # Dark is the look Caddyman comes in; only the wish for the light one is stored, per account.
    update_user(request.state.user, theme=None if request.state.me.get("theme") == "light" else "light")
    # Only ever a path of this site: the value comes back from the browser.
    local = back.startswith("/") and not back.startswith("//") and "\\" not in back and back.isprintable()
    return RedirectResponse(back if local else "/", status_code=303)


@app.post("/profile/password")
def profile_password(request: Request, current: str = Form(""), password: str = Form(""), repeat: str = Form("")):
    me = request.state.me
    if error := own_password_problem(me, current):
        return profile_page(request, status_code=400, password_error=error)
    if error := password_problem(password, repeat):
        return profile_page(request, status_code=400, password_error=error)
    update_user(me["username"], password_hash=hash_password(password))
    # Every other session of this account ends with the change; this one continues.
    changed = find_user(load_users(), me["username"])
    return start_session(redirect("/profile", "ok", "The password is changed."), request, changed)


@app.post("/profile/2fa/start")
def profile_2fa_start(request: Request, current: str = Form("")):
    me = request.state.me
    # Like switching it off: a session alone does not decide about the second factor.
    if me.get("totp"):
        return redirect("/profile", "error", "Two-factor login is on already. Switch it off first to set it up anew.")
    if error := own_password_problem(me, current, "The password is wrong."):
        return profile_page(request, status_code=400, totp_error=error)
    secret = base64.b32encode(secrets.token_bytes(20)).decode()
    update_user(request.state.user, totp_pending=seal(secret))
    return RedirectResponse("/profile#two-factor", status_code=303)


@app.post("/profile/2fa/confirm")
def profile_2fa_confirm(request: Request, code: str = Form("")):
    me = find_user(load_users(), request.state.user)
    # A factor that is on is never replaced from here, only switched off with the password.
    secret = totp_secret(me, "totp_pending") if not me.get("totp") else None
    step = totp_step(secret, code) if secret else None
    if step is None:
        return profile_page(request, status_code=400, totp_error="This code does not fit. Check the clock of your phone and try the next one.")
    codes = [secrets.token_hex(5) for _ in range(RECOVERY_CODES)]
    # Every session opened with the password alone ends here; this one continues.
    fields = {"totp": me["totp_pending"], "totp_pending": None, "totp_last": step, "logouts": one_more_logout}
    update_user(me["username"], recovery=[recovery_digest(code) for code in codes], **fields)
    # Shown this once and never again: only their hashes are kept.
    response = profile_page(request, recovery_codes=[f"{code[:5]}-{code[5:]}" for code in codes])
    return start_session(response, request, find_user(load_users(), me["username"]))


@app.post("/profile/2fa/disable")
def profile_2fa_disable(request: Request, current: str = Form("")):
    me = request.state.me
    if error := own_password_problem(me, current, "The password is wrong."):
        return profile_page(request, status_code=400, totp_error=error)
    update_user(me["username"], **{key: None for key in TOTP_KEYS if key in me})
    return redirect("/profile", "ok", "Two-factor login is switched off.")


@app.get("/settings")
def settings_home(request: Request):
    rights = request.state.me["permissions"]
    for right, block in (("caddy", "/settings/caddy"), ("general", "/settings/security"), ("smtp", "/settings/mail"), ("alerts", "/settings/alerts"), ("users", "/settings/users")):
        if right in rights:
            return RedirectResponse(block, status_code=303)
    return page(request, "forbidden.html", status_code=403, right=PERMISSIONS["caddy"])


@app.get("/settings/caddy")
def settings_caddy():
    return RedirectResponse(host_settings_url(), status_code=303)


@app.get("/settings/alerts")
def settings_alerts(request: Request):
    receivers = [user["username"] for user in load_users() if user.get("alerts") and user.get("email")]
    return page(request, "settings_alerts.html", settings=load_settings(), receivers=receivers, mail=mail_ready())


@app.post("/settings/alerts")
async def settings_alerts_save(request: Request):
    form = await request.form()
    days = str(form.get("alert_cert_days", "")).strip()
    if not is_number(days) or not 1 <= int(days) <= 90:
        return redirect("/settings/alerts", "error", "The days before a certificate ends are a number from 1 to 90.")
    save_settings(**{key: "1" if form.get(key) else "" for key in ALERT_DEFAULTS if key != "alert_cert_days"}, alert_cert_days=days)
    return redirect("/settings/alerts", "ok", "Saved.")


@app.get("/settings/security")
def settings_security(request: Request):
    without = [user["username"] for user in load_users() if not user.get("totp")]
    settings = load_settings()
    zones = {"chosen": settings.get("time_zone", ""), "fallback": TIME_ZONE.key, "zones": zone_names()}
    return page(request, "settings_security.html", settings=settings, without=without, **zones)


@app.post("/settings/security")
def settings_security_save(
    request: Request, require_2fa: str = Form(""), public_ca: str = Form(""), login_ca_hint: str = Form(""), https_only_on: str = Form("")
):
    # Switched on over plain HTTP, the answer to this very request would already be refused.
    if https_only_on and not https_only() and not is_https(request):
        return redirect("/settings/security", "error", "Open Caddyman over HTTPS first, through its own route, and switch it on from there.")
    # Checkboxes in one form: one that is not sent was unticked.
    switched_on = https_only_on and not https_only()
    save_settings(require_2fa=require_2fa and "1", public_ca=public_ca and "1", login_ca_hint=login_ca_hint and "1", https_only=https_only_on and "1")
    if not switched_on:
        return redirect("/settings/security", "ok", "Saved.")
    # A cookie set over plain HTTP may have been read on the way. Every session ends; this one starts over, over HTTPS.
    with USERS_LOCK:
        users = load_users()
        for user in users:
            user["logouts"] = one_more_logout(user)
        save_users(users)
    response = redirect("/settings/security", "ok", "Saved. Every other session has ended.")
    return start_session(response, request, find_user(users, request.state.user))


@app.get("/settings/general")
def settings_general():
    # The block is called General; its page kept the address it had as Security.
    return RedirectResponse("/settings/security", status_code=303)


@app.post("/settings/general")
def settings_general_save(zone: str = Form("")):
    zone = zone.strip()
    if zone and not find_zone(zone):
        return redirect("/settings/security", "error", "Unknown time zone. Pick one from the list, like Europe/Berlin.")
    save_settings(time_zone=zone)
    return redirect("/settings/security", "ok", "Saved.")


@app.get("/settings/users")
def users_list(request: Request):
    return page(request, "users.html", users=load_users())


@app.get("/settings/mail")
def mail_form(request: Request):
    mail = load_mail()
    return page(request, "mail_form.html", mail=mail, securities=MAIL_SECURITY)


@app.post("/settings/mail")
async def mail_save(request: Request):
    form = await request.form()
    stored = load_mail()
    mail = {key: str(form.get(key, "")).strip() for key in MAIL_DEFAULTS}
    mail["public_url"] = mail["public_url"].rstrip("/")
    if error := mail_problem(mail):
        return page(request, "mail_form.html", status_code=400, error=error, mail=mail, securities=MAIL_SECURITY)
    if password := str(form.get("password", "")):
        mail["password_enc"] = seal(password)
    elif mail["user"] and all(mail[key] == stored[key] for key in ("user", "host", "port", "security")) and stored.get("password_enc"):
        # An empty field keeps the password of the same login at the same server, sent the same way.
        mail["password_enc"] = stored["password_enc"]
    write_json(MAIL_FILE, mail)
    if not mail["host"]:
        return redirect("/settings/mail", "ok", 'Mail is switched off. The login page no longer offers "Forgot password?".')
    return redirect("/settings/mail", "ok", "The mail settings are saved. Send a test mail to check them.")


@app.post("/settings/mail/test")
def users_test_mail(request: Request):
    me, mail = request.state.me, load_mail()
    if not mail_ready(mail):
        return redirect("/settings/mail", "error", "Mail is not set up yet.")
    if not me.get("email"):
        return redirect("/settings/mail", "error", "Your own profile has no email address to send the test to.")
    if error := send_mail(me["email"], "Caddyman: test mail", f"Mail from Caddyman works. Links will point at {mail['public_url']}\n"):
        return redirect("/settings/mail", "error", f"The mail was not sent: {error}")
    return redirect("/settings/mail", "ok", f"A test mail is on its way to {me['email']}.")


@app.get("/settings/users/new")
def user_new(request: Request):
    return page(request, "user_form.html", user={"permissions": []}, new=True, invite=mail_ready())


@app.get("/settings/users/{name:path}/edit")
def user_edit(request: Request, name: str):
    user = find_user(load_users(), name)
    if user is None:
        return redirect("/settings/users", "error", "This user does not exist.")
    return page(request, "user_form.html", user=user)


@app.post("/settings/users/new")
@app.post("/settings/users/{name:path}/edit")
async def user_save(request: Request, name: str | None = None):
    form = await request.form()
    with USERS_LOCK:
        users = load_users()
        existing = find_user(users, name) if name is not None else None
        if name is not None and existing is None:
            return redirect("/settings/users", "error", "This user does not exist.")
        user = {
            **(existing or {}),
            "username": existing["username"] if existing else str(form.get("username", "")).strip(),
            "realname": str(form.get("realname", "")).strip(),
            "email": str(form.get("email", "")).strip(),
            "permissions": [right for right in PERMISSIONS if form.get(f"right_{right}")],
        }
        password, repeat = str(form.get("password", "")), str(form.get("repeat", ""))
        # A new account without a password is invited by mail and sets its own.
        invite = not existing and not password and not repeat and mail_ready()
        error = user_problem(user, [other for other in users if other is not existing])
        if not error and invite and not user["email"]:
            error = "Enter a password, or an email address to send the invitation to."
        if not error and not invite and (password or not existing):
            error = password_problem(password, repeat)
        if not error and existing and existing["username"] == request.state.user and "users" not in user["permissions"]:
            # Whoever manages users keeps that right for themselves, so there is always one left.
            error = "You cannot take the right to manage users away from yourself."
        # Looked at under the lock: two accounts that take the right from each other at the
        # same moment would otherwise both pass and leave nobody.
        if not error and existing and not any("users" in (user if other is existing else other)["permissions"] for other in users):
            error = "One account has to keep the right to manage users."
        if error:
            return page(request, "user_form.html", status_code=400, error=error, user=user, new=not existing, invite=mail_ready())
        if password:
            user["password_hash"] = hash_password(password)
            user.pop("invited", None)
        elif invite:
            # Nobody knows this one. The link in the mail is the only way in until a password is set.
            user["password_hash"] = hash_password(secrets.token_urlsafe(32))
            # Shown in the list until the account has a password of its own.
            user["invited"] = True
        if existing and form.get("reset_totp"):
            for key in TOTP_KEYS:
                user.pop(key, None)
            # Whatever sessions the account has were opened with the factor that is gone now.
            user["logouts"] = user.get("logouts", 0) + 1
        save_users([user if other is existing else other for other in users] if existing else [*users, user])
    if existing and existing["username"] == request.state.user and (password or form.get("reset_totp")):
        return start_session(redirect("/settings/users", "ok", f"{user['username']} is saved."), request, user)
    if invite:
        if error := send_invite_mail(user):
            return redirect(
                "/settings/users",
                "warn",
                f"{user['username']} is created, but the invitation was not sent: {error} "
                'Set a password under "Edit", or let them use "Forgot password?" once mail works.',
            )
        return redirect("/settings/users", "ok", f"{user['username']} is created. The invitation is on its way to {user['email']}.")
    return redirect("/settings/users", "ok", f"{user['username']} is saved.")


@app.post("/settings/users/{name:path}/invite")
def user_invite_again(name: str):
    user = find_user(load_users(), name)
    if not user or not user.get("invited"):
        return redirect("/settings/users", "error", "This account is not waiting for an invitation.")
    if not mail_ready() or not user.get("email"):
        return redirect("/settings/users", "error", "The invitation needs mail to be set up and an email address on the account.")
    if error := send_invite_mail(user):
        return redirect("/settings/users", "error", f"The invitation was not sent: {error}")
    return redirect("/settings/users", "ok", f"A new invitation is on its way to {user['email']}.")


@app.post("/settings/users/{name:path}/delete")
def user_delete(request: Request, name: str):
    if name == request.state.user:
        return redirect("/settings/users", "error", "You cannot delete your own account.")
    with USERS_LOCK:
        left = [user for user in load_users() if user["username"] != name]
        # Under the lock, like in user_save: two accounts deleting each other at once leave one.
        if not any("users" in user["permissions"] for user in left):
            return redirect("/settings/users", "error", "One account has to keep the right to manage users.")
        save_users(left)
    return redirect("/settings/users", "ok", f"{name} is deleted.")


HOST_DEFAULTS = {
    "admin_url": "http://caddy:2020",
    "caddyfile": "/etc/caddy/Caddyfile",
    "sites_dir": "/etc/caddy/sites",
    "tls_snippet": "",
    "sso_snippet": "",
    "dns_snippet": "",
    "root_ca_url": "",
    "domain_suffix": "",
}
HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9-]+)*\Z")
SNIPPET_RE = re.compile(r"^[A-Za-z0-9_-]+\Z")
# One DNS snippet per DNS provider, written into the one setting separated by spaces. The first is the default.
MAX_DNS_SNIPPETS = 5


def dns_snippets(host: dict) -> list[str]:
    return host.get("dns_snippet", "").split()
ADMIN_TIMEOUT = 5
# The recommended way to reach the admin API: it stays on localhost, behind a site that asks for a login.
ADMIN_SITE_SNIPPET = (
    ":2020 {\n\tbasic_auth {\n\t\tcaddyman <hash>\n\t}\n"
    "\treverse_proxy localhost:2019 {\n\t\theader_up Host {upstream_hostport}\n\t}\n}"
)


STORAGES = ("mounted", "managed")


def managed_dir(host_id: str) -> Path:
    return DATA_DIR / "hosts" / host_id


def with_paths(host: dict) -> dict:
    """A managed host keeps its base Caddyfile and routes in the data directory.

    Setting the two paths here lets everything else treat both layouts alike.
    """
    if host.get("storage") == "managed":
        host["caddyfile"] = str(managed_dir(host["id"]) / "Caddyfile")
        host["sites_dir"] = str(managed_dir(host["id"]) / "sites")
    return host


def load_hosts() -> list[dict]:
    # The defaults fill in what a file from an older version does not know yet.
    return [with_paths({**HOST_DEFAULTS, **host}) for host in read_json(HOSTS_FILE, [])]


def admin_auth(host: dict) -> tuple[str, str] | None:
    """Login for an admin API that sits behind basic auth. None when there is none to send."""
    if not host.get("admin_user"):
        return None
    try:
        return host["admin_user"], unseal(host.get("admin_password_enc", ""))
    except (InvalidToken, ValueError):
        # Encrypted with another secret key. The status page says so.
        return None


@lru_cache(maxsize=4)
def trust_context(pem: str) -> ssl.SSLContext:
    context = httpx.create_ssl_context()  # the public CAs
    context.load_verify_locations(cadata=pem)
    return context


def admin_verify(host: dict) -> ssl.SSLContext | bool:
    """How the certificate of an https admin API is checked: the public CAs, plus the CA remembered for this host."""
    return trust_context(host["admin_ca"]) if host.get("admin_ca") else True


def remember_admin_ca(host: dict, previous: str = "") -> str:
    """The CA certificates to trust for an https admin API, fetched when the settings are saved.

    A private CA is the normal case here, and the container does not know it. This is trust on
    first use: whoever sits on the wire at the moment of saving could hand in a CA of their
    own. The status page shows the check code of what was remembered, to compare with the
    Root CA page. Pasting the CA into the settings closes that gap: then nothing is fetched.
    """
    if not host["admin_url"].startswith("https://"):
        return ""
    found = []
    # The own CA if one is named, and Caddy's internal one: the admin site may use either.
    for source in dict.fromkeys((host["root_ca_url"], "")):
        try:
            pem = fetch_root_ca({**host, "root_ca_url": source}, first=True)[0]
            fingerprints(pem)
            found.append(pem)
        except ValueError:
            pass
    return "".join(found) or previous


def save_hosts(hosts: list[dict]) -> None:
    write_json(HOSTS_FILE, hosts)
    CADDY_ADDRESSES["until"] = 0.0  # the admin URL may have changed: look its addresses up again
    PROBE_CACHE.clear()  # and what the status page found was about the settings before
    ROOT_CA_CACHE.clear()  # like the certificate the open page hands out


def is_http_url(value: str) -> bool:
    try:
        parts = urlsplit(value)
        return parts.scheme in ("http", "https") and bool(parts.hostname) and not parts.username
    except ValueError:
        return False


def is_clean_path(value: str) -> bool:
    return value.startswith("/") and ".." not in value.split("/") and value.isprintable()


def is_own_ground(value: str) -> bool:
    """Whether a path leads to where Caddyman keeps its own things: the data directory, /proc and the logs.

    The base Caddyfile travels in the backup and to Caddy. Pointed at the secret key, the
    accounts or a log, it would carry those along, past the right that guards them.
    """
    path = Path(value).resolve()
    return any(path.is_relative_to(ground) for ground in (DATA_DIR.resolve(), Path("/proc"), LOG_DIR.resolve()))


def host_problem(host: dict) -> str | None:
    if not is_http_url(host["admin_url"]) or urlsplit(host["admin_url"]).path:
        return "The admin API has to look like http://caddy:2020."
    if host.get("storage") != "managed" and not (is_clean_path(host["caddyfile"]) and is_clean_path(host["sites_dir"])):
        return "Caddyfile and sites directory have to be absolute paths without '..'."
    if host.get("storage") != "managed" and (is_own_ground(host["caddyfile"]) or is_own_ground(host["sites_dir"])):
        return "Caddyfile and sites directory have to be those of Caddy, not a place in Caddyman's own data or in the log directory."
    if host.get("admin_user") and not AUTH_USER_RE.match(host["admin_user"]):
        return "The admin API username may only contain letters, digits, '.', '_', '@' and '-'."
    snippets = [host[key] for key in ("tls_snippet", "sso_snippet") if host[key]] + dns_snippets(host)
    if not all(map(SNIPPET_RE.match, snippets)):
        return "A snippet name may only contain letters, digits, '-' and '_'."
    if len(dns_snippets(host)) > MAX_DNS_SNIPPETS:
        return f"Up to {MAX_DNS_SNIPPETS} DNS snippets, one per DNS provider."
    if len(set(snippets)) < len(snippets):
        return "The TLS, SSO and DNS snippets have to be different snippets."
    if host["root_ca_url"] and not is_http_url(host["root_ca_url"]):
        return "The root CA source has to be an http or https URL."
    return None


def preflight(host: dict) -> list[dict]:
    """Check what a host needs before routes can be written. Reads only, writes nothing."""
    checks = []

    def add(label: str, ok, detail: str = "", hint: str = "", block: str = "") -> None:
        checks.append({"label": label, "ok": bool(ok), "detail": detail, "hint": hint, "block": block})

    caddyfile, sites, snippet = host["caddyfile"], host["sites_dir"], host["tls_snippet"]
    managed = host.get("storage") == "managed"
    try:
        text = Path(caddyfile).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        text = None
        if managed:
            add("Base Caddyfile is stored", False, str(error), "Edit this host and paste the base Caddyfile.")
        else:
            add(
                "Base Caddyfile is readable",
                False,
                str(error),
                "Mount Caddy's Caddyfile into this container, at the path Caddy uses. In this tool's compose file:",
                f"    volumes:\n      - /opt/caddy/Caddyfile:{caddyfile}:ro",
            )
    else:
        add("Base Caddyfile is stored" if managed else "Base Caddyfile is readable", True, caddyfile)

    if text is not None:
        import_line = f"import {sites}/*.caddy"
        imported = None if managed else re.search(rf"^\s*{re.escape(import_line)}\s*$", text, re.MULTILINE)
        if managed:
            file_import = re.search(r"^\s*import\s+\S*[/*]\S*\s*$", text, re.MULTILINE)
            add(
                "Base Caddyfile imports no files",
                not file_import,
                file_import.group(0).strip() if file_import else "",
                'With "Network only" the routes are sent inline. Remove this line from the base Caddyfile:',
                file_import.group(0).strip() if file_import else "",
            )
        else:
            add(
                "Base Caddyfile imports the sites directory",
                imported,
                import_line,
                "Add this line at the end of the base Caddyfile:",
                import_line,
            )
        if snippet:
            add(
                f"TLS snippet '{snippet}' exists",
                snippet_exists(text, snippet),
                "",
                "Add the snippet to the base Caddyfile, with the ACME directory of your CA:",
                f"({snippet}) {{\n\ttls {{\n\t\tca https://ca.example/acme/acme/directory\n"
                "\t\tca_root /etc/caddy/root_ca.crt\n\t}\n}",
            )
            # Only next to Caddy: from another machine this container may not see what Caddy sees,
            # and a red mark that can be wrong is worse than none.
            if ca_url := "" if managed else acme_ca_url(text, snippet):
                try:
                    # Not verified: the certificate comes from the very CA that is being asked.
                    answer = httpx.get(ca_url, timeout=REACH_TIMEOUT, verify=False)
                    ca_ok, detail = answer.status_code == 200, f"HTTP {answer.status_code}"
                except httpx.HTTPError as error:
                    ca_ok, detail = False, said(error)
                add(
                    "ACME CA answers",
                    ca_ok,
                    f"{ca_url} - {detail}",
                    "Without the CA, Caddy can neither issue nor renew certificates. Asked from the Caddyman "
                    "container: if only Caddy can resolve that name, all is well.",
                    "",
                )
        if not snippet:
            lost = [path.stem for path in sorted(Path(sites).glob("*.caddy")) if lost_tls_snippet(host, path.read_text(encoding="utf-8", errors="replace"))]
            if lost:
                add(
                    "Routes find their TLS snippet",
                    False,
                    ", ".join(lost),
                    "These routes were made with Own ACME CA. Set the TLS snippet under Settings, Caddy again, or adopt them with the snippet mode.",
                )
        for dns in dns_snippets(host):
            add(
                f"DNS snippet '{dns}' exists",
                snippet_exists(text, dns),
                "",
                "Add the snippet to the base Caddyfile. This one is for Cloudflare; the Caddy settings show other providers:",
                f"({dns}) {{\n\ttls {{\n\t\tdns cloudflare {{env.CLOUDFLARE_API_TOKEN}}\n\t}}\n}}",
            )
        if sso := host["sso_snippet"]:
            add(
                f"SSO snippet '{sso}' exists",
                snippet_exists(text, sso),
                "",
                "Add the snippet to the base Caddyfile. This one is for Authelia; other login services document their own:",
                f"({sso}) {{\n\tforward_auth authelia:9091 {{\n\t\turi /api/authz/forward-auth\n"
                "\t\tcopy_headers Remote-User Remote-Groups Remote-Email Remote-Name\n\t}\n}",
            )
        # Allowed networks go by client_ip, and that follows X-Forwarded-For from every proxy Caddy trusts.
        # With a wide trust, anyone in that range names their own address.
        wide = re.search(r"^\s*trusted_proxies\s+static\s+.*?(0\.0\.0\.0/0|::/0|private_ranges).*$", text, re.MULTILINE)
        if any(path.read_text(encoding="utf-8", errors="replace").find("not client_ip ") > 0 for path in Path(sites).glob("*.caddy")):
            add(
                "Allowed networks see the real visitor",
                not wide,
                wide.group(0).strip() if wide else "",
                "With this line, a client in that range can claim any address and get past Allowed networks. Trust only the proxies in front of Caddy.",
            )
        # Caddy reads from top to bottom: a snippet below the import is unknown to the routes
        # and every route that names it is rejected. Sent inline, the routes always come last.
        for name in filter(None, dict.fromkeys((snippet, *dns_snippets(host), host["sso_snippet"]))):
            found = re.search(rf"^\({re.escape(name)}\)\s*\{{", text, re.MULTILINE)
            if imported and found:
                add(
                    f"Snippet '{name}' stands above the import of the routes",
                    found.start() < imported.start(),
                    "",
                    "Move the snippet above this line in the base Caddyfile. A route cannot use one that comes after it:",
                    import_line,
                )

    if host.get("admin_user"):
        add(
            "Admin API password is readable",
            admin_auth(host) is not None,
            "",
            "The stored password was encrypted with a different CADDYMAN_SECRET_KEY. Edit this host and enter it again.",
        )
    running = None
    try:
        response = admin_get(host, "/config/")
        admin_ok, detail = response.status_code == 200, f"HTTP {response.status_code}"
        running = response.content if admin_ok else None
    except httpx.HTTPError as error:
        admin_ok, detail = False, said(error)
    if "CERTIFICATE_VERIFY_FAILED" in detail:
        hint, block = (
            'Caddyman does not know the CA behind this certificate. Press "Save and check" in the Caddy settings to fetch it.'
        ), ""
    elif managed:
        hint, block = (
            "Caddy's admin API has no login of its own. Expose it through a site with basic auth like this one, "
            "keep that site in the base Caddyfile of this host, and enter the login in the settings."
        ), (
            "admin.home.example {\n\tbasic_auth {\n\t\tcaddyman <bcrypt hash from: caddy hash-password>\n\t}\n"
            "\treverse_proxy localhost:2019 {\n\t\theader_up Host {upstream_hostport}\n\t}\n}"
        )
    elif detail == "HTTP 401":
        hint, block = "The login was refused. Check username and password in the settings.", ADMIN_SITE_SNIPPET
    else:
        hint, block = (
            "Add this site to the base Caddyfile, restart Caddy, and enter the address (http://caddy:2020) and the "
            "login in the settings. Create the hash with: docker exec -it caddy caddy hash-password"
        ), ADMIN_SITE_SNIPPET
    add("Admin API is reachable", admin_ok, f"{host['admin_url']} - {detail}", hint, block)
    for dns in dns_snippets(host) if admin_ok and text is not None else []:
        if not snippet_exists(text, dns):
            continue
        problem = dns_snippet_problem(host, text, dns)
        add(
            f"Caddy understands the DNS snippet '{dns}'",
            not problem,
            problem,
            "Caddy refused the snippet. \"Module not registered\" means this Caddy was built without the plugin of your "
            "DNS provider; the Caddy settings show the Dockerfile for it.",
        )
    if host.get("admin_ca"):
        # Remembered on first use, so it is shown: the codes are the ones the Root CA page gives.
        origin = "entered in the settings" if host.get("admin_ca_pasted") else "fetched when the settings were saved"
        add("CA of the admin API is remembered", True, f"check code {check_codes(host['admin_ca'])}, {origin}")
    if admin_ok:
        # The quick way in, 'admin :2019', works but leaves Caddy open to every container on its network.
        add(
            "Admin API asks for a login",
            bool(host.get("admin_user")),
            "",
            "Anything that reaches this address can reconfigure Caddy. Remove 'admin :2019' from the global options, "
            "add this site instead, and enter its address and login in the settings. Create the hash with: "
            "docker exec -it caddy caddy hash-password",
            ADMIN_SITE_SNIPPET,
        )
    # Caddy's own CA comes through the admin API: when that is down, the line above says so already.
    if host["root_ca_url"] or admin_ok:
        try:
            _, source, _ = fetch_root_ca(host)
            add("Root CA can be downloaded", True, source)
        except ValueError as error:
            add(
                "Root CA can be downloaded",
                False,
                str(error),
                "The Root CA page has nothing to offer until this answers. "
                + ("Check the root CA source in the settings." if host["root_ca_url"] else "Caddy's own CA did not answer."),
                "",
            )

    add(
        "Sites directory is writable",
        os.path.isdir(sites) and os.access(sites, os.W_OK),
        sites,
        "Save this host again to create its directory in the data volume." if managed
        else "Mount Caddy's sites directory into this container, writable. In this tool's compose file:",
        "" if managed else f"    volumes:\n      - /opt/caddy/sites:{sites}",
    )
    if managed and running is not None:
        add(
            "Caddy runs what Caddyman pushed",
            pushed_digest(host) == hashlib.sha256(running).hexdigest(),
            "",
            "Nothing was pushed yet, or Caddy was restarted without --resume and dropped every route. "
            "Start Caddy with this command, then use 'Reload Caddy':",
            "command: caddy run --resume --config /etc/caddy/Caddyfile --adapter caddyfile",
        )
    if text is not None:
        # Two words the log setup gained later. Each is only asked about where it matters.
        logger = re.search(r"^\s*log\s+\S+\s*\{", text, re.MULTILINE)
        if logger and any(item["route"] and item["route"].get("log") for item in list_routes(host)):
            add(
                "Requests of routes with an access log stay out of Caddy's own log",
                "exclude http.log.access" in text,
                "",
                "Requests of a route with its own access log are written twice. Add this line to the logger in the "
                "base Caddyfile, then use 'Reload Caddy':",
                "exclude http.log.access",
            )
        if managed and LOG_REMOTE_DIR in text:
            add(
                "Rotated logs are listed",
                re.search(r"\bfile_server\s+browse\b", text),
                "",
                "Without a directory listing the Logs page only offers caddy.log. Write it like this in the base "
                "Caddyfile, then use 'Reload Caddy':",
                f"handle_path {LOG_REMOTE_DIR}/* {{\n\troot * /var/log/caddy\n\tfile_server browse\n}}",
            )
    # About Caddyman, not about Caddy, but this is the list people look at. The key itself is
    # never shown: every account can open this page.
    add(
        "Secret key comes from the environment",
        SECRET_KEY_FROM_ENV,
        "CADDYMAN_SECRET_KEY" if SECRET_KEY_FROM_ENV else str(SECRET_FILE),
        "Caddyman made a key of its own and keeps it in the data volume, next to the passwords it protects. "
        "Print it and put it into the .env file next to the compose file; nothing has to be entered again.",
        "docker exec caddyman cat /data/secret.key\n\n# .env\nCADDYMAN_SECRET_KEY=<what the command printed>",
    )
    if SECRET_KEY_FROM_ENV and len(SECRET_KEY) < MIN_SECRET_KEY_CHARS:
        add(
            "Secret key is long enough",
            False,
            f"{len(SECRET_KEY)} characters",
            f"A key under {MIN_SECRET_KEY_CHARS} characters can be guessed from a session cookie. Put a new one into the "
            ".env file. Every session ends; stored passwords and two-factor logins have to be set up again.",
            "openssl rand -base64 32",
        )
    return checks


async def host_from_form(request: Request) -> dict:
    """The host as entered. The keys starting with 'form_' never reach hosts.json."""
    form = await request.form()
    host = {key: str(form.get(key, "")).strip() for key in (*HOST_DEFAULTS, "storage", "admin_user")}
    host["admin_url"] = host["admin_url"].rstrip("/")
    host["sites_dir"] = host["sites_dir"].rstrip("/") or "/"
    host["form_password"] = str(form.get("admin_password", ""))
    host["dns_snippet"] = " ".join(dict.fromkeys(host["dns_snippet"].replace(",", " ").split()))
    host["form_base"] = str(form.get("base_caddyfile", "")).replace("\r\n", "\n").strip()
    # Only the certificates are kept; text around them is dropped. Something that holds none stays, to be refused.
    pasted = str(form.get("admin_ca", "")).strip()
    host["form_ca"] = "\n".join(PEM_RE.findall(pasted)) or pasted
    host["form_reach"] = str(form.get("reach", "")).strip()
    return host


def pushed_file(host: dict) -> Path:
    return managed_dir(host["id"]) / "pushed.sha256"


def pushed_digest(host: dict) -> str:
    try:
        return pushed_file(host).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


META_PREFIX = "# caddyman "
ROUTE_TYPES = ("reverse_proxy", "redirect", "static")
TLS_MODES = ("acme_ca", "default", "dns", "snippet", "internal", "none")
REDIRECT_CODES = ("301", "302", "308")
# The port may be left out: Caddy then takes 443 for https:// and 80 for everything else.
UPSTREAM_RE = re.compile(r"^(https?://)?([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?)(?::([0-9]{1,5}))?\Z")
# Everything below ends up in a file Caddy executes, so each value is held to a
# character set that cannot open a block, start a directive or add a line.
REDIRECT_RE = re.compile(r"^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?\Z")
STATIC_ROOT_RE = re.compile(r"^/[A-Za-z0-9._/-]*\Z")
AUTH_USER_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}\Z")
BCRYPT_RE = re.compile(r"^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}\Z")
ROUTE_NAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?\Z")
# Groups only sort the list. Which route is in which group stands in the route file; this
# file only keeps the names, so a group can exist before a route uses it.
GROUPS_FILE = DATA_DIR / "groups.json"
GROUP_RE = re.compile(r"\w[\w .-]{0,39}")
GROUP_HINT = "A group name is up to 40 letters, digits, spaces, '.', '_' and '-'."
# Where a route with an access log has Caddy write it: the directory of Caddy's own log, as
# Caddy sees it, so the Logs page shows both. The file is named after the route file.
ACCESS_LOG_DIR, ACCESS_LOG_PREFIX = "/var/log/caddy", "access-"
LOAD_TIMEOUT = 30
REACH_TIMEOUT = 2
# One writer at a time: write, reload and a possible undo must not interleave.
WRITE_LOCK = threading.Lock()


def valid_upstream(value) -> bool:
    """host, host:port or http(s)://host:port, with a port that exists."""
    match = UPSTREAM_RE.match(value) if isinstance(value, str) else None
    return bool(match) and (not match.group(4) or valid_port(match.group(4)))


def typed_target(value: str) -> str:
    """A target as somebody copies it out of a browser, brought to what Caddy needs.

    http:// and a slash at the end say nothing: plain HTTP is what Caddy speaks anyway.
    https:// stays, it is what makes Caddy speak TLS to the target.
    """
    value = value.strip()
    if value.lower().startswith("https://"):
        value = "https://" + value[8:]
    elif value.lower().startswith("http://"):
        value = value[7:]
    return value.rstrip("/")


def valid_port(value: str) -> bool:
    return is_number(value) and 1 <= int(value) <= 65535


# A snippet and its block, up to the closing brace at the start of a line.
SNIPPET_BLOCK_RE = re.compile(r"^\(([A-Za-z0-9_-]+)\)\s*\{\n(.*?)^\}", re.MULTILINE | re.DOTALL)


def base_snippets(host: dict) -> list[str]:
    """The snippets of the base Caddyfile that set up TLS, whether the TLS setting names them or not.

    SSO and DNS snippets have settings of their own and stay out.
    """
    others = {host["sso_snippet"], *dns_snippets(host)}
    return [name for name, block in SNIPPET_BLOCK_RE.findall(base_text(host))
            if name not in others and re.search(r"^\s*tls\b", block, re.MULTILINE)]


def snippet_exists(caddyfile_text: str, snippet: str) -> bool:
    return bool(snippet and re.search(rf"^\({re.escape(snippet)}\)\s*\{{", caddyfile_text, re.MULTILINE))


def acme_ca_url(caddyfile_text: str, snippet: str) -> str:
    """The ACME directory a TLS snippet points at, or '' when it names none in the plain form 'ca <url>'."""
    block = re.search(rf"^\({re.escape(snippet)}\)\s*\{{\n(.*?)^\}}", caddyfile_text, re.MULTILINE | re.DOTALL)
    found = re.search(r"^\s*ca\s+(https?://\S+)\s*$", block.group(1), re.MULTILINE) if block else None
    return found.group(1) if found else ""


# What Caddy needs for the DNS challenge, per provider: the name of its plugin under
# github.com/caddy-dns and the lines of the 'dns' directive. Every one of them was read by a
# Caddy built with that plugin. Whoever is missing takes the snippet of a neighbour as a start.
DNS_PROVIDERS = {
    "Cloudflare": ("cloudflare", ["dns cloudflare {env.CLOUDFLARE_API_TOKEN}"]),
    "deSEC": ("desec", ["dns desec {", "\ttoken {env.DESEC_TOKEN}", "}"]),
    "DigitalOcean": ("digitalocean", ["dns digitalocean {env.DO_AUTH_TOKEN}"]),
    "Duck DNS": ("duckdns", ["dns duckdns {env.DUCKDNS_API_TOKEN}"]),
    "Gandi": ("gandi", ["dns gandi {env.GANDI_BEARER_TOKEN}"]),
    "Hetzner": ("hetzner", ["dns hetzner {env.HETZNER_API_TOKEN}"]),
    "INWX": ("inwx", ["dns inwx {", "\tusername {env.INWX_USERNAME}", "\tpassword {env.INWX_PASSWORD}", "}"]),
    "IONOS": ("ionos", ["dns ionos {env.IONOS_API_TOKEN}"]),
    "Namecheap": ("namecheap", ["dns namecheap {", "\tapi_key {env.NAMECHEAP_API_KEY}", "\tuser {env.NAMECHEAP_API_USER}", "}"]),
    "netcup": (
        "netcup",
        [
            "dns netcup {",
            "\tcustomer_number {env.NETCUP_CUSTOMER_NUMBER}",
            "\tapi_key {env.NETCUP_API_KEY}",
            "\tapi_password {env.NETCUP_API_PASSWORD}",
            "}",
        ],
    ),
    "OVH": (
        "ovh",
        [
            "dns ovh {",
            "\tendpoint {env.OVH_ENDPOINT}",
            "\tapplication_key {env.OVH_APPLICATION_KEY}",
            "\tapplication_secret {env.OVH_APPLICATION_SECRET}",
            "\tconsumer_key {env.OVH_CONSUMER_KEY}",
            "}",
        ],
    ),
    "Porkbun": ("porkbun", ["dns porkbun {", "\tapi_key {env.PORKBUN_API_KEY}", "\tapi_secret_key {env.PORKBUN_API_SECRET_KEY}", "}"]),
}


def dns_guides(snippet: str) -> list[dict]:
    """Per provider the three things to copy: the image, the variables for Caddy, the snippet."""
    guides = []
    for name, (plugin, lines) in DNS_PROVIDERS.items():
        directive = "".join(f"\t\t{line}\n" for line in lines)
        variables = re.findall(r"\{env\.([A-Z0-9_]+)\}", directive)
        guides.append(
            {
                "name": name,
                "dockerfile": f"FROM caddy:2-builder AS builder\nRUN xcaddy build --with github.com/caddy-dns/{plugin}\n\n"
                "FROM caddy:2-alpine\nCOPY --from=builder /usr/bin/caddy /usr/bin/caddy",
                "environment": "    environment:\n" + "".join(f"      {variable}: <from your provider>\n" for variable in variables).rstrip(),
                "snippet": f"({snippet}) {{\n\ttls {{\n{directive}\t}}\n}}",
            }
        )
    return guides


def dns_snippet_problem(host: dict, caddyfile_text: str, name: str) -> str:
    """Caddy's own words on why it cannot read the DNS snippet, '' when it can.

    The plugin of a DNS provider is compiled into Caddy, and the admin API has no list of
    what is in there. So Caddy is handed the snippet with a site that uses it and asked to
    adapt that: nothing is loaded, and a missing plugin shows as an unknown module.
    """
    block = re.search(rf"^\({re.escape(name)}\)\s*\{{\n.*?^\}}", caddyfile_text, re.MULTILINE | re.DOTALL)
    if not block:
        return ""
    try:
        response = httpx.post(
            f"{host['admin_url']}/adapt",
            content=f"{block.group(0)}\n\ndns-check.invalid {{\n\timport {name}\n}}\n".encode(),
            headers={"Content-Type": "text/caddyfile"},
            timeout=ADMIN_TIMEOUT,
            auth=admin_auth(host),
            verify=admin_verify(host),
        )
        if response.status_code == 200:
            return ""
        return str(response.json().get("error", "")) or f"HTTP {response.status_code}"
    except (httpx.HTTPError, ValueError) as error:
        return said(error)


def base_text(host: dict) -> str:
    """The base Caddyfile, or '' when it cannot be read."""
    try:
        return Path(host["caddyfile"]).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def has_snippet(host: dict, key: str, name: str = "") -> bool:
    """Whether the snippet a host setting names is in the base Caddyfile. For the DNS snippets: name, or any."""
    names = ([name] if name else dns_snippets(host)) if key == "dns_snippet" else [host[key]]
    text = base_text(host)
    return any(snippet_exists(text, one) for one in names)


MAX_NETWORKS = 20
MAX_ALIASES = 20
HSTS_LINE = 'header Strict-Transport-Security "max-age=31536000"'
MAX_PATHS = 20

# Error pages: Caddy hands a request it could not answer to Caddyman, which sends a page in the
# chosen design with the same status code. 'blocked' is for the route that catches every name
# no other route knows, where a DNS blocker points blocked names.
ERROR_PAGES = {
    "400": ("Bad request", "The server could not make sense of this request."),
    "403": ("Forbidden", "You are not allowed to open this address."),
    "404": ("Not found", "There is nothing at this address."),
    "405": ("Method not allowed", "This address does not accept that kind of request."),
    "500": ("Internal server error", "Something went wrong on the server."),
    "502": ("Bad gateway", "The service behind this address does not answer."),
    "503": ("Service unavailable", "The service behind this address is not available right now."),
    "504": ("Gateway timeout", "The service behind this address took too long to answer."),
    "blocked": ("Blocked", "This address is blocked on this network."),
    "maintenance": ("Maintenance", "This service is being worked on and will be back soon."),
}
# When each page comes up, for whoever picks its design. The visitor reads the text above instead.
ERROR_MEANINGS = {
    "400": "The request was malformed, often a broken link or client.",
    "403": "Access was refused, for example by Allowed networks.",
    "404": "Nothing answers at this path.",
    "405": "The method is not accepted, like POST where only GET works.",
    "500": "Caddy itself failed while answering.",
    "502": "The target does not answer or refuses the connection.",
    "503": "The target is overloaded or down for a moment.",
    "504": "The target took too long to answer.",
    "blocked": "Names no route knows, sent here by a DNS blocker.",
    "maintenance": "Routes that are switched off, when set under Setup.",
}
# The pages that are no status code of their own, and the code they are sent with.
PAGE_STATUS = {"blocked": 403, "maintenance": 503}
ERROR_TEXT_LIMITS = {"title": 60, "text": 200}
ERROR_DESIGNS = {
    "caddyman": "Caddyman", "ghost": "Ghost", "terminal": "Terminal", "connection": "Connection", "minimal": "Minimal",
    "unicorn": "Unicorn", "space": "Space", "gaming": "Gaming", "forest": "Forest", "synthwave": "Synthwave",
    "ocean": "Ocean", "paper": "Paper",
}
# Never 401: the answer to it has to carry the question for the login, which gets lost on the way.
ERRORS_HANDLED = " ".join(code for code in ERROR_PAGES if code.isdigit())
ERRORS_FILE = DATA_DIR / "errors.json"
CATCH_ALL = "catch-all"


def load_errors() -> dict:
    """Where Caddy finds Caddyman if somebody typed it in, and the design chosen for each error."""
    stored = read_json(ERRORS_FILE, {})
    disabled = "maintenance" if stored.get("disabled") == "maintenance" else ""
    return {"upstream": stored.get("upstream", ""), "designs": stored.get("designs", {}), "texts": error_texts(stored.get("texts")), "disabled": disabled}


def off_value(host: dict):
    """What "off" holds for a route switched off now: True, or where Caddy fetches the maintenance page."""
    return caddyman_upstream(host) if load_errors()["disabled"] == "maintenance" else True


def error_texts(texts) -> dict:
    """Own wording for an error page, where somebody wrote one: {code: {"title": ..., "text": ...}}."""
    if not isinstance(texts, dict):
        return {}
    kept = {}
    for code, item in texts.items():
        if code in ERROR_PAGES and isinstance(item, dict):
            item = {key: str(item.get(key, "")).strip()[:limit] for key, limit in ERROR_TEXT_LIMITS.items()}
            if any(item.values()):
                kept[code] = item
    return kept


def caddyman_upstream(host: dict, request: Request | None = None) -> str:
    """Where Caddy reaches Caddyman: the address saved under Error pages, else the target of a
    route to Caddyman, else a guess. Error pages and the own route ask here, so both agree."""
    if stored := load_errors()["upstream"]:
        return stored
    for item in list_routes(host):
        route = item["route"]
        if route and not route.get("off") and route["type"] == "reverse_proxy" and route["upstream"].endswith(f":{OWN_PORT}"):
            return route["upstream"]
    # A Caddy next door reaches this container by name, one elsewhere by the address the browser used.
    # That address comes from the Host header: only a suggestion in a form, never written into a route.
    there = asked_host(request)[0] if request and host.get("storage") == "managed" else "caddyman"
    return f"{there}:{OWN_PORT}"


# A path that goes to a target of its own. Never '/' alone: that is what the main target is for.
PATH_RE = re.compile(r"^/[A-Za-z0-9._~-][A-Za-z0-9._~/-]*\*?\Z")


def allowed_networks(text: str) -> str | None:
    """The networks a route is limited to, tidied and joined by spaces, or None when one is no network.

    'private' stands for every private range. Everything else goes through ipaddress, so
    nothing but an address or a network can reach the route file.
    """
    found = []
    for item in text.replace(",", " ").split()[: MAX_NETWORKS + 1]:
        # An IPv6 address may name a zone after '%', and ipaddress keeps whatever stands there.
        if "%" in item:
            return None
        try:
            if item.lower() == "private":
                found.append("private")
            elif "/" in item:
                found.append(str(ipaddress.ip_network(item, strict=False)))
            else:
                found.append(str(ipaddress.ip_address(item)))
        except ValueError:
            return None
    return " ".join(dict.fromkeys(found)) if len(found) <= MAX_NETWORKS else None


def after_group(route: dict, key: str, value: str) -> dict:
    """The route with key right after the group, or the TLS mode without one: regroup() keeps it there."""
    items = [item for item in route.items() if item[0] != key]
    at = next(index for index, (name, _) in enumerate(items) if name == ("group" if "group" in route else "tls")) + 1
    return dict(items[:at] + [(key, value)] + items[at:])


def route_from_form(form, host: dict, previous: dict | None = None) -> tuple[dict, str | None]:
    """Normalise the form into route metadata and name the first problem, if any.

    previous is the route as it is on disk when editing; its password hash is kept
    when the form leaves the password empty. Optional keys are only added when set,
    and always in the same order, so files written before a key existed stay ours.
    """
    get = lambda key: str(form.get(key, "")).strip()  # noqa: E731
    # One field per entry from the form; a file that is taken over hands them in as one text.
    many = lambda key: " ".join(map(str, form.getlist(key))) if hasattr(form, "getlist") else get(key)  # noqa: E731

    def full(name: str) -> str:
        return name.lower().strip(".")

    def usable(name: str) -> bool:
        # '*.' in front stands for every name one level below: a wildcard.
        return bool(HOSTNAME_RE.match(name.removeprefix("*."))) and ".." not in name and len(name) <= 253

    name = full(get("host"))
    route = {"type": get("type"), "host": name, "port": get("port"), "tls": get("tls")}
    if group := get("group"):
        route["group"] = group
        if not GROUP_RE.fullmatch(group):
            return route, GROUP_HINT
    if get("log"):
        route["log"] = True
    if typed := many("allow").strip():
        allow = allowed_networks(typed)
        if not allow:
            return route, f"Allowed networks are up to {MAX_NETWORKS} addresses or networks like 192.168.1.0/24, or the word 'private'."
        route["allow"] = allow
    # Further names for the same route. The first one stays the main name: it names the file.
    aliases = [alias for alias in dict.fromkeys(map(full, many("aliases").replace(",", " ").split())) if alias != name]
    if aliases:
        route["aliases"] = aliases
        if len(aliases) > MAX_ALIASES or not all(map(usable, aliases)):
            return route, f"More hostnames are up to {MAX_ALIASES} names of lowercase letters, digits, '-' and '.', separated by commas."
    # A login service in front of the route. A redirect has nothing to protect.
    if get("sso") and get("type") != "redirect":
        route["sso"] = True
        if not has_snippet(host, "sso_snippet"):
            return route, "This host has no SSO snippet in its base Caddyfile, so a single sign-on cannot be put in front."
    # HSTS only means something where the route speaks TLS.
    if get("hsts") and get("tls") != "none":
        route["hsts"] = True
    # Caddy's own errors as a page from Caddyman. A redirect has no error to show.
    if get("errors") and get("type") != "redirect":
        route["errors"] = caddyman_upstream(host)
    if not usable(name):
        return route, "The hostname may only contain lowercase letters, digits, '-' and '.'."
    if route["port"] and not valid_port(route["port"]):
        return route, "The port has to be a number between 1 and 65535."
    if route["tls"] not in TLS_MODES:
        return route, "Unknown TLS mode."
    if route["tls"] == "acme_ca" and not has_snippet(host, "tls_snippet"):
        return route, "This host has no TLS snippet in its base Caddyfile, so 'Own ACME CA' is not available."
    if route["tls"] == "dns":
        names = dns_snippets(host)
        chosen = get("dns") or (names[0] if names else "")
        if chosen not in names or not has_snippet(host, "dns_snippet", chosen):
            return route, "This host has no such DNS snippet in its base Caddyfile, so the DNS challenge is not available."
        if len(names) > 1:
            route = after_group(route, "dns", chosen)
    if route["tls"] == "snippet":
        # Any snippet of the base Caddyfile, for a TLS setup none of the host settings names.
        if (chosen := get("snippet")) not in base_snippets(host):
            return route, "Pick a snippet from the base Caddyfile."
        route = after_group(route, "snippet", chosen)
    # No CA hands out a wildcard after a check over HTTP: that proves one name, not all of them.
    if route["tls"] in ("acme_ca", "default") and any(item.startswith("*.") for item in (name, *aliases)):
        return route, "A wildcard name needs the DNS challenge or Caddy's internal CA. A certificate for it cannot be obtained over HTTP."
    if route["type"] == "reverse_proxy":
        route["upstream"] = typed_target(get("upstream"))
        if not valid_upstream(route["upstream"]):
            return route, "The target has to look like host, host:port or http://host:port."
        if auth_user := get("auth_user"):
            if not AUTH_USER_RE.match(auth_user):
                return route, "The basic auth username may only contain letters, digits, '.', '_', '@' and '-'."
            route["auth_user"] = auth_user
            # Not stripped: a password may start or end with a space.
            password = str(form.get("auth_password", ""))
            kept = previous.get("auth_hash", "") if previous and previous.get("auth_user") == auth_user else ""
            if password:
                if len(password) < MIN_PASSWORD_CHARS:
                    return route, f"The basic auth password needs at least {MIN_PASSWORD_CHARS} characters."
                if len(password.encode()) > MAX_PASSWORD_BYTES:
                    return route, f"The basic auth password is longer than {MAX_PASSWORD_BYTES} bytes."
                # Only the hash is kept, in the route file. The password itself is never stored.
                route["auth_hash"] = hash_password(password)
            elif BCRYPT_RE.match(kept):
                route["auth_hash"] = kept
            else:
                return route, "Basic auth needs a password."
        if get("host_header"):
            route["host_header"] = True
        # Paths that go to a target of their own: one pair of fields each, an empty pair is dropped.
        typed = zip(form.getlist("path"), form.getlist("path_upstream")) if hasattr(form, "getlist") else form.get("paths", [])
        paths = [[str(path).strip(), typed_target(str(target))] for path, target in typed if str(path).strip() or str(target).strip()]
        # Only where TLS is spoken at all: on a plain target the block would switch TLS on.
        if get("skip_verify") and any(target.startswith("https://") for target in (route["upstream"], *(pair[1] for pair in paths))):
            route["skip_verify"] = True
        if paths:
            # Longest first. Caddy sorts them like that anyway, except in the route block
            # around allowed networks, where the lines run as written.
            route["paths"] = sorted(paths, key=lambda pair: -len(pair[0]))
            if len(paths) > MAX_PATHS or len({pair[0] for pair in paths}) < len(paths):
                return route, f"Paths to other targets are up to {MAX_PATHS}, each path once."
            for path, target in paths:
                if not PATH_RE.match(path) or ".." in path:
                    return route, "A path starts with '/' and may end in '*', like /api/*. Letters, digits, '.', '_', '~', '-' and '/' only."
                if not valid_upstream(target):
                    return route, f"The target for {path} has to look like host, host:port or http://host:port."
    elif route["type"] == "redirect":
        route["target"], route["code"] = get("target").rstrip("/"), get("code")
        if not REDIRECT_RE.match(route["target"]):
            return route, "The redirect target has to be a plain http or https URL without query."
        if route["code"] not in REDIRECT_CODES:
            return route, "The redirect code has to be 301, 302 or 308."
    elif route["type"] == "static":
        route["root"] = get("root")
        if not STATIC_ROOT_RE.match(route["root"]) or ".." in route["root"].split("/"):
            return route, "The directory has to be an absolute path of letters, digits, '.', '_', '-' and '/'."
    else:
        return route, "Unknown route type."
    # Only a reverse proxy asks for a login. Changing the type would drop it without a word.
    if route["type"] != "reverse_proxy" and previous and previous.get("auth_user"):
        return route, "This route asks for a login (basic auth), which only a reverse proxy does. Remove the login first, then change the type."
    # Always the last key, so the button in the list can add and drop it without the form.
    # A route switched off with the maintenance page keeps it when it is saved.
    if get("off"):
        route["off"] = caddyman_upstream(host) if get("off") == "maintenance" else True
    return route, None


def render_route(route: dict, host: dict) -> str:
    """The complete file for a route. Expects metadata that passed route_from_form."""
    # Caddyman's own address goes in from several places, not only the form: checked once here, for all of them.
    own = [route.get("errors"), route["off"] if isinstance(route.get("off"), str) else ""]
    own += [route.get("upstream")] if route["type"] == "error_page" else []
    if any(value and not valid_upstream(value) for value in own):
        raise ValueError("not an address Caddy can reach Caddyman under")
    # Caddy has no directive that turns TLS off; an http:// address does.
    scheme, port = "http://" if route["tls"] == "none" else "", f":{route['port']}" if route["port"] else ""
    address = ", ".join(f"{scheme}{name}{port}" for name in (route["host"], *route.get("aliases", [])))
    if route["type"] == "error_page":
        # No name at all: every request over plain HTTP that no other route claims.
        # Plain HTTP only. Over HTTPS it would need a certificate for any name, and Caddy takes
        # no issuer on a site without a name once the base Caddyfile has one itself or an email.
        address = "http://"
    lines = []
    if route["tls"] == "acme_ca":
        lines.append(f"import {host['tls_snippet']}")
    elif route["tls"] == "dns":
        lines.append(f"import {route.get('dns') or next(iter(dns_snippets(host)), '')}")
    elif route["tls"] == "snippet":
        lines.append(f"import {route['snippet']}")
    elif route["tls"] == "internal":
        lines.append("tls internal")
    if route.get("hsts"):
        # One year, this name only. Caddy puts headers first, so every answer of the route carries it.
        lines.append(HSTS_LINE)
    # Everything that answers a request starts here; with allowed networks it is wrapped below.
    handlers = len(lines)
    # Switched off with the maintenance page: Caddy keeps the name and its certificate,
    # and every request gets the page, with 503. Off without it, the block is commented out below.
    maintenance = route.get("off") if isinstance(route.get("off"), str) else ""
    if route.get("sso") and not maintenance:
        lines.append(f"import {host['sso_snippet']}")
    if maintenance:
        lines += ["rewrite * /error/maintenance", f"reverse_proxy {maintenance}"]
    elif route["type"] == "reverse_proxy":
        if route.get("auth_user"):
            lines += ["basic_auth {", f"\t{route['auth_user']} {route['auth_hash']}", "}"]
        # The paths first, then everything else. The options go for every target of the route.
        for path, target in [*route.get("paths", []), ("", route["upstream"])]:
            options = []
            if route.get("host_header"):
                options.append("\theader_up Host {upstream_hostport}")
            if route.get("skip_verify") and target.startswith("https://"):
                options += ["\ttransport http {", "\t\ttls_insecure_skip_verify", "\t}"]
            proxy = f"reverse_proxy {path} {target}" if path else f"reverse_proxy {target}"
            lines += [f"{proxy} {{", *options, "}"] if options else [proxy]
    elif route["type"] == "redirect":
        lines.append(f"redir {route['target']}{{uri}} {route['code']}")
    elif route["type"] == "error_page":
        lines += [f"rewrite * /error/{route['page']}", f"reverse_proxy {route['upstream']}"]
    else:
        lines += [f"root * {route['root']}", "file_server"]
    if route.get("allow"):
        # In a route block the lines run as written. Outside of one Caddy sorts them, and a
        # redirect or a login would come before the refusal.
        networks = route["allow"].replace("private", "private_ranges")
        inside = [f"\t{line}" for line in lines[handlers:]]
        # 'error' instead of 'respond' where error pages are on: only an error reaches handle_errors.
        refusal = "\terror @outside 403" if route.get("errors") else "\trespond @outside 403"
        lines[handlers:] = [f"@outside not client_ip {networks}", "route {", refusal, *inside, "}"]
    if route.get("errors"):
        lines += [f"handle_errors {ERRORS_HANDLED} {{", "\trewrite * /error/{err.status_code}", f"\treverse_proxy {route['errors']}", "}"]
    if route.get("log"):
        # Every request to this route, in a file of its own next to Caddy's log, where the Logs page finds it.
        file = f"{ACCESS_LOG_DIR}/{ACCESS_LOG_PREFIX}{route_file_name(route, host)}.log"
        lines += ["log {", f"\toutput file {file} {{", "\t\troll_size 10MiB", "\t\troll_keep 3", "\t}", "}"]
    body = "".join(f"\t{line}\n" for line in lines)
    site = f"{address} {{\n{body}}}\n"
    if route.get("off") is True:
        # Switched off: Caddy skips comments, while the file keeps every setting for later.
        site = "".join(f"# {line}\n" for line in site.splitlines())
    return f"{META_PREFIX}{json.dumps(route, separators=(',', ':'))}\n{site}"


def route_file_name(route: dict, host: dict) -> str:
    """File name without extension: the hostname without the host's suffix."""
    if route["type"] == "error_page":
        return CATCH_ALL
    # An install from before 15.10.2026 may still have a domain suffix: its files keep their short names.
    name = route["host"].removesuffix(f".{host['domain_suffix']}") if host.get("domain_suffix") else route["host"]
    # A star cannot stand in a file name.
    name = "wildcard" + name[1:] if name.startswith("*") else name
    return name + (f"_{route['port']}" if route["port"] else "")


def route_path(host: dict, name: str) -> Path | None:
    """The file for a route name, or None when the name would leave the sites directory."""
    if not ROUTE_NAME_RE.match(name) or ".." in name:
        return None
    sites = Path(host["sites_dir"]).resolve()
    path = (sites / f"{name}.caddy").resolve()
    return path if path.parent == sites else None


# Where render_route expects text. A number there would render just as well, and then trip
# up everything that reads the route afterwards.
ROUTE_TEXTS = ("type", "host", "port", "tls", "group", "dns", "snippet", "allow", "errors", "upstream", "auth_user", "auth_hash", "target", "code", "root", "page")


def well_formed(route) -> bool:
    """Whether the metadata of a file has the shapes route_from_form gives it."""
    if not isinstance(route, dict) or not all(isinstance(route.get(key, ""), str) for key in ROUTE_TEXTS):
        return False
    if "off" in route and route["off"] is not True and not valid_upstream(route["off"]):
        return False
    aliases, paths = route.get("aliases", []), route.get("paths", [])
    pairs = isinstance(paths, list) and all(isinstance(pair, list) and len(pair) == 2 and all(isinstance(part, str) for part in pair) for pair in paths)
    return pairs and isinstance(aliases, list) and all(isinstance(name, str) for name in aliases)


LOST_TLS_SNIPPET = "Made with Own ACME CA, but no TLS snippet is set under Settings → Caddy any more"


def route_meta(content: str):
    """What the first line of a file says about it, or None when it says nothing readable."""
    first = content.split("\n", 1)[0]
    try:
        return json.loads(first[len(META_PREFIX):]) if first.startswith(META_PREFIX) else None
    except ValueError:
        return None


def lost_tls_snippet(host: dict, content: str) -> bool:
    """Whether a file was written with Own ACME CA before the TLS snippet was taken out of the settings."""
    meta = route_meta(content)
    return not host["tls_snippet"] and isinstance(meta, dict) and meta.get("tls") == "acme_ca"


def read_route(path: Path, host: dict) -> dict | None:
    """Metadata of a file this tool wrote and nobody changed since, else None."""
    try:
        content = path.read_text(encoding="utf-8")
        route = route_meta(content)
        if not well_formed(route):
            return None
        # No form writes this type: it is the one file Error pages writes, and nothing else.
        if route["type"] == "error_page" and not (path.stem == CATCH_ALL and route.get("page") in ERROR_PAGES and valid_upstream(route.get("upstream", ""))):
            return None
        # No hash, no parser: a file is ours exactly when its metadata reproduces it.
        return route if render_route(route, host) == content else None
    except (OSError, ValueError, KeyError, TypeError):
        return None


def list_routes(host: dict) -> list[dict]:
    try:
        paths = sorted(Path(host["sites_dir"]).glob("*.caddy"))
    except OSError:
        return []
    return [{"name": path.stem, "path": path, "route": read_route(path, host)} for path in paths]


def route_group(route: dict | None) -> str:
    """The group of a route, empty for none. The value comes from a file somebody may have edited."""
    group = route.get("group") if route else ""
    return group if isinstance(group, str) else ""


def stored_groups() -> list[str]:
    return read_json(GROUPS_FILE, [])


GROUPS_LOCK = threading.Lock()


def change_groups(change) -> None:
    """Read, change and write the stored names in one go, so two changes at once both stay."""
    with GROUPS_LOCK:
        write_json(GROUPS_FILE, sorted(set(change(stored_groups())), key=str.lower))


def load_groups(host: dict) -> list[str]:
    """Every group: the ones created here and the ones a route file names, as after a restore."""
    used = {route_group(item["route"]) for item in list_routes(host)} - {""}
    return sorted({*stored_groups(), *used}, key=str.lower)


def regroup(host: dict, old: str, new: str) -> str | None:
    """Move every route of a group to another name, or to none. One reload, undone as a whole."""
    changes = {}
    stamps = route_stamps(host)
    for item in list_routes(host):
        route = item["route"]
        if route_group(route) == old:
            rest = {key: value for key, value in route.items() if key != "group"}
            # Same place as in route_from_form, or the file would no longer count as ours.
            head = {key: rest[key] for key in ("type", "host", "port", "tls")}
            changes[item["path"]] = render_route({**head, **({"group": new} if new else {}), **rest}, host)
    # Raises Conflict when one of the files was saved by somebody else since it was read here.
    return apply_route(host, changes, "group", f"{old} -> {new or 'no group'}", expect={path: stamps.get(path) for path in changes}) if changes else None


def admin_get(host: dict, path: str, **more) -> httpx.Response:
    """Ask the admin API, with the login and the CA this host needs."""
    return httpx.get(f"{host['admin_url']}{path}", timeout=ADMIN_TIMEOUT, auth=admin_auth(host), verify=admin_verify(host), **more)


def caddy_body(host: dict) -> bytes:
    """The complete Caddyfile for a host, as text. Never JSON: Caddy adapts it itself."""
    base = Path(host["caddyfile"]).read_bytes()
    if host.get("storage") != "managed":
        # Sent word for word: Caddy resolves the import of the sites directory itself, so what
        # is pushed here can never differ from what Caddy reads from the file after a restart.
        return base
    # A Caddy elsewhere cannot see these files, an import would find nothing: put them inline.
    routes = [path.read_bytes() for path in sorted(Path(host["sites_dir"]).glob("*.caddy"))]
    return b"\n".join([base, *routes])


def caddy_load(host: dict) -> str | None:
    """Push the configuration as it is on disk. Returns Caddy's error, or None on success."""
    try:
        response = httpx.post(
            f"{host['admin_url']}/load",
            content=caddy_body(host),
            headers={"Content-Type": "text/caddyfile"},
            timeout=LOAD_TIMEOUT,
            auth=admin_auth(host),
            verify=admin_verify(host),
        )
    except (OSError, httpx.HTTPError) as error:
        return said(error)
    if response.status_code == 200:
        if host.get("storage") == "managed":
            # Remembered so the status page can tell when Caddy has fallen back to another config.
            try:
                running = admin_get(host, "/config/")
                pushed_file(host).write_text(hashlib.sha256(running.content).hexdigest(), encoding="utf-8")
            except (OSError, httpx.HTTPError):
                pass
        return None
    if response.status_code == 401:
        return "The admin API refused the login. Check username and password of this host."
    try:
        return response.json()["error"]
    except (ValueError, KeyError, TypeError):
        return response.text or f"HTTP {response.status_code}"


def audit(host: dict, route: str, action: str, error: str | None) -> None:
    entry = {
        "time": datetime.now(timezone.utc).strftime(STAMP),
        "user": CURRENT_USER.get(),
        "route": route,
        "action": action,
        "result": error or "ok",
    }
    with open(AUDIT_FILE, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")


def read_audit() -> list[dict]:
    # Reads the whole log for the last lines and never rotates it. A line per
    # change keeps that small for years; add rotation if someone scripts against the UI.
    try:
        lines = AUDIT_FILE.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    return [json.loads(line) for line in reversed(lines[-AUDIT_SHOWN:])]


def local_time(stamp: str, zone: ZoneInfo) -> str:
    """A time from the change log, which is kept in UTC, in the zone that is shown."""
    try:
        moment = datetime.strptime(stamp, STAMP).replace(tzinfo=timezone.utc)
    except ValueError:
        return stamp
    return moment.astimezone(zone).strftime(STAMP)


class Conflict(Exception):
    """The file changed on disk after it was loaded into the editor."""


CHANGED_MEANWHILE = "A route file was changed in the meantime. Nothing was done, try again."


def route_stamps(host: dict) -> dict[Path, int]:
    """The modification time of every route file, taken before they are read: for apply_route(expect=...)."""
    return {path: file_mtime(path) for path in Path(host["sites_dir"]).glob("*.caddy")}


def file_mtime(path: Path) -> int:
    try:
        return path.stat().st_mtime_ns
    except OSError:
        return 0


def apply_route(
    host: dict,
    changes: dict[Path, str | None],
    action: str,
    label: str,
    expect: tuple[Path, int] | dict[Path, int] | None = None,
    fresh: Path | None = None,
) -> str | None:
    """Write the files (None deletes one), reload Caddy, undo everything on failure.

    Every write path goes through here. With expect, the change is refused when that
    file (or one of several) no longer has the modification time it had when it was loaded. fresh names a
    file that must not be there yet: looked at under the lock, so two saves at the same
    moment cannot both take the name.
    """
    with WRITE_LOCK:
        stamps = dict([expect]) if isinstance(expect, tuple) else expect or {}
        if any(file_mtime(path) != stamp for path, stamp in stamps.items()):
            raise Conflict
        if fresh and fresh.exists():
            return f"A route file {fresh.name} already exists."
        previous = {path: path.read_bytes() if path.exists() else None for path in changes}
        try:
            for path, content in changes.items():
                if content is None:
                    path.unlink()
                else:
                    write_whole(path, content.encode())
            error = caddy_load(host)
        except OSError as os_error:
            error = str(os_error)
        if error:
            # A broken file left on disk would stop Caddy from starting the next time.
            for path, content in previous.items():
                if content is None:
                    path.unlink(missing_ok=True)
                else:
                    write_whole(path, content)
            # If the reload only timed out, Caddy may hold the new config: bring it back in line.
            caddy_load(host)
        # What the route list knew about certificates and targets is from before this change.
        PROBE_CACHE.clear()
        audit(host, label, action, error)
        if error:
            alert("alert_reload", f"Caddy rejected a change to {label}",
                  f"{CURRENT_USER.get()} tried to {action} {label}. Caddy did not take it, and the change was undone.\n\n{error}", right="routes")
        return error


# What a reverse_proxy block may hold when a hand-written file is taken over: the lines
# render_route writes for each option, in its order.
PROXY_OPTIONS = {
    "host_header": [["header_up", "Host", "{upstream_hostport}"]],
    "skip_verify": [["transport", "http", "{"], ["tls_insecure_skip_verify"], ["}"]],
}


def adopt_route(content: str, host: dict) -> tuple[dict | None, str]:
    """Metadata for a hand-written file, or the reason it cannot be taken over.

    This is no Caddyfile parser: it accepts exactly what render_route would produce,
    give or take whitespace and line order, and refuses everything else.
    """
    lines = [line.split() for line in content.splitlines() if line.strip() and not line.startswith(META_PREFIX)]
    if len(lines) < 3 or len(lines[0]) < 2 or lines[0][-1] != "{" or lines[-1] != ["}"]:
        return None, "it is not a single site block"
    # One address, or several separated by commas that differ in nothing but the name.
    names = [re.match(r"^(http://)?([^:/,]+)(?::([0-9]+))?$", token.rstrip(",")) for token in lines[0][:-1]]
    if not all(names) or len({(found.group(1), found.group(3)) for found in names}) != 1:
        return None, "its address is not a plain hostname"
    address = names[0]
    form = {"host": address.group(2), "port": address.group(3) or "", "tls": "none" if address.group(1) else "default"}
    form["aliases"] = " ".join(found.group(2) for found in names[1:])
    inner, index, login, snippets = lines[1:-1], 0, None, base_snippets(host)
    while index < len(inner):
        tokens, block = inner[index], inner[index + 1 : index + 3]
        index += 1
        if tokens == ["import", host["tls_snippet"]]:
            form["tls"] = "acme_ca"
        elif len(tokens) == 2 and tokens[0] == "import" and tokens[1] in dns_snippets(host):
            form["tls"], form["dns"] = "dns", tokens[1]
        elif tokens == ["import", host["sso_snippet"]]:
            form["sso"] = "1"
        elif len(tokens) == 2 and tokens[0] == "import" and tokens[1] in snippets:
            # A snippet none of the host settings names: the TLS mode that imports any snippet.
            form["tls"], form["snippet"] = "snippet", tokens[1]
        elif tokens == HSTS_LINE.split():
            form["hsts"] = "1"
        elif tokens == ["tls", "internal"]:
            form["tls"] = "internal"
        elif tokens[:3] == ["@outside", "not", "client_ip"]:
            form["allow"] = " ".join(tokens[3:]).replace("private_ranges", "private")
        elif tokens == ["handle_errors", *ERRORS_HANDLED.split(), "{"] and len(inner) >= index + 3:
            # Its three lines are skipped: the reverse_proxy in there is not the target of the route.
            form["errors"] = "1"
            index += 3
        elif tokens in (["route", "{"], ["respond", "@outside", "403"], ["error", "@outside", "403"], ["}"]):
            # The wrapper around a route with allowed networks. Whether it sits where
            # Caddyman would put it shows in the comparison at the end.
            continue
        elif tokens == ["basic_auth", "{"] and len(block) == 2 and len(block[0]) == 2 and block[1] == ["}"]:
            # The two blocks Caddyman writes itself, and only in that shape. The hash is taken
            # over as it stands; nobody is asked for the password behind it.
            login = {"auth_user": block[0][0], "auth_hash": block[0][1]}
            form["auth_user"] = login["auth_user"]
            index += 2
        elif tokens[0] == "reverse_proxy":
            # One target, or a path and its target, each with or without the block of options.
            opens = tokens[-1] == "{"
            target = tokens[1 : -1 if opens else None]
            if len(target) == 2 and target[0].startswith("/"):
                form.setdefault("paths", []).append(target)
            elif len(target) == 1:
                form.update(type="reverse_proxy", upstream=target[0])
            else:
                return None, f"it contains a line Caddyman would not write: {' '.join(tokens)}"
            if opens:
                for option, shape in PROXY_OPTIONS.items():
                    if inner[index : index + len(shape)] == shape:
                        form[option] = "1"
                        index += len(shape)
                if inner[index : index + 1] != [["}"]]:
                    return None, f"it contains a line Caddyman would not write: {' '.join(tokens)}"
                index += 1
        elif tokens[0] == "redir" and len(tokens) == 3 and tokens[1].endswith("{uri}"):
            form.update(type="redirect", target=tokens[1].removesuffix("{uri}"), code=tokens[2])
        elif tokens[:2] == ["root", "*"] and len(tokens) == 3:
            form.update(type="static", root=tokens[2])
        elif tokens != ["file_server"]:
            return None, f"it contains a line Caddyman would not write: {' '.join(tokens)}"
    if "type" not in form:
        return None, "it has no reverse_proxy, redir or root line"
    if login and not BCRYPT_RE.match(login["auth_hash"]):
        return None, "its basic auth password is not a bcrypt hash"
    route, error = route_from_form(form, host, previous=login)
    if error:
        return None, error
    rendered = [line.split() for line in render_route(route, host).splitlines()[1:]]
    if rendered[0] != lines[0] or sorted(rendered[1:-1]) != sorted(lines[1:-1]):
        return None, "its content differs from what Caddyman would write for it"
    return route, ""


def target_reachable(upstream: str) -> bool:
    match = UPSTREAM_RE.match(upstream)
    # A metadata line edited by hand can carry a target the form would have refused.
    if not match:
        return False
    port = int(match.group(4) or (443 if match.group(1) == "https://" else 80))
    try:
        with socket.create_connection((match.group(2), port), timeout=REACH_TIMEOUT):
            return True
    except (OSError, OverflowError):
        return False


CERT_TIMEOUT = 3
# The issuer name Caddy's built-in CA uses for the certificates it hands out.
CADDY_INTERNAL_ISSUER = "Caddy Local Authority"


def served_certificate(address: str, port: int, server_name: str) -> x509.Certificate:
    """The certificate Caddy presents for a hostname, exactly as a browser would get it."""
    # Deliberately unverified: this looks at the certificate, it does not rely on it.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((address, port), timeout=CERT_TIMEOUT) as raw:
        with context.wrap_socket(raw, server_hostname=server_name) as tls:
            return x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))


def display_name(name: x509.Name) -> str:
    for oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME):
        if attributes := name.get_attributes_for_oid(oid):
            return str(attributes[0].value)
    return name.rfc4514_string() or "(no name)"


def time_left(expires: datetime) -> str:
    hours = int((expires - datetime.now(timezone.utc)).total_seconds() // 3600)
    return f"{hours} h" if hours < 48 else f"{hours // 24} days"


def certificate_status(host: dict, route: dict | None) -> dict | None:
    """Issuer and expiry of what a route really serves. None when there is nothing to check.

    The handshake goes to Caddy itself with the route's hostname as SNI, so it works
    without DNS for that name. level is ok, warn, fail or unknown.
    """
    if not route or route["tls"] == "none":
        return None
    address = urlsplit(host["admin_url"]).hostname
    try:
        # For a wildcard any name below it is asked for: Caddy answers with the certificate for all of them.
        certificate = served_certificate(address, int(route["port"] or 443), route["host"].replace("*", "wildcard-check", 1))
    except ssl.SSLError:
        # Caddy answers the handshake with an alert as long as it has no certificate for the name.
        return {"level": "fail", "short": "No certificate", "detail": "Caddy has not obtained one yet. Its log says why."}
    except (OSError, ValueError) as error:
        return {"level": "unknown", "short": "Not checked", "detail": f"{address} is not reachable for a TLS handshake: {error}"}
    issuer = display_name(certificate.issuer)
    expires = certificate.not_valid_after_utc
    detail = f"Expires {expires:%Y-%m-%d %H:%M} UTC"
    if expires <= datetime.now(timezone.utc):
        return {"level": "fail", "short": "Expired", "issuer": issuer, "detail": detail}
    # short is what the list shows; who issued it and what is wrong are its tooltip.
    status = {"level": "ok", "short": f"{time_left(expires)} left", "issuer": issuer, "detail": detail, "expires": expires}
    if route["tls"] == "acme_ca" and CADDY_INTERNAL_ISSUER in issuer:
        # The failure that went unnoticed longest: a route quietly served from Caddy's own CA.
        status.update(level="warn", detail=f"Issued by Caddy's internal CA instead of your ACME CA. {detail}")
    return status


# The checks behind the route list: one TLS handshake and one connection to the target per
# route. What they find is kept for a while, good news longer than bad, so a problem that
# was just fixed shows soon. Every change to the routes forgets all of it.
PROBES = ThreadPoolExecutor(max_workers=16, thread_name_prefix="probe")
PROBE_CACHE: dict[tuple, tuple[float, object]] = {}
PROBE_SECONDS = {True: 60, False: 15}
# The page waits this long for all checks together. One that is still running then, a name no
# DNS answers for instance, finishes in the background and is there on the next load.
PROBE_BUDGET = 6
RUNNING, QUEUED = object(), object()
# Certificate levels, worst first.
CERT_RANK = ("fail", "warn", "unknown", "ok")


def probes(jobs: dict[tuple, tuple]) -> dict[tuple, object]:
    """Run checks side by side. jobs maps a key to (function, arguments, what counts as good).

    Returns the result per key, or RUNNING or QUEUED for a check the budget ran out on.
    """
    now, results, futures = time.monotonic(), {}, {}
    for key, (function, arguments, good) in jobs.items():
        kept = PROBE_CACHE.get(key)
        if kept and kept[0] > now:
            results[key] = kept[1]
            continue

        def run(key=key, function=function, arguments=arguments, good=good):
            value = function(*arguments)
            PROBE_CACHE[key] = (time.monotonic() + PROBE_SECONDS[bool(good(value))], value)
            return value

        futures[key] = PROBES.submit(run)
    wait(futures.values(), timeout=PROBE_BUDGET)
    for key, future in futures.items():
        results[key] = future.result() if future.done() else RUNNING if future.running() else QUEUED
    return results


def hand_written(content: str) -> dict | None:
    """Just enough of a route to look at its certificate, for a file that does not open in the form.

    Taken from the first line, when that is one plain address. Which CA was meant is unknown,
    so the status can say who issued the certificate but not whether that is the wrong one.
    """
    first = next((line.split() for line in content.splitlines() if line.strip() and not line.lstrip().startswith("#")), [])
    address = re.match(r"^(http://)?([^:/]+)(?::([0-9]+))?$", first[0]) if len(first) == 2 and first[1] == "{" else None
    if not address or not HOSTNAME_RE.match(address.group(2)) or (address.group(3) and not valid_port(address.group(3))):
        return None
    return {"tls": "none" if address.group(1) else "default", "host": address.group(2), "port": address.group(3) or ""}


# One word for the badge in the route list, by what the reason from adopt_route says. The reason is its tooltip.
REFUSAL_LABELS = (
    ("would not write", "Unknown line"),
    ("single site block", "Block"),
    ("address", "Address"),
    ("no reverse_proxy", "No target"),
    ("bcrypt", "Password"),
    ("differs", "Changed"),
    ("cannot be read", "Unreadable"),
)


def refusal_label(reason: str) -> str:
    return next((label for part, label in REFUSAL_LABELS if part in reason), "Invalid")


templates.env.filters["refusal_label"] = refusal_label


def site_url(route: dict, name: str) -> str:
    """The address a browser opens for one hostname of a route."""
    # A wildcard is no address anybody can open.
    if "*" in name:
        return ""
    port = f":{route['port']}" if route.get("port") else ""
    return f"{'http' if route['tls'] == 'none' else 'https'}://{name}{port}"


def route_links(route: dict | None) -> tuple[str, str]:
    """Where a click on the hostname and on the target leads. Empty where there is nothing to open."""
    if not route:
        return "", ""
    site = site_url(route, route["host"])
    target = route.get("upstream") or route.get("target") or ""
    if route["type"] == "reverse_proxy" and "://" not in target:
        target = f"http://{target}"
    # Only ever a web address: the value comes from a file somebody may have edited.
    if not target.startswith(("http://", "https://")):
        return site, ""
    # A name without a dot (a container next to Caddy, localhost) or a loopback address means
    # something only on Caddy's side. A browser cannot open it and would wait for nothing.
    name = urlsplit(target).hostname or ""
    if route["type"] == "reverse_proxy" and ("." not in name or name.startswith("127.")):
        return site, ""
    return site, target


def own_route(route: dict | None, request: Request) -> str:
    """'' for an ordinary route, 'own' for one that leads to Caddyman itself, 'used' when this
    very request came in through it.

    Told by the port alone, like the hint on the status page: another service on the same
    port counts too, which costs a sterner question before deleting it.
    """
    if not route or route["type"] != "reverse_proxy" or not route["upstream"].endswith(f":{OWN_PORT}"):
        return ""
    return "used" if asked_host(request)[0] in (route["host"], *route.get("aliases", [])) else "own"


class NoHost(Exception):
    """No Caddy is set up yet. The page that needs one sends to the form for it."""


@app.exception_handler(NoHost)
def no_host(request: Request, error: NoHost):
    return RedirectResponse("/hosts/new", status_code=303)


def pick_host() -> dict | None:
    """The Caddy in use. Caddyman manages one; the list in the file is how it has always looked."""
    return next(iter(load_hosts()), None)


def the_host() -> dict:
    """The Caddy this install manages, for a page that cannot do anything without one."""
    if host := pick_host():
        return host
    raise NoHost


def route_form_page(request: Request, host: dict, route: dict, error: str | None = None, **context):
    context.setdefault("status_code", 400 if error else 200)
    context["groups"] = load_groups(host)
    return page(request, "route_form.html", host=host, route=route, error=error, acme_ca=has_snippet(host, "tls_snippet"), sso=has_snippet(host, "sso_snippet"), dns=has_snippet(host, "dns_snippet"), dns_names=dns_snippets(host), snippets=base_snippets(host), **context)


def existing_route(name: str) -> tuple[dict | None, Path | None]:
    """The host and the file of a route that is on disk, or a None for what is missing."""
    current = pick_host()
    path = route_path(current, name) if current else None
    return current, path if path and path.is_file() else None


@app.get("/")
def index(request: Request):
    current = the_host()
    # The route for unknown names is switched on and off under Error pages, and only there.
    routes = [item for item in list_routes(current) if not (item["name"] == CATCH_ALL and item["route"] and item["route"]["type"] == "error_page")]
    jobs = {}
    for item in routes:
        item["hand"] = None
        if not item["route"]:
            try:
                text = (Path(current["sites_dir"]) / f"{item['name']}.caddy").read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                item["refused"] = "it cannot be read"
            else:
                item["hand"] = hand_written(text)
                # Why it cannot be adopted, shown in the list before anybody clicks. Empty when it can.
                item["refused"] = adopt_route(text, current)[1]
                # Ours once, until the setting it was made with went away.
                item["lost"] = LOST_TLS_SNIPPET if lost_tls_snippet(current, text) else ""
        served = item["route"] or item["hand"]
        if served and served.get("off"):
            # Caddy does not serve it: no certificate to look at, no target to reach.
            continue
        if served and served["tls"] != "none":
            # One handshake per name: each of them gets a certificate of its own.
            item["cert_keys"] = {}
            for name in (served["host"], *served.get("aliases", [])):
                key = ("certificate", current["admin_url"], name, served["port"], served["tls"])
                item["cert_keys"][name] = key
                jobs[key] = (certificate_status, (current, {**served, "host": name}), lambda status: status and status["level"] == "ok")
        if item["route"] and item["route"]["type"] == "reverse_proxy":
            # The main target and the one of every path.
            item["reach_keys"] = {}
            for target in (item["route"]["upstream"], *(pair[1] for pair in item["route"].get("paths", []))):
                item["reach_keys"][target] = ("target", target)
                jobs[("target", target)] = (target_reachable, (target,), bool)
    found = probes(jobs)
    late = {"level": "unknown", "short": "Still checking", "detail": "The check did not finish in time. Reload the page in a moment."}
    for item in routes:
        # The worst of all names is what the row shows; a further name is called by name.
        item["certificate"], main = None, True
        for name, key in item.get("cert_keys", {}).items():
            status = late if found.get(key) in (RUNNING, QUEUED) else found.get(key)
            shown = item["certificate"]
            if status and (shown is None or CERT_RANK.index(status["level"]) < CERT_RANK.index(shown["level"])):
                item["certificate"] = status if main else {**status, "detail": f"{name}: {status['detail']}"}
            main = False
        # A check that is still running after all that time is a target that does not answer.
        # One that never got its turn says nothing about the target.
        item["target_down"] = [target for target, key in item.get("reach_keys", {}).items() if found.get(key, True) in (False, RUNNING)]
        item["site"], item["link"] = route_links(item["route"])
        item["alias_sites"] = [(alias, site_url(item["route"], alias)) for alias in (item["route"] or {}).get("aliases", [])]
        item["group"] = route_group(item["route"])
        item["own"] = own_route(item["route"], request)
    # Groups in order, what has none at the end.
    routes.sort(key=lambda item: (not item["group"], item["group"].lower()))
    return page(request, "index.html", host=current, routes=routes, own_port=OWN_PORT)


@app.get("/routes/new")
def route_new(request: Request, own: bool = False):
    current = the_host()
    tls = "acme_ca" if has_snippet(current, "tls_snippet") else "default"
    route = {"type": "reverse_proxy", "tls": tls, "code": "308"}
    if own:
        route.update(upstream=caddyman_upstream(current, request))
    return route_form_page(request, current, route)


def arrived(request: Request) -> str:
    """How this request came in: 'https', 'plain', or 'unseen' for HTTPS that Caddyman does not know of.

    Behind Caddy the scheme still reads http unless CADDYMAN_FORWARDED_ALLOW_IPS trusts Caddy.
    Caddy says so in a header all the same; that header is what tells the two cases apart.
    Somebody could send it by hand over plain HTTP, and would only fool the hint on their own screen.
    """
    if is_https(request):
        return "https"
    return "unseen" if request.headers.get("x-forwarded-proto", "").lower() == "https" else "plain"


def own_route_address(host: dict) -> tuple[bool, str]:
    """Whether a route leads to Caddyman itself, and its HTTPS address where that is known.

    Any route file naming this port counts, hand-written ones too; the address is only known
    for a route from the form. Another service on the same port counts as well, which is harmless.
    """
    def leads_here(path: Path) -> bool:
        # Comments do not count: a route that is switched off leads nowhere. Neither does the
        # line after a rewrite to /error/, which only fetches an error page.
        lines = [line for line in path.read_bytes().splitlines() if not line.startswith(b"#")]
        return any(f":{OWN_PORT}".encode() in line and b"/error/" not in before for before, line in zip([b"", *lines], lines))

    try:
        exists = any(map(leads_here, Path(host["sites_dir"]).glob("*.caddy")))
    except OSError:
        exists = False
    for item in list_routes(host):
        route = item["route"]
        if route and not route.get("off") and route["type"] == "reverse_proxy" and route["upstream"].endswith(f":{OWN_PORT}") and route["tls"] != "none":
            return True, f"https://{route['host']}" + (f":{route['port']}" if route["port"] else "")
    return exists, ""


@app.post("/routes/new")
async def route_create(request: Request):
    current = the_host()
    route, error = route_from_form(await request.form(), current)
    if error:
        return route_form_page(request, current, route, error)
    path = route_path(current, route_file_name(route, current))
    if path is None:
        return route_form_page(request, current, route, "This hostname cannot be used as a file name.")
    if path.exists():
        return route_form_page(request, current, route, f"A route file {path.name} already exists.")
    if error := apply_route(current, {path: render_route(route, current)}, "create", path.stem, fresh=path):
        return route_form_page(request, current, route, f"Caddy rejected the route, nothing was changed: {error}")
    if route["type"] == "reverse_proxy" and not target_reachable(route["upstream"]):
        return redirect("/", "warn", f"{route['host']} is saved, but {route['upstream']} does not answer yet.")
    return redirect("/", "ok", f"{route['host']} is live.")


@app.post("/routes/{name}/delete")
def route_delete(name: str):
    current = pick_host()
    path = route_path(current, name) if current else None
    if path is None or not path.exists():
        return redirect("/", "error", "This route does not exist.")
    try:
        error = apply_route(current, {path: None}, "delete", path.stem, expect=(path, file_mtime(path)))
    except Conflict:
        return redirect("/", "warn", f"{path.name} was changed in the meantime. Nothing was done.")
    if error:
        return redirect("/", "error", f"Caddy rejected the reload, {path.name} was kept: {error}")
    return redirect("/", "ok", f"{path.name} was removed.")


def raw_page(request: Request, host: dict, name: str, content: str, mtime: int, **context):
    adoptable = adopt_route(content, host)[0] is not None
    return page(request, "route_raw.html", host=host, name=name, content=content, mtime=mtime, adoptable=adoptable, **context)


@app.get("/routes/{name}/edit")
def route_edit(request: Request, name: str, raw: bool = False):
    current, path = existing_route(name)
    if path is None:
        return redirect("/", "error", "This route does not exist.")
    # Read the time first: a change between the two reads then shows up as a conflict on save.
    mtime = file_mtime(path)
    route = None if raw else read_route(path, current)
    if route and route["type"] == "error_page":
        # Not a route from the form: it is switched on and off where the error pages are.
        return RedirectResponse("/error-pages", status_code=303)
    if route:
        return route_form_page(request, current, route, name=name, mtime=mtime)
    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return redirect("/", "error", f"{path.name} is not UTF-8 text and cannot be edited here.")
    return raw_page(request, current, name, content, mtime)


@app.post("/routes/{name}/edit")
async def route_update(request: Request, name: str):
    current, path = existing_route(name)
    if path is None:
        return redirect("/", "error", "This route does not exist.")
    form = await request.form()
    mtime = int(form["mtime"]) if is_number(str(form.get("mtime", ""))) else 0
    raw = form.get("mode") == "raw"
    route, new_path = None, path
    if raw:
        # Goes to Caddy unchecked by design: the reload validates it, and a rejected file is undone.
        content = str(form.get("content", "")).replace("\r\n", "\n").rstrip() + "\n"
        error = None if content.strip() else "The file would be empty. Delete the route instead."
    else:
        route, error = route_from_form(form, current, previous=read_route(path, current))
        if not error:
            content = render_route(route, current)
            new_path = route_path(current, route_file_name(route, current))
            if new_path is None:
                error = "This hostname cannot be used as a file name."
            elif new_path != path and new_path.exists():
                error = f"A route file {new_path.name} already exists."

    def again(**context):
        if raw:
            return raw_page(request, current, name, content, context.pop("mtime", mtime), **context)
        return route_form_page(request, current, route, name=name, **{"mtime": mtime, **context})

    if error:
        return again(error=error, status_code=400)
    changes = {new_path: content}
    if new_path != path:
        changes[path] = None
    label = name if new_path == path else f"{name} -> {new_path.stem}"
    try:
        error = apply_route(current, changes, "update", label, expect=(path, mtime), fresh=new_path if new_path != path else None)
    except Conflict:
        # Saving once more from this page overwrites what is on disk, knowingly.
        disk = path.read_text(encoding="utf-8", errors="replace") if path.exists() else "(the file was deleted)"
        return again(conflict={"disk": disk, "yours": content}, mtime=file_mtime(path), status_code=409)
    if error:
        return again(error=f"Caddy rejected the change, nothing was changed: {error}", status_code=400)
    if route and route.get("off"):
        return redirect("/", "ok", f"{new_path.name} is saved and stays switched off.")
    if route and route["type"] == "reverse_proxy" and not target_reachable(route["upstream"]):
        return redirect("/", "warn", f"{new_path.name} is saved, but {route['upstream']} does not answer yet.")
    return redirect("/", "ok", f"{new_path.name} is saved and live.")


@app.post("/routes/{name}/toggle")
def route_toggle(request: Request, name: str):
    """Switch a route off or on again. The file stays where it is; only Caddy stops reading it."""
    current, path = existing_route(name)
    if path is None:
        return redirect("/", "error", "This route does not exist.")
    mtime = file_mtime(path)
    route = read_route(path, current)
    if route is None:
        return redirect("/", "warn", f"{path.name} was written by hand. Adopt it first, or comment it out as text.")
    off = not route.pop("off", False)
    if off:
        route["off"] = off_value(current)
    try:
        error = apply_route(current, {path: render_route(route, current)}, "disable" if off else "enable", name, expect=(path, mtime))
    except Conflict:
        return redirect("/", "warn", f"{path.name} was changed in the meantime. Nothing was done.")
    if error:
        return redirect("/", "error", f"Caddy rejected the reload, {path.name} was left as it is: {error}")
    if off:
        shows = "It shows the maintenance page" if route["off"] is not True else "Caddy no longer answers for it"
        return redirect("/", "ok", f"{route['host']} is switched off. {shows}; its settings are kept.")
    return redirect("/", "ok", f"{route['host']} is live again.")


@app.post("/routes/{name}/adopt")
def route_adopt(name: str):
    current, path = existing_route(name)
    if path is None:
        return redirect("/", "error", "This route does not exist.")
    # Taken before reading: a save in between would otherwise be replaced by what was read.
    mtime = file_mtime(path)
    route, reason = adopt_route(path.read_text(encoding="utf-8", errors="replace"), current)
    if route is None:
        return redirect("/", "warn", f"{path.name} was left as it is: {reason}.")
    try:
        error = apply_route(current, {path: render_route(route, current)}, "adopt", name, expect=(path, mtime))
    except Conflict:
        return redirect("/", "warn", f"{path.name} was changed in the meantime. Nothing was done.")
    if error:
        return redirect("/", "error", f"Caddy rejected the reload, {path.name} was left as it is: {error}")
    return redirect("/", "ok", f"{path.name} now opens in the form.")


@app.get("/groups")
def groups_page(request: Request):
    current = the_host()
    members = [route_group(item["route"]) for item in list_routes(current)]
    return page(request, "groups.html", groups=[(name, members.count(name)) for name in load_groups(current)])


def taken(name: str, groups: list[str]) -> bool:
    return name.lower() in (group.lower() for group in groups)


@app.post("/groups")
def group_add(name: str = Form("")):
    current = pick_host()
    name = name.strip()
    if current is None or not GROUP_RE.fullmatch(name):
        return redirect("/groups", "error", GROUP_HINT)
    if taken(name, load_groups(current)):
        return redirect("/groups", "error", f"A group {name} already exists.")
    change_groups(lambda groups: [*groups, name])
    return redirect("/groups", "ok", f"{name} was added. Pick it in the form of a route.")


@app.post("/groups/rename")
def group_rename(old: str = Form(""), new: str = Form("")):
    current = pick_host()
    new = new.strip()
    groups = load_groups(current) if current else []
    if old not in groups:
        return redirect("/groups", "error", "This group does not exist.")
    if not GROUP_RE.fullmatch(new):
        return redirect("/groups", "error", GROUP_HINT)
    if taken(new, [group for group in groups if group != old]):
        return redirect("/groups", "error", f"A group {new} already exists.")
    try:
        error = regroup(current, old, new)
    except Conflict:
        return redirect("/groups", "warn", CHANGED_MEANWHILE)
    if error:
        return redirect("/groups", "error", f"Caddy rejected the reload, nothing was changed: {error}")
    change_groups(lambda groups: [new if group == old else group for group in [*groups, old]])
    return redirect("/groups", "ok", f"{old} is now {new}.")


@app.post("/groups/delete")
def group_delete(name: str = Form("")):
    current = pick_host()
    if current is None or name not in load_groups(current):
        return redirect("/groups", "error", "This group does not exist.")
    try:
        error = regroup(current, name, "")
    except Conflict:
        return redirect("/groups", "warn", CHANGED_MEANWHILE)
    if error:
        return redirect("/groups", "error", f"Caddy rejected the reload, nothing was changed: {error}")
    change_groups(lambda groups: [group for group in groups if group != name])
    return redirect("/groups", "ok", f"{name} was removed. Its routes are kept, without a group.")


@app.api_route("/error/{code}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def error_page(request: Request, code: str, design: str = ""):
    """The page for an error, sent with its status code. Open to everybody, and to every
    method: Caddy passes the failed request on as it came."""
    # Only the errors Caddy is told to hand over, not any status somebody asks for by address.
    if code not in ERROR_PAGES:
        return Response(status_code=404)
    stored = load_errors()
    own = stored["texts"].get(code, {})
    title, text = own.get("title") or ERROR_PAGES[code][0], own.get("text") or ERROR_PAGES[code][1]
    status = int(code) if code.isdigit() else PAGE_STATUS[code]
    # Only an account that is logged in picks the design in the address: that is the preview.
    chosen = design if request.state.me and design else stored["designs"].get(code)
    if chosen not in ERROR_DESIGNS:
        chosen = "caddyman"
    # Caddy keeps the name the visitor asked for. It is shown, so it has to look like a name.
    name = request.headers.get("host", "").split(":")[0].lower()
    context = {"code": str(status), "title": title, "text": text, "host": name if HOSTNAME_RE.match(name) else ""}
    return templates.TemplateResponse(request, f"errors/{chosen}.html", context, status_code=status, headers={"Cache-Control": "no-store"})


def catch_all_state(host: dict) -> str:
    """'on', 'off' when its block is commented out, 'taken' when the file is somebody else's, else ''."""
    path = route_path(host, CATCH_ALL)
    if not path.exists():
        return ""
    route = read_route(path, host)
    if not route or route["type"] != "error_page":
        return "taken"
    return "off" if route.get("off") else "on"


def error_pages_view(request: Request, code: str = ""):
    current = the_host()
    stored = load_errors()
    context = {"code": code, "pages": ERROR_PAGES, "meanings": ERROR_MEANINGS, "designs": ERROR_DESIGNS, "chosen": stored["designs"], "disabled": stored["disabled"], "texts": stored["texts"], "limits": ERROR_TEXT_LIMITS, "upstream": caddyman_upstream(current, request), "settings_url": host_settings_url()}
    if not code:
        routes = [item["route"] for item in list_routes(current) if item["route"]]
        context.update(catch_all=catch_all_state(current), users=sum(1 for route in routes if route.get("errors")))
        # The address to hand to a DNS blocker. A page that came through Caddy was asked for under a
        # name that leads to Caddy; one that came straight to this port only tells where Caddyman
        # is, which is Caddy's machine when the two sit next to each other.
        name, port = asked_host(request)
        if port != int(OWN_PORT) or current.get("storage") != "managed":
            context["caddy_ip"] = next((address for address in sorted(resolve_addresses(name)) if re.fullmatch(r"[0-9.]+", address) and not address.startswith("127.")), "")
    return page(request, "error_pages.html", **context)


@app.get("/error-pages")
def error_pages(request: Request):
    return error_pages_view(request)


def move_caddyman_upstream(current: dict, upstream: str) -> tuple[str, str]:
    """Where Caddy finds Caddyman. The address stands in every route that shows error pages."""
    changes = {}
    stamps = route_stamps(current)
    for item in list_routes(current):
        route = item["route"]
        if route and route["type"] == "error_page":
            route = {**route, "upstream": upstream}
        elif route and (route.get("errors") or isinstance(route.get("off"), str)):
            route = {**route, **{key: upstream for key in ("errors", "off") if isinstance(route.get(key), str)}}
        else:
            continue
        changes[item["path"]] = render_route(route, current)
    try:
        error = apply_route(current, changes, "error pages", upstream, expect={path: stamps.get(path) for path in changes}) if changes else None
    except Conflict:
        return "warn", CHANGED_MEANWHILE
    if error:
        return "error", f"Caddy rejected the reload, the address was not changed: {error}"
    write_json(ERRORS_FILE, {**load_errors(), "upstream": upstream})
    return "ok", "Saved." + (f" {len(changes)} route files now use the new address." if changes else "")


@app.post("/error-pages/disabled")
def error_pages_disabled(request: Request, mode: str = Form("")):
    """What a route shows while it is switched off. Rewrites the routes that are off right now."""
    current = the_host()
    mode = "maintenance" if mode == "maintenance" else ""
    write_json(ERRORS_FILE, {**load_errors(), "disabled": mode})
    value = off_value(current)
    stamps, changes = route_stamps(current), {}
    for item in list_routes(current):
        route = item["route"]
        if route and route.get("off") and route["type"] != "error_page" and route["off"] != value:
            changes[item["path"]] = render_route({**route, "off": value}, current)
    try:
        error = apply_route(current, changes, "error pages", "switched off routes", expect={path: stamps.get(path) for path in changes}) if changes else None
    except Conflict:
        return redirect("/error-pages", "warn", CHANGED_MEANWHILE)
    if error:
        return redirect("/error-pages", "error", f"Caddy rejected the reload, the routes were left as they are: {error}")
    said = "show the maintenance page" if mode else "are no longer answered"
    return redirect("/error-pages", "ok", f"Switched off routes {said}." + (f" {len(changes)} route files were rewritten." if changes else ""))


@app.post("/error-pages/catch-all")
def error_pages_catch_all(request: Request, on: str = Form("")):
    """The route for every name no other route knows. A file like the others, but not in the route list."""
    current = the_host()
    path = route_path(current, CATCH_ALL)
    # What was looked at is what gets replaced: a file put there in between is not overwritten.
    mtime, state = file_mtime(path), catch_all_state(current)
    if state == "taken":
        return redirect("/error-pages", "error", f"{path.name} exists and was not written here. Rename or delete it first.")
    route = {"type": "error_page", "host": "*", "port": "", "tls": "none", "upstream": caddyman_upstream(current), "page": "blocked"}
    error = None
    try:
        if on or state:
            error = apply_route(current, {path: render_route(route, current) if on else None}, "create" if on else "delete", CATCH_ALL, expect=(path, mtime))
    except Conflict:
        return redirect("/error-pages", "warn", CHANGED_MEANWHILE)
    if error:
        return redirect("/error-pages", "error", f"Caddy rejected the reload, nothing was changed: {error}")
    return redirect("/error-pages", "ok", "Every unknown name now gets the Blocked page." if on else "Unknown names are no longer answered.")


@app.get("/error-pages/{code}")
def error_design(request: Request, code: str):
    if code not in ERROR_PAGES:
        return redirect("/error-pages", "error", "There is no page for this error.")
    return error_pages_view(request, code)


@app.post("/error-pages/{code}")
def error_design_save(code: str, design: str = Form(""), everywhere: str = Form(""), title: str = Form(""), text: str = Form("")):
    if code not in ERROR_PAGES or design not in ERROR_DESIGNS:
        return redirect("/error-pages", "error", "Unknown error or design.")
    stored = load_errors()
    designs = dict.fromkeys(ERROR_PAGES, design) if everywhere else {**stored["designs"], code: design}
    # Empty fields bring back the wording Caddyman ships with.
    texts = error_texts({**stored["texts"], code: {"title": title, "text": text}})
    write_json(ERRORS_FILE, {**stored, "designs": designs, "texts": texts})
    return redirect(f"/error-pages/{code}", "ok", f"Every error now shows {ERROR_DESIGNS[design]}." if everywhere else f"{ERROR_PAGES[code][0]} now shows {ERROR_DESIGNS[design]}.")


def host_settings_url() -> str:
    """Caddyman manages one Caddy: its settings if it is set up, the setup dialog if not."""
    host = pick_host()
    return f"/hosts/{host['id']}/edit" if host else "/hosts/new"


@app.get("/hosts")
def hosts_list():
    return RedirectResponse(host_settings_url(), status_code=303)


@app.get("/hosts/new")
def host_new(request: Request):
    if load_hosts():
        return RedirectResponse(host_settings_url(), status_code=303)
    return page(request, "host_form.html", host={**HOST_DEFAULTS, "storage": "mounted"}, first=True)


@app.get("/hosts/{host_id}/edit")
def host_edit(request: Request, host_id: str):
    host = next((item for item in load_hosts() if item["id"] == host_id), None)
    if host is None:
        return RedirectResponse("/hosts", status_code=303)
    host = {"storage": "mounted", **host}
    if host["storage"] == "managed":
        try:
            host["form_base"] = Path(host["caddyfile"]).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            host["form_base"] = ""
    # The field shows a CA only when somebody put it there; one Caddyman fetched stays on the status page.
    host["form_ca"] = host.get("admin_ca", "") if host.get("admin_ca_pasted") else ""
    host["form_reach"] = caddyman_upstream(host, request)
    return page(request, "host_form.html", host=host, route_count=len(list_routes(host)))


@app.post("/hosts/new")
@app.post("/hosts/{host_id}/edit")
async def host_save(request: Request, host_id: str | None = None):
    hosts = load_hosts()
    host = await host_from_form(request)
    existing = next((item for item in hosts if item["id"] == host_id), None)
    # There is no field for it any more. One set before stays, for the names of the route files.
    host["domain_suffix"] = existing.get("domain_suffix", "") if existing else ""
    # A second host cannot be added, and an id that is not the one host is not edited.
    if existing is None and (host_id is not None or hosts):
        return RedirectResponse("/hosts", status_code=303)
    # Routes live in different places per layout, so it is fixed once the host exists.
    host["storage"] = existing.get("storage", "mounted") if existing else host["storage"] or "mounted"
    password, base, pasted_ca, reach = host.pop("form_password"), host.pop("form_base"), host.pop("form_ca"), host.pop("form_reach")
    error = None if host["storage"] in STORAGES else "Unknown layout."
    if existing and reach and not valid_upstream(reach):
        error = "Where Caddy reaches Caddyman has to look like host:port or http://host:port."
    error = error or host_problem(host) or (ca_problem(pasted_ca) if pasted_ca else None)
    if not error and host["storage"] == "managed" and not base:
        error = "This layout needs the base Caddyfile: global options, snippets and the site that exposes the admin API."
    if not error and host["admin_user"]:
        if password:
            host["admin_password_enc"] = seal(password)
        elif existing and (existing.get("admin_user"), existing.get("admin_url")) == (host["admin_user"], host["admin_url"]) and existing.get("admin_password_enc"):
            host["admin_password_enc"] = existing["admin_password_enc"]
        else:
            # The stored one belongs to the address it was entered for and is not sent to another.
            error = "The admin API login needs a password. It is not kept for another login or address."
    if error:
        context = {**host, "id": host_id, "form_base": base, "form_ca": pasted_ca, "form_reach": reach}
        return page(request, "host_form.html", status_code=400, error=error, host=context)
    host = with_paths({"id": host_id or secrets.token_hex(4), **host})
    if pasted_ca:
        # Entered by hand: nothing is fetched, so nobody on the wire has a say in it.
        host["admin_ca"], host["admin_ca_pasted"] = pasted_ca, "1"
    else:
        # A CA that was pasted before and is now removed is not what gets remembered next.
        previous = existing.get("admin_ca", "") if existing and not existing.get("admin_ca_pasted") else ""
        # A login that was kept only goes to a server that shows the CA remembered for it. Typing
        # the password again is the way to trust a new CA at the same address.
        known = previous if not password else ""
        if known:
            asked = {**host, "admin_ca": known}
        elif password:
            asked = host
        else:
            # Kept, and no CA to check the server against: the login is not sent along.
            asked = {**host, "admin_user": ""}
        if admin_ca := remember_admin_ca(asked, previous):
            host["admin_ca"] = admin_ca
    if host["storage"] == "managed":
        # The one base Caddyfile this tool writes: its own copy, which Caddy never reads from disk.
        Path(host["sites_dir"]).mkdir(parents=True, exist_ok=True)
        write_private(Path(host["caddyfile"]), base + "\n")
    # Before the host is rewritten without them: keep the root CA switches an older version stored in it.
    save_settings()
    save_hosts([host if item["id"] == host["id"] else item for item in hosts] if existing else [*hosts, host])
    if existing and reach and reach != caddyman_upstream(host):
        kind, message = move_caddyman_upstream(host, reach)
        if kind != "ok":
            return redirect(f"/hosts/{host['id']}/edit", kind, message)
    # Only the first setup goes on to the status page, to show what Caddy still lacks.
    if existing:
        return redirect(f"/hosts/{host['id']}/edit", "ok", "Saved.")
    return RedirectResponse("/status", status_code=303)


@app.post("/hosts/{host_id}/delete")
def host_delete(host_id: str):
    hosts = load_hosts()
    save_hosts([item for item in hosts if item["id"] != host_id])
    for item in hosts:
        if item["id"] == host_id and item.get("storage") == "managed":
            # Its base Caddyfile and routes live here and nowhere else Caddyman would look again:
            # the next Caddy gets a new id. The question before disconnecting says so.
            shutil.rmtree(managed_dir(item["id"]), ignore_errors=True)
    return RedirectResponse("/hosts/new", status_code=303)


@app.post("/hosts/{host_id}/push")
def host_push(host_id: str):
    host = next((item for item in load_hosts() if item["id"] == host_id), None)
    if host is None:
        return RedirectResponse("/hosts", status_code=303)
    with WRITE_LOCK:
        error = caddy_load(host)
        PROBE_CACHE.clear()
        audit(host, "-", "reload", error)
    if error:
        alert("alert_reload", "Caddy rejected a reload", f"{CURRENT_USER.get()} pressed Reload Caddy. Caddy did not take it:\n\n{error}", right="routes")
        return redirect(f"/status#host-{host_id}", "error", f"Caddy rejected the configuration: {error}")
    return redirect(f"/status#host-{host_id}", "ok", "Caddy now runs the configuration from Caddyman.")


PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL)


def fetch_root_ca(host: dict, first: bool = False) -> tuple[str, str, bool]:
    """Root certificates as PEM, where they came from, and whether that is Caddy's own CA.

    Raises ValueError with a message for the page when nothing usable comes back. first is
    the fetch while the settings are saved, the one moment a login goes out unchecked.
    """
    internal = not host["root_ca_url"]
    source = f"{host['admin_url']}/pki/ca/local" if internal else host["root_ca_url"]
    try:
        # Not verified while no CA is known: this is the download of the very certificate that
        # would be needed to verify it. The fingerprint on the page is what gets compared instead.
        # Once a CA is remembered for the admin API, its login only goes to a server that shows it.
        verify = admin_verify(host) if internal and host.get("admin_ca") else False
        # An https admin API whose CA was never remembered gets no login from a page view:
        # anybody can open /trust, and each time the password would go to whoever answers.
        unchecked = host["admin_url"].startswith("https://") and not host.get("admin_ca")
        response = httpx.get(source, timeout=ADMIN_TIMEOUT, verify=verify, auth=admin_auth(host) if internal and (first or not unchecked) else None)
        text = response.json().get("root_certificate", "") if internal else response.text
    except (httpx.HTTPError, ValueError, AttributeError) as error:
        raise ValueError(f"{source} did not answer with a certificate: {said(error)}") from None
    certificates = PEM_RE.findall(text) if isinstance(text, str) else []
    if response.status_code != 200 or not certificates:
        raise ValueError(f"{source} did not answer with a certificate (HTTP {response.status_code}).")
    # Caddy's own CA always comes along (Max, 15.10.2026): a route on "Caddy internal CA" needs it
    # too. Not on the first fetch, which checks only the source being saved; missing, it is left out.
    if not internal and not first:
        try:
            own, own_source, _ = fetch_root_ca({**host, "root_ca_url": ""})
            certificates += [one for one in PEM_RE.findall(own) if one not in certificates]
            source = f"{source} and {own_source}"
        except ValueError:
            pass
    return "\n".join(certificates) + "\n", source, internal


def fingerprints(pem: str) -> list[dict]:
    result = []
    for certificate in PEM_RE.findall(pem):
        try:
            der = ssl.PEM_cert_to_DER_cert(certificate)
        except ValueError:
            raise ValueError("The source returned something that is not a certificate.") from None
        pairs = lambda digest: ":".join(digest[i : i + 2] for i in range(0, len(digest), 2)).upper()  # noqa: E731
        sha256 = hashlib.sha256(der).hexdigest()
        entry = {"sha256": pairs(sha256), "sha1": pairs(hashlib.sha1(der).hexdigest())}
        # 48 bits: short enough to say on the phone, too long to hit with a forged certificate by trying.
        entry["check_code"] = " ".join(sha256[i : i + 4].upper() for i in (0, 4, 8))
        try:
            parsed = x509.load_der_x509_certificate(der)
            entry.update(subject=display_name(parsed.subject), expires=f"{parsed.not_valid_after_utc:%Y-%m-%d}")
        except ValueError:
            pass
        result.append(entry)
    return result


ROOT_CA_SECONDS = 60
ROOT_CA_CACHE: dict[str, tuple[float, tuple | ValueError]] = {}


def public_root_ca(host: dict) -> tuple[str, str, bool]:
    """fetch_root_ca for the pages without a login: anyone can call those, so the source is asked once a minute at most."""
    cached = ROOT_CA_CACHE.get(host["id"])
    if not cached or cached[0] < time.monotonic():
        try:
            result = fetch_root_ca(host)
        except ValueError as error:
            result = error
        cached = ROOT_CA_CACHE[host["id"]] = (time.monotonic() + ROOT_CA_SECONDS, result)
    if isinstance(cached[1], ValueError):
        raise cached[1]
    return cached[1]


def ca_context(host: dict, fetch=fetch_root_ca, cert: int = 1) -> dict:
    """What the Root CA pages show. cert picks one certificate when the source hands out several."""
    context = {"host": host}
    try:
        pem, context["source"], context["internal"] = fetch(host)
        context["fingerprints"] = fingerprints(pem)
        certs = []
        for number, (one, print_) in enumerate(zip(PEM_RE.findall(pem), context["fingerprints"]), 1):
            der = base64.b64encode(ssl.PEM_cert_to_DER_cert(one)).decode()
            certs.append({"number": number, "subject": print_.get("subject", ""), "check_code": print_["check_code"], "der_base64": der})
        # Windows, iPhone and Android take only the first certificate out of a file, so with several
        # each one gets its own download, check code and command. With one, nothing carries a number.
        many = len(certs) > 1
        chosen = certs[cert - 1] if 1 <= cert <= len(certs) else certs[0]
        context.update(
            certs=certs,
            cert=chosen,
            many=many,
            file_name=f"root-ca-{chosen['number']}.crt" if many else "root-ca.crt",
            pick=f"cert={chosen['number']}" if many else "",
        )
    except ValueError as error:
        context["error"] = str(error)
    return context


@app.get("/ca")
def ca_page(request: Request, cert: int = 1):
    current = the_host()
    # Whether /trust is open decides what the page tells the admin to pass on.
    return page(request, "ca.html", open_page=flag("public_ca"), **ca_context(current, cert=cert))


@app.get("/trust")
def trust_page(request: Request, cert: int = 1):
    current = pick_host()
    if current is None:
        return Response(status_code=404)
    context = ca_context(current, public_root_ca, cert)
    return page(request, "ca.html", public=True, status_code=503 if "error" in context else 200, **context)


def certificate_download(pem: str, cert: int | None) -> Response:
    """Everything the source handed out, or the one certificate asked for by its number."""
    certificates = PEM_RE.findall(pem)
    if cert is None:
        body, name = pem, "root-ca.crt"
    elif 1 <= cert <= len(certificates):
        body, name = certificates[cert - 1] + "\n", f"root-ca-{cert}.crt"
    else:
        return Response(status_code=404)
    headers = {"Content-Disposition": f'attachment; filename="{name}"'}
    return Response(body, media_type="application/x-x509-ca-cert", headers=headers)


@app.get("/root-ca.crt")
def root_ca_public(cert: int | None = None):
    current = pick_host()
    if current is None:
        return Response(status_code=404)
    try:
        pem, _, _ = public_root_ca(current)
        fingerprints(pem)
    except ValueError:
        # No details here: the message names the admin API.
        return Response("The certificate is not available right now.", status_code=503, media_type="text/plain")
    return certificate_download(pem, cert)


@app.get("/ca/root-ca.crt")
def ca_download(cert: int | None = None):
    current = the_host()
    try:
        pem, _, _ = fetch_root_ca(current)
        fingerprints(pem)
    except ValueError as error:
        return Response(str(error), status_code=502, media_type="text/plain")
    return certificate_download(pem, cert)


# The archive travels through the confirmation page as a form field, so it has to
# stay small. Route files are a few hundred bytes each; switch to a temp file if this ever pinches.
BACKUP_MAX_BYTES = 512 * 1024
BACKUP_MAX_UNPACKED = 5 * 1024 * 1024
BACKUP_MAX_FILES = 2000
BACKUP_README = """Caddyman backup
Created: {created} UTC
Caddyman version: {version}

sites/         one file per route. This is what a restore writes back.
groups.json    the names of the route groups. A restore adds the ones that are missing.
Caddyfile      the base Caddyfile, as a copy for reference. Caddyman never writes it.
hosts.json     where Caddy is reachable. Only used when restoring into an empty install.
settings.json  the switches and the time zone under Settings, General. Only used when restoring into an empty install.
mail.json      the mail settings without the password. Only used when restoring into an empty install.
errors.json    the design and own wording chosen for each error page, and the address Caddy fetches them from if it was changed.
               Only used when restoring into an empty install.

NOT IN HERE: the root CA.
It lives in the volume of your CA (for step-ca: the volume mounted at /home/step),
not with Caddy and not with Caddyman. Back that volume up separately. It matters more
than this file: routes are retyped in an hour, but a lost root has to be imported on
every device again.

NOT IN HERE: the accounts and every password.
Password hashes and the keys of two-factor logins would turn this file into something
to lock away. To keep those too, back up the data volume of Caddyman (/data).
"""


def build_backup(host: dict) -> bytes:
    buffer = io.BytesIO()
    created = datetime.now(timezone.utc).strftime(STAMP)
    # Field by field, so nothing that is ever added to a host ends up in a backup by accident.
    # The remembered CA of the admin API is a public certificate; logins and passwords stay out.
    keys = ("id", *HOST_DEFAULTS, "storage", "admin_ca", "admin_ca_pasted")
    hosts = [{key: item.get(key, HOST_DEFAULTS.get(key, "")) for key in keys} for item in load_hosts()]
    mail = load_mail()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("README.txt", BACKUP_README.format(created=created, version=VERSION))
        archive.writestr("backup.json", json.dumps({"created": created, "version": VERSION, "host_id": host["id"]}))
        archive.writestr("hosts.json", json.dumps(hosts, indent=2))
        # The switches and the time zone. "Only over HTTPS" stays out: restored without its route, it would lock everybody out.
        settings = load_settings()
        archive.writestr("settings.json", json.dumps({key: settings.get(key, "") for key in (*SETTING_DEFAULTS, "time_zone")}, indent=2))
        archive.writestr("mail.json", json.dumps({key: mail[key] for key in MAIL_DEFAULTS}, indent=2))
        archive.writestr("groups.json", json.dumps(load_groups(host), indent=2))
        # The designs, and where Caddy finds Caddyman if somebody changed that: new routes need it again.
        errors = load_errors()
        there = {"upstream": errors["upstream"]} if errors["upstream"] else {}
        archive.writestr("errors.json", json.dumps({"designs": errors["designs"], "texts": errors["texts"], "disabled": errors["disabled"], **there}, indent=2))
        try:
            archive.writestr("Caddyfile", Path(host["caddyfile"]).read_bytes())
        except OSError:
            pass
        for path in sorted(Path(host["sites_dir"]).glob("*.caddy")):
            archive.writestr(f"sites/{path.name}", path.read_bytes())
    return buffer.getvalue()


def read_backup(data: bytes) -> dict:
    """Routes, hosts and metadata of an uploaded archive. Raises ValueError with a message.

    Nothing is ever extracted by its path: members are read into memory and only names
    that pass the route name check are kept, so an archive cannot write outside sites/.
    """
    if len(data) > BACKUP_MAX_BYTES:
        raise ValueError(f"The archive is larger than {BACKUP_MAX_BYTES // 1024} KB.")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        members = archive.infolist()
        if len(members) > BACKUP_MAX_FILES or sum(item.file_size for item in members) > BACKUP_MAX_UNPACKED:
            raise ValueError("The archive unpacks to more than a backup ever holds.")
        if any(item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) for item in members):
            raise ValueError("This is not a readable Caddyman backup.")

        def read(item: zipfile.ZipInfo) -> bytes:
            # Never more than the archive says: a member that unpacks to more fails its checksum
            # instead of filling the memory first.
            with archive.open(item) as member:
                return member.read(item.file_size)

        routes, ignored, extra = {}, [], {}
        for item in members:
            name = item.filename[len("sites/") : -len(".caddy")]
            if item.filename == f"sites/{name}.caddy" and ROUTE_NAME_RE.match(name) and ".." not in name:
                routes[name] = read(item).decode("utf-8")
            elif item.filename in ("hosts.json", "backup.json", "settings.json", "mail.json", "groups.json", "errors.json"):
                extra[item.filename] = json.loads(read(item))
            elif item.filename == "Caddyfile":
                extra["Caddyfile"] = read(item).decode("utf-8")
            elif item.filename != "README.txt":
                ignored.append(item.filename)
    except (zipfile.BadZipFile, zlib.error, UnicodeDecodeError, json.JSONDecodeError, RuntimeError, NotImplementedError):
        raise ValueError("This is not a readable Caddyman backup.") from None
    hosts = []
    saved = extra.get("hosts.json")
    for item in saved if isinstance(saved, list) else []:
        if not isinstance(item, dict):
            continue
        host = {key: str(item.get(key, default)).strip() for key, default in HOST_DEFAULTS.items()}
        host["storage"] = item.get("storage") if item.get("storage") in STORAGES else "mounted"
        if host_problem(host) is None:
            host_id = str(item.get("id", ""))
            host_id = host_id if re.fullmatch(r"[0-9a-f]{8}", host_id) else secrets.token_hex(4)
            admin_ca = "\n".join(PEM_RE.findall(str(item.get("admin_ca", ""))))
            # Held to what the settings form takes: text that only looks like a certificate
            # would later break every page that builds a TLS context from it.
            if not admin_ca or ca_problem(admin_ca):
                admin_ca = ""
            kept = {"admin_ca": admin_ca, **({"admin_ca_pasted": "1"} if item.get("admin_ca_pasted") else {})} if admin_ca else {}
            hosts.append(with_paths({"id": host_id, **host, **kept}))
    meta = extra.get("backup.json")
    # Everything below is held to what the forms of the interface would accept.
    stored = extra.get("settings.json") if isinstance(extra.get("settings.json"), dict) else {}
    # Switches; the days before a certificate alert are the one number among them.
    settings = {key: "1" if stored.get(key) else "" for key in SETTING_DEFAULTS if key in stored and key != "alert_cert_days"}
    if find_zone(stored.get("time_zone")):
        settings["time_zone"] = stored["time_zone"]
    days = str(stored.get("alert_cert_days", ""))
    if is_number(days) and 1 <= int(days) <= 90:
        settings["alert_cert_days"] = days
    mail = extra.get("mail.json")
    mail = {key: str(mail.get(key, default)) for key, default in MAIL_DEFAULTS.items()} if isinstance(mail, dict) else {}
    groups = extra.get("groups.json")
    groups = [name for name in groups if isinstance(name, str) and GROUP_RE.fullmatch(name)] if isinstance(groups, list) else []
    errors = extra.get("errors.json")
    designs = errors.get("designs") if isinstance(errors, dict) else None
    designs = {code: design for code, design in designs.items() if code in ERROR_PAGES and design in ERROR_DESIGNS} if isinstance(designs, dict) else {}
    there = errors.get("upstream") if isinstance(errors, dict) else None
    there = {"upstream": there} if valid_upstream(there) else {}
    texts = error_texts(errors.get("texts")) if isinstance(errors, dict) else {}
    disabled = {"disabled": "maintenance"} if isinstance(errors, dict) and errors.get("disabled") == "maintenance" else {}
    return {
        "routes": routes,
        "hosts": hosts,
        "meta": meta if isinstance(meta, dict) else {},
        "ignored": ignored,
        "caddyfile": extra.get("Caddyfile", ""),
        "settings": settings,
        "mail": mail if mail and mail["host"] and mail_problem(mail) is None else {},
        "groups": groups,
        "errors": {"designs": designs, "texts": texts, **disabled, **there} if designs or texts or disabled or there else {},
    }


def backup_plan(backup: dict, host: dict | None) -> list[dict]:
    """What a restore would do with each route of the archive."""
    plan = []
    for name, content in sorted(backup["routes"].items()):
        path = route_path(host, name) if host else None
        try:
            current = path.read_text(encoding="utf-8") if path and path.exists() else None
        except (OSError, UnicodeDecodeError):
            current = ""
        state = "new" if current is None else "unchanged" if current == content else "overwrite"
        plan.append({"name": name, "state": state, "path": path, "content": content})
    return plan


@app.get("/backup")
def backup_page(request: Request):
    return page(request, "backup.html", host=pick_host())


@app.get("/backup/download")
def backup_download():
    current = the_host()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    headers = {"Content-Disposition": f'attachment; filename="caddyman-{stamp}.zip"'}
    return Response(build_backup(current), media_type="application/zip", headers=headers)


@app.post("/backup/import")
async def backup_restore(request: Request):
    current = pick_host()

    def refuse(error: str, status_code: int = 400):
        return page(request, "backup.html", status_code=status_code, host=current, error=error)

    # The context manager closes the uploaded temp file again.
    async with request.form() as form:
        confirmed = "payload" in form
        payload = str(form.get("payload", ""))
        upload = form.get("archive")
        uploaded = await upload.read(BACKUP_MAX_BYTES + 1) if hasattr(upload, "read") else b""
    try:
        data = base64.b64decode(payload, validate=True) if confirmed else uploaded
        backup = read_backup(data)
    except (ValueError, binascii.Error) as error:
        return refuse(str(error))
    # Into an empty install the hosts come back too; otherwise the routes go to the chosen host.
    fresh = current is None
    target = current
    if fresh and not {"caddy", "general", "smtp"} <= set(request.state.me["permissions"]):
        # The connection to Caddy, the switches and the mail settings decide who gets in and where
        # reset links go. The right to restore routes alone must not be enough to set them.
        return refuse("No Caddy is set up yet. Importing its connection from an archive needs the right to change the settings.", 403)
    if fresh:
        target = next((item for item in backup["hosts"] if item["id"] == backup["meta"].get("host_id")), None)
        target = target or (backup["hosts"][0] if backup["hosts"] else None)
    if target is None:
        return refuse("Add a Caddy host first: this archive has no usable host settings to import the routes into.")
    if fresh and target["storage"] == "managed" and not backup["caddyfile"].strip():
        # Pushed with an empty base, the routes alone would replace Caddy's whole configuration.
        return refuse("This archive has no base Caddyfile, which the layout of its Caddy needs. Set the Caddy up under Settings first, then import the routes.")
    plan = backup_plan(backup, target)
    # The switches and the mail settings come back only into an empty install.
    rights = request.state.me["permissions"]
    with_settings = fresh
    # Like on the page for it: the mail settings take the right to manage users as well.
    with_mail = fresh and "users" in rights
    # Alerts and error pages each have a right of their own; without it they stay as they are.
    with_errors = fresh and "errors" in rights
    if "alerts" not in rights:
        backup["settings"] = {key: value for key, value in backup["settings"].items() if key not in ALERT_DEFAULTS}
    new_groups = [name for name in backup["groups"] if not taken(name, stored_groups())]
    also = [
        *([f"{len(new_groups)} route groups"] if new_groups else []),
        *(["the switches under Settings, General"] if with_settings and backup["settings"] else []),
        *(["the mail settings, without the password"] if with_mail and backup["mail"] else []),
        *(["the designs of the error pages"] if with_errors and backup["errors"] else []),
    ]
    if not confirmed:
        payload = base64.b64encode(data).decode()
        context = {"plan": plan, "target": target, "fresh": fresh, "ignored": backup["ignored"], "payload": payload, "also": also}
        return page(request, "backup.html", host=current, **context)
    if any(item["path"] is None for item in plan):
        return refuse("A route name in the archive is not usable.")
    if fresh and target["storage"] == "managed":
        # A managed host keeps its base Caddyfile here, so this copy is restored with it. The reload
        # below needs it; left behind after a rejected restore it is a file nobody reads.
        Path(target["sites_dir"]).mkdir(parents=True, exist_ok=True)
        write_private(Path(target["caddyfile"]), backup["caddyfile"])
    changes = {item["path"]: item["content"] for item in plan if item["state"] != "unchanged"}
    # One reload for all files: either the whole backup is live afterwards or none of it.
    if changes and (error := apply_route(target, changes, "import", f"{len(changes)} routes")):
        back = "/backup" if fresh else "/"
        return redirect(back, "error", f"Caddy rejected the imported routes, nothing was changed: {error}")
    # Everything else only now, so a rejected restore leaves the install as it was.
    if fresh:
        save_hosts([target])
    if with_settings and backup["settings"]:
        save_settings(**backup["settings"])
    if with_mail and backup["mail"]:
        write_json(MAIL_FILE, backup["mail"])
    if with_errors and backup["errors"]:
        write_json(ERRORS_FILE, backup["errors"])
    if new_groups:
        change_groups(lambda groups: [*groups, *new_groups])
    if not changes:
        return redirect("/", "ok", "Everything in the archive is already in place.")
    return redirect("/", "ok", f"{len(changes)} routes imported and live.")


LOG_SNIPPET = (
    "{\n\tlog caddyman {\n\t\toutput file /var/log/caddy/caddy.log {\n\t\t\troll_size 10MiB\n"
    "\t\t\troll_keep 3\n\t\t}\n\t\tformat json\n\t\texclude http.log.access\n\t}\n}"
)
# The exclude keeps the requests of routes with an access log out of this file: they have their own.
# For a Caddy elsewhere: its log is served by the same site that guards the admin API.
LOG_REMOTE_SNIPPET = (
    "admin.home.example {\n\tbasic_auth {\n\t\tcaddyman <bcrypt hash>\n\t}\n"
    "\thandle_path /caddyman-logs/* {\n\t\troot * /var/log/caddy\n\t\tfile_server browse\n\t}\n"
    "\thandle {\n\t\treverse_proxy localhost:2019 {\n\t\t\theader_up Host {upstream_hostport}\n\t\t}\n\t}\n}"
)
# Where Caddy's log directory is mounted in this container. Found there, the Logs page just works.
LOG_DIR = Path(os.getenv("CADDYMAN_LOG_DIR", "/var/log/caddy"))
LOG_REMOTE_DIR, LOG_REMOTE_FILE = "/caddyman-logs", "caddy.log"
# A packed log of a Caddy elsewhere is fetched whole; rotated at 10 MiB, it is far below this.
LOG_REMOTE_PACKED_MAX = 16 * 1024 * 1024
# The end of a file is where the answer is; a log of any size costs the same to show.
LOG_TAIL_BYTES = 512 * 1024
LOG_UNPACK_MAX = 64 * 1024 * 1024
LOG_SHOWN = 300
LOG_LEVELS = ("debug", "info", "warn", "error")
# A link from a reset or invitation mail carries its token in the address, and an access log
# keeps addresses. Whoever may read logs is not meant to pick up a way into an account there.
LINK_TOKEN_RE = re.compile(r"(/reset\?token=)[A-Za-z0-9._~%-]+")


def log_name(name: str) -> bool:
    """A log Caddy wrote, or one it packed when rotating."""
    return name.endswith((".log", ".log.gz"))


def local_log_files() -> list[Path]:
    """The log files directly in the mounted log directory, newest first. Caddy packs the ones it rotated away."""
    try:
        files = [path for path in LOG_DIR.iterdir() if log_name(path.name) and path.is_file()]
        return sorted(files, key=file_mtime, reverse=True)
    except OSError:
        return []


def window_lines(data: bytes, start: int) -> tuple[list[str], int]:
    """The whole lines in a piece of a log that begins at byte start, and where the piece before it ends.

    A piece from the middle of a file opens with the rest of a line. That line is left to the
    older piece, which therefore ends right behind it. 0 says there is nothing older.
    """
    older = 0
    if start:
        cut = data.find(b"\n") + 1
        older, data = start + cut, data[cut:] if cut else b""
    return data.decode("utf-8", errors="replace").splitlines(), older


def unpacked_window(packed, end: int) -> tuple[bytes, int]:
    """The last LOG_TAIL_BYTES before byte end of a packed log (0: before its end), and where they begin.

    A packed file cannot be read from its end: it is unpacked in passing and only the wanted
    part is kept. Caddy rolls at 10 MiB by default; the limit is for a file that is something else.
    """
    tail, read, stop = b"", 0, min(end or LOG_UNPACK_MAX, LOG_UNPACK_MAX)
    with gzip.open(packed, "rb") as handle:
        while read < stop and (chunk := handle.read(min(1024 * 1024, stop - read))):
            read += len(chunk)
            tail = (tail + chunk)[-LOG_TAIL_BYTES:]
    return tail, read - len(tail)


def read_log_tail(path: Path, end: int = 0) -> tuple[list[str], int]:
    """Lines from the end of a log file, or from before byte end, and where the piece before them ends."""
    try:
        if path.name.endswith(".gz"):
            data, start = unpacked_window(path, end)
        else:
            with open(path, "rb") as handle:
                size = handle.seek(0, os.SEEK_END)
                stop = min(end, size) if end else size
                start = max(0, stop - LOG_TAIL_BYTES)
                handle.seek(start)
                data = handle.read(stop - start)
    except (OSError, EOFError, zlib.error):
        return [], 0
    return window_lines(data, start)


def remote_log_names(host: dict) -> list[str]:
    """The logs a Caddy elsewhere offers, newest first. Without a listing there is only the current one."""
    try:
        response = admin_get(host, f"{LOG_REMOTE_DIR}/", headers={"Accept": "application/json"})
        listed = response.json() if response.status_code == 200 else []
        files = [item for item in listed if not item.get("is_dir") and log_name(str(item.get("name", "")))]
        names = [str(item["name"]) for item in sorted(files, key=lambda item: str(item.get("mod_time", "")), reverse=True)]
    except (httpx.HTTPError, ValueError, AttributeError, TypeError):
        names = []
    # A site set up before the listing existed serves the file but not the directory.
    return [name for name in names if "/" not in name] or [LOG_REMOTE_FILE]


def read_remote_log(host: dict, name: str, end: int) -> tuple[list[str], int] | None:
    """Like read_log_tail, over the network. None when the file could not be had at all."""
    packed = name.endswith(".gz")
    if packed:
        # Cannot be cut on the way: fetched whole, up to a limit, and unpacked here.
        wanted = f"bytes=0-{LOG_REMOTE_PACKED_MAX - 1}"
    elif end:
        wanted = f"bytes={max(0, end - LOG_TAIL_BYTES)}-{end - 1}"
    else:
        wanted = f"bytes=-{LOG_TAIL_BYTES}"
    try:
        response = admin_get(host, f"{LOG_REMOTE_DIR}/{quote(name)}", headers={"Range": wanted})
    except httpx.HTTPError:
        return None
    if response.status_code not in (200, 206):
        return None
    content = response.content
    if packed:
        try:
            return window_lines(*unpacked_window(io.BytesIO(content), end))
        except (OSError, EOFError, zlib.error):
            return [], 0
    # Where the piece begins is in the answer: "bytes 1000-1999/5000". A server that ignores
    # the range sends everything, which begins at 0.
    begins = re.match(r"bytes (\d+)-", str(response.headers.get("content-range", ""))) if response.status_code == 206 else None
    start = int(begins.group(1)) if begins else 0
    if len(content) > LOG_TAIL_BYTES:
        start, content = start + len(content) - LOG_TAIL_BYTES, content[-LOG_TAIL_BYTES:]
    return window_lines(content, start)


def load_log(host: dict, wanted: str, end: int = 0) -> tuple[list[str], str, list[str], int]:
    """The available log names, the one that was read, its lines, and where the piece before them ends.

    A Caddy on this machine is read from the mounted directory. A Caddy elsewhere is asked
    over the address and login that already reach its admin API. Either way only a name
    from the listing is ever opened, so the parameter cannot point anywhere else.
    """
    if host.get("storage") != "managed":
        files = local_log_files()
        chosen = next((path for path in files if path.name == wanted), files[0] if files else None)
        lines, older = read_log_tail(chosen, end) if chosen else ([], 0)
        return [path.name for path in files], chosen.name if chosen else "", lines, older
    names = remote_log_names(host)
    chosen = wanted if wanted in names else names[0]
    found = read_remote_log(host, chosen, end)
    if found is None and names == [LOG_REMOTE_FILE]:
        return [], "", [], 0  # the site does not serve the log yet: the page explains the setup
    return names, chosen, *(found or ([], 0))


def parse_log_line(line: str, zone: ZoneInfo | None = None) -> dict:
    """One line of Caddy's JSON log as columns. Anything else is shown as it is."""
    try:
        entry = json.loads(line)
        stamp = entry.pop("ts", "")
        if isinstance(stamp, (int, float)):
            stamp = datetime.fromtimestamp(stamp, zone or time_zone()).strftime(STAMP)
        level = str(entry.pop("level", "")).lower()
        logger, message = str(entry.pop("logger", "")), str(entry.pop("msg", ""))
        asked = entry.get("request")
        if logger.startswith("http.log.access") and isinstance(asked, dict):
            # A request, told in one line instead of a screen of JSON.
            message = f"{asked.get('method', '')} {asked.get('uri', '')} - {entry.get('status', '')}"
            took = entry.get("duration")
            parts = [str(asked.get("host", "")), f"from {asked.get('remote_ip', '')}", f"{entry.get('size', 0)} bytes"]
            extra = ", ".join(parts) + (f", {took:.3f} s" if isinstance(took, (int, float)) else "")
        else:
            extra = json.dumps(entry, ensure_ascii=False) if entry else ""
        return {"time": str(stamp), "level": level, "logger": logger, "msg": message, "extra": extra}
    except (ValueError, AttributeError, TypeError, OverflowError, OSError):
        return {"time": "", "level": "", "logger": "", "msg": line, "extra": ""}


@app.get("/logs")
def logs_page(request: Request, file: str = "", level: str = "", q: str = "", quiet: str = "", end: int = 0):
    current = the_host()
    names, chosen, lines, older = load_log(current, file, max(0, end))
    entries = []
    needle = q.strip().lower()
    threshold = LOG_LEVELS.index(level) if level in LOG_LEVELS else 0
    zone = time_zone()
    for line in reversed(lines):
        line = LINK_TOKEN_RE.sub(r"\1[hidden]", line)
        if needle and needle not in line.lower():
            continue
        entry = parse_log_line(line, zone)
        if threshold and (entry["level"] not in LOG_LEVELS or LOG_LEVELS.index(entry["level"]) < threshold):
            continue
        # Caddyman's own polling of the admin API would otherwise bury everything else.
        # In the log of a route the requests are the point, so they stay.
        if quiet and (entry["logger"] == "admin.api" or (entry["logger"].startswith("http.log.access") and not chosen.startswith(ACCESS_LOG_PREFIX))):
            continue
        entries.append(entry)
        if len(entries) == LOG_SHOWN:
            break
    context = {"files": names, "chosen": chosen, "entries": entries, "level": level, "q": q, "quiet": quiet}
    # The way to the piece before this one, and whether this is already an older piece.
    context.update(older=older, end=max(0, end))
    snippets = {"snippet": LOG_SNIPPET, "remote_snippet": LOG_REMOTE_SNIPPET, "log_dir": str(LOG_DIR)}
    return page(request, "logs.html", host=current, shown=LOG_SHOWN, **snippets, **context)


def open_log(host: dict, wanted: str):
    """The name and an open binary handle of a whole log, unpacked, or None. Only names from the listing."""
    try:
        if host.get("storage") != "managed":
            path = next((path for path in local_log_files() if path.name == wanted), None)
            if path is None:
                return None
            handle = gzip.open(path, "rb") if path.name.endswith(".gz") else open(path, "rb")
            return path.name, handle
        if wanted not in remote_log_names(host):
            return None
        # Up to the limit for a packed file; Caddy rolls its logs far below it.
        response = admin_get(host, f"{LOG_REMOTE_DIR}/{quote(wanted)}", headers={"Range": f"bytes=0-{LOG_REMOTE_PACKED_MAX - 1}"})
        if response.status_code not in (200, 206):
            return None
        handle = io.BytesIO(response.content)
        return wanted, gzip.GzipFile(fileobj=handle) if wanted.endswith(".gz") else handle
    except (OSError, httpx.HTTPError):
        return None


@app.get("/logs/download")
def logs_download(file: str = ""):
    """One log as text in the columns of the page, oldest first, with the same links hidden."""
    opened = open_log(the_host(), file)
    if opened is None:
        return redirect("/logs", "error", "This log could not be read.")
    name, handle = opened
    zone = time_zone()

    def lines():
        read = 0
        with handle:
            try:
                for raw in handle:
                    read += len(raw)
                    if read > LOG_UNPACK_MAX:
                        break
                    line = LINK_TOKEN_RE.sub(r"\1[hidden]", raw.decode("utf-8", errors="replace").rstrip("\r\n"))
                    entry = parse_log_line(line, zone)
                    columns = (entry["time"], entry["level"].upper() or "-", entry["logger"], entry["msg"], entry["extra"])
                    yield ("\t".join(column.replace("\t", " ") for column in columns).rstrip("\t") + "\n").encode()
            except (OSError, EOFError, zlib.error):
                return

    filename = name.removesuffix(".gz")
    return StreamingResponse(lines(), media_type="text/plain; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{filename}"'})


# The status page is open to every account, and its checks ask Caddy, the CA and the admin API
# with Caddyman's own login. Kept for a moment, so reloading the page does not multiply them.
STATUS_SECONDS = 10


def kept_preflight(host: dict) -> list[dict]:
    key = ("preflight", host["id"])
    kept = PROBE_CACHE.get(key)
    if not kept or kept[0] < time.monotonic():
        kept = PROBE_CACHE[key] = (time.monotonic() + STATUS_SECONDS, preflight(host))
    return list(kept[1])


@app.get("/status")
def status(request: Request):
    hosts = [{**host, "checks": kept_preflight(host)} for host in load_hosts()]
    way = arrived(request)
    has_route, address = own_route_address(hosts[0]) if hosts else (False, "")
    if hosts and way != "plain":
        # Only said when the page did come in over HTTPS: then it is either fine or one variable away from it.
        caddy = client_address(request)
        hosts[0]["checks"].append({
            "label": "HTTPS in front of Caddyman is recognised",
            "ok": way == "https",
            "detail": "" if way == "https" else f"{caddy} says HTTPS, but is not the Caddy from the settings",
            "hint": "Caddyman believes the Caddy it manages "
            f"({', '.join(sorted(caddy_addresses())) or 'no address found for it'}); this page came through something "
            "else. To trust it too, add its address to the .env file and start the container again. Only if "
            "nothing but your proxy reaches Caddyman from that address, so not for the gateway of a Docker network:",
            "block": f"CADDYMAN_FORWARDED_ALLOW_IPS={caddy}",
        })
    context = {"no_https": bool(hosts) and way == "plain", "has_own_route": has_route, "own_address": address}
    return page(request, "status.html", hosts=hosts, **context)


@app.get("/caddyfile")
def caddyfile_page(request: Request):
    """The base Caddyfile, to read. Right "caddy": its snippets can hold logins and API tokens."""
    current = the_host()
    try:
        text, error = Path(current["caddyfile"]).read_text(encoding="utf-8", errors="replace"), ""
    except OSError as problem:
        text, error = "", f"It could not be read: {problem.strerror or problem}."
    return page(request, "caddyfile.html", host=current, text=text, error=error)


@app.get("/changes")
def changes(request: Request):
    """Who changed which route, and what Caddy said to it. Open to every account, like the status."""
    zone = time_zone()
    # What Caddy said to a rejected reload can quote from a route file: only for who may open those.
    full = "routes" in request.state.me["permissions"]
    said_by_caddy = lambda result: result if full or result == "ok" else "rejected"  # noqa: E731
    entries = [{**entry, "time": local_time(entry["time"], zone), "result": said_by_caddy(entry["result"])} for entry in read_audit()]
    return page(request, "changes.html", audit=entries)


# What comes through the Caddy this tool manages is believed without further setup: that it
# was HTTPS, and which address the visitor has. The first decides whether the session cookie
# is marked Secure, the second what the login limit counts against. Caddy writes both headers
# itself and does not pass on what a visitor sent, so its address is the thing to check.
CADDY_ADDRESSES = {"until": 0.0, "found": frozenset(), "busy": False}
CADDY_ADDRESS_SECONDS = 60


def resolve_addresses(hostname: str) -> set[str]:
    try:
        return {info[4][0] for info in socket.getaddrinfo(hostname, None)}
    except OSError:
        return set()


def caddy_addresses() -> frozenset[str]:
    """The addresses behind the name in the admin URL: where requests from the managed Caddy come from.

    Looked up again every minute in the background, so a slow DNS never holds a request.
    Only the very first look, and the one after the settings changed, waits a moment.
    """
    if looking := look_up_caddy():
        wait([looking], timeout=1)
    return CADDY_ADDRESSES["found"]


def look_up_caddy():
    """Starts a look for caddy_addresses when one is due. What to wait for when nothing was found before, else None."""
    state = CADDY_ADDRESSES
    if state["until"] < time.monotonic() and not state["busy"]:
        state["busy"] = True

        def refresh() -> None:
            try:
                hosts = load_hosts()
                name = urlsplit(hosts[0]["admin_url"]).hostname if hosts else None
                state["found"] = frozenset(resolve_addresses(name)) if name else frozenset()
                state["until"] = time.monotonic() + CADDY_ADDRESS_SECONDS
            finally:
                state["busy"] = False

        first = state["until"] == 0
        looking = PROBES.submit(refresh)
        return looking if first else None
    return None


# Alerts: mailed to every account that asks for them in its profile. The watcher looks every
# WATCH_SECONDS; something that is down is only told after WATCH_AFTER looks in a row, and
# told again when it is back. Kept in memory: a restart forgets what was already said.
WATCH_SECONDS = 300
WATCH_AFTER = 2
CERT_WATCH_SECONDS = 6 * 3600
WATCH_STATE: dict = {}
ALERT_SENT: dict = {}
WATCHER = {"started": False}


def alert(setting: str, subject: str, body: str, key: str = "", every: int = 0, right: str = "") -> bool:
    """Mail an alert if it is switched on, mail works and somebody wants it. key with every: at most once per every seconds.
    right: only to accounts that may see what the mail says."""
    if not flag(setting) or not mail_ready():
        return False
    now = time.monotonic()
    if key and every and ALERT_SENT.get(key, -every) > now - every:
        return False
    receivers = [user["email"] for user in load_users() if user.get("alerts") and user.get("email") and (not right or right in user["permissions"])]
    if not receivers:
        return False
    if key:
        ALERT_SENT[key] = now

    def send() -> None:
        for receiver in receivers:
            send_mail(receiver, f"Caddyman: {subject}", body + "\n\nSwitch alerts off in your profile in Caddyman.")

    threading.Thread(target=send, daemon=True).start()
    return True


def watched(key: str, ok: bool, setting: str, down: tuple[str, str], up: tuple[str, str]) -> None:
    """Count looks in a row that found something down; tell when it has been down a while, and when it is back."""
    failures = WATCH_STATE.get(key, 0)
    if ok:
        if failures >= WATCH_AFTER:
            alert(setting, *up)
        WATCH_STATE.pop(key, None)
        return
    WATCH_STATE[key] = failures + 1
    if failures + 1 == WATCH_AFTER:
        alert(setting, *down)


def watch_once() -> None:
    """One look at everything an alert can be about."""
    host = pick_host()
    if host is None or not mail_ready():
        return
    try:
        admin_ok = admin_get(host, "/config/").status_code == 200
    except httpx.HTTPError:
        admin_ok = False
    minutes = WATCH_SECONDS * WATCH_AFTER // 60
    watched("admin", admin_ok, "alert_admin",
            ("Caddy's admin API does not answer", f"{host['admin_url']} has not answered for {minutes} minutes. Changes to routes cannot be made."),
            ("Caddy's admin API answers again", f"{host['admin_url']} answers again."))
    routes = [item["route"] for item in list_routes(host) if item["route"] and not item["route"].get("off")]
    # Whether the services behind the routes answer is left to a monitor like Uptime Kuma (Max, 15.10.2026).
    now = time.monotonic()
    if flag("alert_cert") and WATCH_STATE.get("certs", -CERT_WATCH_SECONDS) <= now - CERT_WATCH_SECONDS:
        WATCH_STATE["certs"] = now
        days = int(load_settings()["alert_cert_days"] or 14)
        names = [(route, name) for route in routes if route["tls"] != "none" and "*" not in route["host"]
                 for name in (route["host"], *route.get("aliases", []))]
        found = PROBES.map(lambda pair: certificate_status(host, {**pair[0], "host": pair[1]}), names)
        for (route, name), status in zip(names, found):
            expires = status and status.get("expires")
            if expires and expires - datetime.now(timezone.utc) < timedelta(days=days):
                alert("alert_cert", f"The certificate of {name} ends in {time_left(expires)}",
                      f"{name} is served with a certificate that ends {expires:%Y-%m-%d %H:%M} UTC, issued by {status['issuer']}. "
                      "Caddy renews on its own; when it does not, its log says why.",
                      key=f"cert:{name}", every=24 * 3600)


def start_watcher() -> None:
    """The watcher runs in the background for the life of the process, once."""
    if WATCHER["started"]:
        return
    WATCHER["started"] = True

    def loop() -> None:
        while True:
            time.sleep(WATCH_SECONDS)
            try:
                watch_once()
            except Exception as error:  # a broken look must not end the watching
                print(f"Alert watcher: {error!r}", flush=True)

    threading.Thread(target=loop, daemon=True, name="watcher").start()


class TrustCaddy:
    """Takes scheme and visitor address from the forwarded headers when the request comes from the managed Caddy."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        client = scope.get("client")
        # Waited for without holding every other request: this runs on the event loop.
        if scope["type"] == "http" and client and (looking := look_up_caddy()):
            await asyncio.wait([asyncio.wrap_future(looking)], timeout=1)
        if scope["type"] == "http" and client and client[0] in CADDY_ADDRESSES["found"]:
            headers = {name: value.decode("latin-1") for name, value in scope["headers"]}
            scheme = headers.get(b"x-forwarded-proto", "").strip().lower()
            if scheme in ("http", "https"):
                scope["scheme"] = scheme
            # The last entry is the address Caddy itself saw; anything before it came from further out.
            visitor = headers.get(b"x-forwarded-for", "").split(",")[-1].strip()
            try:
                # Only ever an address: it is what the login limit counts against and what the status page shows.
                scope["client"] = (str(ipaddress.ip_address(visitor)), 0)
            except ValueError:
                pass
        await self.app(scope, receive, send)


# Added last, so it runs first: everything else then sees the request as the visitor sent it.
app.add_middleware(TrustCaddy)
