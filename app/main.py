"""Caddyman - a web interface for Caddy routes."""

import base64
import binascii
import contextvars
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import smtplib
import socket
import ssl
import struct
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from email.message import EmailMessage
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote, urlsplit

import bcrypt
import httpx
import segno
from cryptography import x509
from cryptography.fernet import Fernet, InvalidToken
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, Form, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer

VERSION = "0.9.0"
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
FLASH_COOKIE = "caddyman_flash"
# For installs where nobody gets to read the container log.
ENV_SETUP_TOKEN = os.getenv("CADDYMAN_SETUP_TOKEN", "").strip()
OWN_PORT = os.getenv("CADDYMAN_PORT", "5052")
# Whoever knows the token becomes admin, so a chosen one must not be guessable.
MIN_SETUP_TOKEN_CHARS = 12

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
# Encrypts the admin API passwords in hosts.json. Lose the key and they have to be typed in again.
VAULT = Fernet(base64.urlsafe_b64encode(hashlib.sha256(f"vault:{SECRET_KEY}".encode()).digest()))

# Set at startup while no admin exists, cleared once setup is done.
SETUP_TOKEN: str | None = None

# In memory and never pruned, one entry per failing address. Fine for a
# LAN tool with one worker; move to a bounded store if it is ever exposed publicly.
LOGIN_FAILS: dict[str, list[float]] = {}  # address -> [fail count, locked until]


# One checkbox per area. Seeing the route list, the status page and the own profile needs none.
PERMISSIONS = {
    "routes": "Change routes and reload Caddy",
    "ca": "Root CA page",
    "backup": "Backup and restore",
    "logs": "Logs",
    "settings": "Settings: Caddy, root CA, mail, security",
    "users": "Manage users",
}
USERS_LOCK = threading.Lock()
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+$")
# Who is acting, for the change log. Set per request by the middleware.
CURRENT_USER: contextvars.ContextVar[str] = contextvars.ContextVar("user", default="-")


def load_users() -> list[dict]:
    try:
        data = json.loads(AUTH_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    if isinstance(data, dict):
        # The file of the single admin from before there were users: that account keeps every right.
        return [{**data, "permissions": list(PERMISSIONS)}]
    return data


def save_users(users: list[dict]) -> None:
    write_private(AUTH_FILE, json.dumps(users, indent=2))


def find_user(users: list[dict], username: str) -> dict | None:
    return next((user for user in users if user["username"] == username), None)


def update_user(username: str, **fields) -> None:
    """Read, change and write under one lock, so two requests cannot lose each other's change.

    A field set to None is removed.
    """
    with USERS_LOCK:
        users = load_users()
        if user := find_user(users, username):
            user.update(fields)
            for key in [key for key, value in fields.items() if value is None]:
                user.pop(key, None)
            save_users(users)


def user_problem(user: dict, others: list[dict]) -> str | None:
    """What is wrong with the name fields of a user, checked against all other accounts."""
    name, email = user["username"], user.get("email", "")
    if not name or len(name) > 64 or name != name.strip() or not name.isprintable():
        return "The username needs 1 to 64 characters."
    if any(other["username"] == name for other in others):
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


def locked_seconds(address: str) -> int:
    until = LOGIN_FAILS.get(address, [0, 0.0])[1]
    return max(0, round(until - time.monotonic()))


def record_fail(address: str) -> None:
    entry = LOGIN_FAILS.setdefault(address, [0, 0.0])
    entry[0] += 1
    if entry[0] >= MAX_LOGIN_FAILS:
        entry[0] = 0
        entry[1] = time.monotonic() + LOCK_SECONDS


def session_value(user: dict) -> list[str]:
    # The end of the password hash rides along: a changed password ends every session of that account.
    return [user["username"], user["password_hash"][-8:]]


def signed_user(signer: URLSafeTimedSerializer, value: str | None, users: list[dict], max_age: int) -> dict | None:
    """The account a signed cookie or link stands for, if it is still good for that account."""
    try:
        name, stamp = signer.loads(value or "", max_age=max_age)
    except (BadSignature, ValueError, TypeError):
        return None
    user = find_user(users, name)
    return user if user and session_value(user)[1] == stamp else None


def session_user(request: Request, users: list[dict]) -> dict | None:
    return signed_user(SESSIONS, request.cookies.get(SESSION_COOKIE), users, SESSION_SECONDS)


def start_session(response: RedirectResponse, request: Request, user: dict) -> RedirectResponse:
    response.set_cookie(
        SESSION_COOKIE,
        SESSIONS.dumps(session_value(user)),
        max_age=SESSION_SECONDS,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
    )
    return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    global SETUP_TOKEN
    if not load_users():
        port = OWN_PORT
        if setup_token_problem():
            # No fallback to a random token: whoever set one cannot read this log.
            SETUP_TOKEN = None
            print(f"Setup is blocked: {setup_token_problem()}", flush=True)
        else:
            SETUP_TOKEN = ENV_SETUP_TOKEN or secrets.token_hex(8)
            # A token somebody chose is not repeated in the log.
            shown = "the value of CADDYMAN_SETUP_TOKEN" if ENV_SETUP_TOKEN else SETUP_TOKEN
            print(f"Setup required. Open http://<host>:{port}/setup\nToken: {shown}", flush=True)
    if not SECRET_KEY_FROM_ENV:
        print("CADDYMAN_SECRET_KEY is not set, using a generated key from the data directory.", flush=True)
    yield


app = FastAPI(title="Caddyman", version=VERSION, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")
templates.env.filters["initials"] = initials
templates.env.globals["PERMISSIONS"] = PERMISSIONS


# Open without a login: the root certificate is public by nature, and the people who
# need it are exactly those who have no account here.
PUBLIC_PATHS = {"/trust", "/root-ca.crt"}


# Switches that belong to Caddyman itself, not to the Caddy it manages. "1" or "".
SETTINGS_FILE = DATA_DIR / "settings.json"
SETTING_DEFAULTS = {"public_ca": "1", "login_ca_hint": "1", "require_2fa": ""}


def load_settings() -> dict:
    try:
        stored = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        stored = {}
    # Up to 0.9.0 the two root CA switches were part of the Caddy settings. What somebody
    # chose there still counts until it is saved here.
    hosts = load_hosts()
    old = {key: hosts[0][key] for key in ("public_ca", "login_ca_hint") if hosts and key in hosts[0]}
    return {**SETTING_DEFAULTS, **old, **stored}


def save_settings(**changes) -> None:
    write_private(SETTINGS_FILE, json.dumps({**load_settings(), **changes}, indent=2))


def flag(key: str) -> bool:
    return bool(load_settings()[key])


# The way in: logging in, the second factor and a forgotten password.
LOGIN_PATHS = {"/login", "/login/code", "/forgot", "/reset"}
# The first prefix that fits decides, so the users below /settings come before /settings itself.
AREAS = (
    ("/settings/users", "users"),
    ("/settings", "settings"),
    ("/hosts", "settings"),
    ("/routes", "routes"),
    ("/backup", "backup"),
    ("/logs", "logs"),
    ("/ca", "ca"),
)


def needed_permission(path: str) -> str | None:
    """The right a request needs. Decided here by its path, so no endpoint can forget its own check."""
    if path == "/settings":
        return None  # only forwards to the first block this account may open
    if re.fullmatch(r"/hosts/[^/]+/push", path):
        return "routes"  # "Reload Caddy" lives under /hosts but is part of working with routes
    return next((right for prefix, right in AREAS if path == prefix or path.startswith(prefix + "/")), None)


@app.middleware("http")
async def require_session(request: Request, call_next):
    path = request.url.path
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
        if path not in LOGIN_PATHS and not (path in PUBLIC_PATHS and flag("public_ca")):
            return RedirectResponse("/login", status_code=303)
    else:
        CURRENT_USER.set(me["username"])
        right = needed_permission(path)
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
            flash = SESSIONS.loads(cookie, max_age=60)
        except BadSignature:
            pass
    context = {"version": VERSION, "source_url": SOURCE_URL, "flash": flash, **context}
    response = templates.TemplateResponse(request, template, context, status_code=status_code)
    if cookie:
        response.delete_cookie(FLASH_COOKIE)
    return response


def redirect(url: str, kind: str = "", text: str = "") -> RedirectResponse:
    """Redirect after a POST; the message is shown once on the next page."""
    response = RedirectResponse(url, status_code=303)
    if text:
        response.set_cookie(FLASH_COOKIE, SESSIONS.dumps([kind, text[:500]]), max_age=60, httponly=True, samesite="lax")
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
    password: str = Form(""),
    repeat: str = Form(""),
):
    global SETUP_TOKEN
    address = client_address(request)
    username = username.strip()
    if error := setup_token_problem():
        pass
    elif wait := locked_seconds(address):
        error = f"Too many attempts. Try again in {wait} seconds."
    elif not SETUP_TOKEN or not secrets.compare_digest(token.strip().encode(), SETUP_TOKEN.encode()):
        record_fail(address)
        error = "The token does not match."
    else:
        error = user_problem({"username": username}, []) or password_problem(password, repeat)
    if error:
        return setup_page(request, status_code=400, error=error, username=username)
    # The first account may do everything, including handing out rights to the next ones.
    user = {"username": username, "realname": "", "email": "", "password_hash": hash_password(password), "permissions": list(PERMISSIONS)}
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
    if wait := locked_seconds(address):
        return login_page(request, status_code=429, error=f"Too many attempts. Try again in {wait} seconds.")
    user = find_user(load_users(), username.strip())
    # A hash is always checked, so a wrong username takes as long as a wrong password.
    password_ok = check_password(password, user["password_hash"] if user else DUMMY_HASH)
    if not (user and password_ok):
        record_fail(address)
        return login_page(request, status_code=401, error="Wrong username or password.", username=username)
    if user.get("totp"):
        # Half way in: a short-lived cookie remembers who passed the password, nothing more.
        response = RedirectResponse("/login/code", status_code=303)
        secure = request.url.scheme == "https"
        response.set_cookie(PENDING_COOKIE, PENDING.dumps(session_value(user)), max_age=PENDING_SECONDS, httponly=True, samesite="lax", secure=secure)
        return response
    LOGIN_FAILS.pop(address, None)
    return start_session(RedirectResponse("/", status_code=303), request, user)


PENDING_COOKIE = "caddyman_2fa"
PENDING_SECONDS = 300
PENDING = URLSafeTimedSerializer(SECRET_KEY, salt="2fa")
TOTP_SECONDS = 30
RECOVERY_CODES = 8


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
        return VAULT.decrypt(user.get(key, "").encode()).decode()
    except (InvalidToken, ValueError):
        # Not set, or encrypted with another secret key. A recovery code or a reset by an admin gets around that.
        return None


def recovery_digest(code: str) -> str:
    return hashlib.sha256(re.sub(r"[^0-9a-z]", "", code.lower()).encode()).hexdigest()


def second_factor_ok(user: dict, code: str) -> bool:
    """Check an app code or a recovery code. Either one works exactly once."""
    secret = totp_secret(user, "totp")
    step = totp_step(secret, code) if secret else None
    if step is not None and step > user.get("totp_last", 0):
        update_user(user["username"], totp_last=step)
        return True
    left = [digest for digest in user.get("recovery", []) if digest != recovery_digest(code)]
    if len(left) < len(user.get("recovery", [])):
        update_user(user["username"], recovery=left)
        return True
    return False


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
    if wait := locked_seconds(address):
        return page(request, "login_code.html", status_code=429, error=f"Too many attempts. Try again in {wait} seconds.")
    if not second_factor_ok(user, code):
        record_fail(address)
        return page(request, "login_code.html", status_code=401, error="This code is not valid.")
    LOGIN_FAILS.pop(address, None)
    response = start_session(RedirectResponse("/", status_code=303), request, user)
    response.delete_cookie(PENDING_COOKIE)
    return response


@app.post("/logout")
def logout():
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


def load_mail() -> dict:
    try:
        return {**MAIL_DEFAULTS, **json.loads(MAIL_FILE.read_text(encoding="utf-8"))}
    except FileNotFoundError:
        return dict(MAIL_DEFAULTS)


def mail_ready(mail: dict | None = None) -> bool:
    mail = mail or load_mail()
    return bool(mail["host"] and mail["sender"] and mail["public_url"])


def mail_problem(mail: dict) -> str | None:
    if not mail["host"]:
        return None  # an empty server switches mail off, the rest does not matter then
    if not mail["host"].isprintable() or " " in mail["host"] or len(mail["host"]) > 253:
        return "The mail server has to be a hostname or an address."
    if not mail["port"].isdigit() or not 0 < int(mail["port"]) < 65536:
        return "The port has to be a number between 1 and 65535."
    if not EMAIL_RE.match(mail["sender"]):
        return "The sender has to be an email address."
    if mail["security"] not in MAIL_SECURITY:
        return "Unknown encryption."
    if not is_http_url(mail["public_url"]) or urlsplit(mail["public_url"]).path:
        return "The address of Caddyman has to look like https://caddyman.home.example."
    return None


def send_mail(to: str, subject: str, body: str) -> str | None:
    """Send one plain-text mail. Returns the error, or None on success."""
    mail = load_mail()
    message = EmailMessage()
    message["From"], message["To"], message["Subject"] = mail["sender"], to, subject
    message.set_content(body)
    # The server's certificate is verified against the public CAs. A mail server with a
    # certificate from a private CA needs that CA in the container's trust store.
    context = ssl.create_default_context()
    try:
        password = VAULT.decrypt(mail["password_enc"].encode()).decode() if mail.get("password_enc") else ""
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
        return str(error) or type(error).__name__
    return None


def send_reset_mail(user: dict) -> None:
    link = f"{load_mail()['public_url']}/reset?token={RESETS.dumps(session_value(user))}"
    body = (
        f"Somebody asked for a new password for the Caddyman account {user['username']}.\n\n"
        f"Set one here, within the next hour:\n{link}\n\n"
        "If that was not you, ignore this mail. Nothing changes until the link is used.\n"
    )
    if error := send_mail(user["email"], "Caddyman: set a new password", body):
        print(f"Reset mail for {user['username']} was not sent: {error}", flush=True)


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
    valid = signed_user(RESETS, token, load_users(), RESET_SECONDS) is not None
    return page(request, "reset.html", status_code=200 if valid else 400, token=token, valid=valid, mail_ready=mail_ready())


@app.post("/reset")
def reset_submit(request: Request, token: str = Form(""), password: str = Form(""), repeat: str = Form("")):
    user = signed_user(RESETS, token, load_users(), RESET_SECONDS)
    if user is None:
        return page(request, "reset.html", status_code=400, token=token, valid=False, mail_ready=mail_ready())
    if error := password_problem(password, repeat):
        return page(request, "reset.html", status_code=400, token=token, valid=True, error=error)
    # The link carries the end of the old hash, so it stops working with this very change.
    update_user(user["username"], password_hash=hash_password(password))
    return redirect("/login", "ok", "The password is changed. Log in with the new one.")


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
def profile_save(request: Request, realname: str = Form(""), email: str = Form("")):
    users = load_users()
    fields = {"realname": realname.strip(), "email": email.strip()}
    others = [user for user in users if user["username"] != request.state.user]
    if error := user_problem({"username": request.state.user, **fields}, others):
        return profile_page(request, status_code=400, error=error, form=fields)
    update_user(request.state.user, **fields)
    return redirect("/profile", "ok", "Your profile is saved.")


@app.post("/profile/password")
def profile_password(request: Request, current: str = Form(""), password: str = Form(""), repeat: str = Form("")):
    me = request.state.me
    if not check_password(current, me["password_hash"]):
        return profile_page(request, status_code=400, password_error="The current password is wrong.")
    if error := password_problem(password, repeat):
        return profile_page(request, status_code=400, password_error=error)
    update_user(me["username"], password_hash=hash_password(password))
    # Every other session of this account ends with the change; this one continues.
    changed = find_user(load_users(), me["username"])
    return start_session(redirect("/profile", "ok", "The password is changed."), request, changed)


@app.post("/profile/2fa/start")
def profile_2fa_start(request: Request):
    secret = base64.b32encode(secrets.token_bytes(20)).decode()
    update_user(request.state.user, totp_pending=VAULT.encrypt(secret.encode()).decode())
    return RedirectResponse("/profile#two-factor", status_code=303)


@app.post("/profile/2fa/confirm")
def profile_2fa_confirm(request: Request, code: str = Form("")):
    me = find_user(load_users(), request.state.user)
    secret = totp_secret(me, "totp_pending")
    step = totp_step(secret, code) if secret else None
    if step is None:
        return profile_page(request, status_code=400, totp_error="This code does not fit. Check the clock of your phone and try the next one.")
    codes = [secrets.token_hex(5) for _ in range(RECOVERY_CODES)]
    update_user(me["username"], totp=me["totp_pending"], totp_pending=None, totp_last=step, recovery=[recovery_digest(code) for code in codes])
    # Shown this once and never again: only their hashes are kept.
    return profile_page(request, recovery_codes=[f"{code[:5]}-{code[5:]}" for code in codes])


@app.post("/profile/2fa/disable")
def profile_2fa_disable(request: Request, current: str = Form("")):
    me = request.state.me
    if not check_password(current, me["password_hash"]):
        return profile_page(request, status_code=400, totp_error="The password is wrong.")
    update_user(me["username"], **{key: None for key in ("totp", "totp_pending", "totp_last", "recovery") if key in me})
    return redirect("/profile", "ok", "Two-factor login is switched off.")


@app.get("/settings")
def settings_home(request: Request):
    rights = request.state.me["permissions"]
    if "settings" in rights:
        return RedirectResponse("/settings/caddy", status_code=303)
    if "users" in rights:
        return RedirectResponse("/settings/users", status_code=303)
    return page(request, "forbidden.html", status_code=403, right=PERMISSIONS["settings"])


@app.get("/settings/caddy")
def settings_caddy():
    return RedirectResponse(host_settings_url(), status_code=303)


@app.get("/settings/security")
def settings_security(request: Request):
    without = [user["username"] for user in load_users() if not user.get("totp")]
    return page(request, "settings_security.html", settings=load_settings(), without=without)


@app.post("/settings/security")
def settings_security_save(require_2fa: str = Form(""), public_ca: str = Form(""), login_ca_hint: str = Form("")):
    # Three checkboxes in one form: one that is not sent was unticked.
    save_settings(require_2fa=require_2fa and "1", public_ca=public_ca and "1", login_ca_hint=login_ca_hint and "1")
    return redirect("/settings/security", "ok", "Saved.")


@app.get("/settings/users")
def users_list(request: Request):
    return page(request, "users.html", users=load_users())


@app.get("/settings/mail")
def mail_form(request: Request):
    return page(request, "mail_form.html", mail=load_mail(), securities=MAIL_SECURITY)


@app.post("/settings/mail")
async def mail_save(request: Request):
    form = await request.form()
    stored = load_mail()
    mail = {key: str(form.get(key, "")).strip() for key in MAIL_DEFAULTS}
    mail["public_url"] = mail["public_url"].rstrip("/")
    if error := mail_problem(mail):
        return page(request, "mail_form.html", status_code=400, error=error, mail=mail, securities=MAIL_SECURITY)
    if password := str(form.get("password", "")):
        mail["password_enc"] = VAULT.encrypt(password.encode()).decode()
    elif mail["user"] and mail["user"] == stored["user"] and stored.get("password_enc"):
        mail["password_enc"] = stored["password_enc"]  # an empty field keeps the password of the same login
    write_private(MAIL_FILE, json.dumps(mail, indent=2))
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
    return page(request, "user_form.html", user={"permissions": []}, new=True)


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
        error = user_problem(user, [other for other in users if other is not existing])
        if not error and (password or not existing):
            error = password_problem(password, repeat)
        if not error and existing and existing["username"] == request.state.user and "users" not in user["permissions"]:
            # Whoever manages users keeps that right for themselves, so there is always one left.
            error = "You cannot take the right to manage users away from yourself."
        if error:
            return page(request, "user_form.html", status_code=400, error=error, user=user, new=not existing)
        if password:
            user["password_hash"] = hash_password(password)
        if existing and form.get("reset_totp"):
            for key in ("totp", "totp_pending", "totp_last", "recovery"):
                user.pop(key, None)
        save_users([user if other is existing else other for other in users] if existing else [*users, user])
    if existing and existing["username"] == request.state.user and password:
        return start_session(redirect("/settings/users", "ok", f"{user['username']} is saved."), request, user)
    return redirect("/settings/users", "ok", f"{user['username']} is saved.")


@app.post("/settings/users/{name:path}/delete")
def user_delete(request: Request, name: str):
    if name == request.state.user:
        return redirect("/settings/users", "error", "You cannot delete your own account.")
    with USERS_LOCK:
        save_users([user for user in load_users() if user["username"] != name])
    return redirect("/settings/users", "ok", f"{name} is deleted.")


HOST_DEFAULTS = {
    "admin_url": "http://caddy:2020",
    "caddyfile": "/etc/caddy/Caddyfile",
    "sites_dir": "/etc/caddy/sites",
    "tls_snippet": "",
    "root_ca_url": "",
    "domain_suffix": "",
}
HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9-]+)*$")
SNIPPET_RE = re.compile(r"^[A-Za-z0-9_-]+$")
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
    try:
        return [with_paths(host) for host in json.loads(HOSTS_FILE.read_text(encoding="utf-8"))]
    except FileNotFoundError:
        return []


def admin_auth(host: dict) -> tuple[str, str] | None:
    """Login for an admin API that sits behind basic auth. None when there is none to send."""
    if not host.get("admin_user"):
        return None
    try:
        return host["admin_user"], VAULT.decrypt(host.get("admin_password_enc", "").encode()).decode()
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
    Root CA page. A field to paste the CA into would close that gap.
    """
    if not host["admin_url"].startswith("https://"):
        return ""
    found = []
    # The own CA if one is named, and Caddy's internal one: the admin site may use either.
    for source in dict.fromkeys((host["root_ca_url"], "")):
        try:
            pem = fetch_root_ca({**host, "root_ca_url": source})[0]
            fingerprints(pem)
            found.append(pem)
        except ValueError:
            pass
    return "".join(found) or previous


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
    if not is_http_url(host["admin_url"]) or urlsplit(host["admin_url"]).path:
        return "The admin API has to look like http://caddy:2020."
    if host.get("storage") != "managed" and not (is_clean_path(host["caddyfile"]) and is_clean_path(host["sites_dir"])):
        return "Caddyfile and sites directory have to be absolute paths without '..'."
    if host.get("admin_user") and not AUTH_USER_RE.match(host["admin_user"]):
        return "The admin API username may only contain letters, digits, '.', '_', '@' and '-'."
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
    managed = host.get("storage") == "managed"
    try:
        text = Path(caddyfile).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        text = None
        if managed:
            add("Base Caddyfile is stored", False, str(error), "Edit this host and paste the base Caddyfile.", "")
        else:
            add(
                "Base Caddyfile is readable",
                False,
                str(error),
                "Mount Caddy's Caddyfile into this container at the path Caddy itself uses. In this tool's compose file:",
                f"    volumes:\n      - /opt/caddy/Caddyfile:{caddyfile}:ro",
            )
    else:
        add("Base Caddyfile is stored" if managed else "Base Caddyfile is readable", True, caddyfile)

    if text is not None:
        import_line = f"import {sites}/*.caddy"
        if managed:
            file_import = re.search(r"^\s*import\s+\S*[/*]\S*\s*$", text, re.MULTILINE)
            add(
                "Base Caddyfile imports no files",
                not file_import,
                file_import.group(0).strip() if file_import else "",
                "This Caddy runs elsewhere and cannot read files from here, so the routes are sent inline. "
                "Remove this line from the base Caddyfile of this host:",
                file_import.group(0).strip() if file_import else "",
            )
        else:
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
                snippet_exists(text, snippet),
                "",
                "Add the snippet to the base Caddyfile, with the ACME directory of your CA:",
                f"({snippet}) {{\n\ttls {{\n\t\tca https://ca.example/acme/acme/directory\n"
                "\t\tca_root /etc/caddy/root_ca.crt\n\t}\n}",
            )

    if host.get("admin_user"):
        add(
            "Admin API password is readable",
            admin_auth(host) is not None,
            "",
            "The stored password was encrypted with a different CADDYMAN_SECRET_KEY. Edit this host and enter it again.",
            "",
        )
    running = None
    try:
        response = httpx.get(f"{host['admin_url']}/config/", timeout=ADMIN_TIMEOUT, auth=admin_auth(host), verify=admin_verify(host))
        admin_ok, detail = response.status_code == 200, f"HTTP {response.status_code}"
        running = response.content if admin_ok else None
    except httpx.HTTPError as error:
        admin_ok, detail = False, str(error) or type(error).__name__
    if "CERTIFICATE_VERIFY_FAILED" in detail:
        add(
            "Admin API is reachable",
            False,
            f"{host['admin_url']} - {detail}",
            "Caddyman does not know the CA behind this certificate. Open the Caddy settings and press "
            '"Save and check": it then fetches the CA and remembers it for this address.',
            "",
        )
    elif managed:
        add(
            "Admin API is reachable",
            admin_ok,
            f"{host['admin_url']} - {detail}",
            "Caddy's admin API has no login of its own: whoever reaches it controls Caddy. Expose it through a "
            "site with basic auth like the one below, keep that site in the base Caddyfile of this host (every "
            "push replaces Caddy's whole configuration), and enter the login here. At the very least, firewall the port to this machine.",
            "admin.home.example {\n\tbasic_auth {\n\t\tcaddyman <bcrypt hash from: caddy hash-password>\n\t}\n"
            "\treverse_proxy localhost:2019 {\n\t\theader_up Host {upstream_hostport}\n\t}\n}",
        )
    else:
        add(
            "Admin API is reachable",
            admin_ok,
            f"{host['admin_url']} - {detail}",
            "The login was refused. Check username and password in the settings."
            if detail == "HTTP 401"
            else "Caddy's admin API only listens inside its own container and has no login of its own. Add this site "
            "to the base Caddyfile, restart Caddy, and enter the address (http://caddy:2020) and the login in the "
            "settings. Create the hash with: docker exec -it caddy caddy hash-password",
            ADMIN_SITE_SNIPPET,
        )
    if host.get("admin_ca"):
        # Remembered on first use, so it is shown: the codes are the ones the Root CA page gives.
        codes = [item["sha256"].replace(":", "")[:12] for item in fingerprints(host["admin_ca"])]
        add("CA of the admin API is remembered", True, "check code " + ", ".join(" ".join(code[i : i + 4] for i in (0, 4, 8)) for code in codes))
    if admin_ok:
        # The quick way in, 'admin :2019', works but leaves Caddy open to every container on its network.
        add(
            "Admin API asks for a login",
            bool(host.get("admin_user")),
            "",
            "Right now anything that reaches this address can reconfigure Caddy, including every service behind "
            "the proxy. Remove 'admin :2019' from the global options, add this site instead, and enter its "
            "address and login in the settings. Create the hash with: docker exec -it caddy caddy hash-password",
            ADMIN_SITE_SNIPPET,
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
            "Either nothing has been pushed yet, or Caddy was restarted without --resume and went back to its own "
            "file, dropping every route. Start Caddy with the command below, then use 'Reload Caddy' on this page.",
            "command: caddy run --resume --config /etc/caddy/Caddyfile --adapter caddyfile",
        )
    return checks


async def host_from_form(request: Request) -> dict:
    """The host as entered. The keys starting with 'form_' never reach hosts.json."""
    form = await request.form()
    host = {key: str(form.get(key, "")).strip() for key in (*HOST_DEFAULTS, "storage", "admin_user")}
    host["admin_url"] = host["admin_url"].rstrip("/")
    host["sites_dir"] = host["sites_dir"].rstrip("/") or "/"
    host["domain_suffix"] = host["domain_suffix"].lower().strip(".")
    host["form_password"] = str(form.get("admin_password", ""))
    host["form_base"] = str(form.get("base_caddyfile", "")).replace("\r\n", "\n").strip()
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
TLS_MODES = ("acme_ca", "default", "internal", "none")
REDIRECT_CODES = ("301", "302", "308")
# The port may be left out: Caddy then takes 443 for https:// and 80 for everything else.
UPSTREAM_RE = re.compile(r"^(https?://)?([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?)(?::([0-9]{1,5}))?$")
# Everything below ends up in a file Caddy executes, so each value is held to a
# character set that cannot open a block, start a directive or add a line.
REDIRECT_RE = re.compile(r"^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$")
STATIC_ROOT_RE = re.compile(r"^/[A-Za-z0-9._/-]*$")
AUTH_USER_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
BCRYPT_RE = re.compile(r"^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$")
ROUTE_NAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")
LOAD_TIMEOUT = 30
REACH_TIMEOUT = 2
# One writer at a time: write, reload and a possible undo must not interleave.
WRITE_LOCK = threading.Lock()


def valid_port(value: str) -> bool:
    return value.isdigit() and 1 <= int(value) <= 65535


def snippet_exists(caddyfile_text: str, snippet: str) -> bool:
    return bool(snippet and re.search(rf"^\({re.escape(snippet)}\)\s*\{{", caddyfile_text, re.MULTILINE))


def acme_ca_available(host: dict) -> bool:
    try:
        return snippet_exists(Path(host["caddyfile"]).read_text(encoding="utf-8"), host["tls_snippet"])
    except (OSError, UnicodeDecodeError):
        return False


def route_from_form(form, host: dict, previous: dict | None = None) -> tuple[dict, str | None]:
    """Normalise the form into route metadata and name the first problem, if any.

    previous is the route as it is on disk when editing; its password hash is kept
    when the form leaves the password empty. Optional keys are only added when set,
    and always in the same order, so files written before a key existed stay ours.
    """
    get = lambda key: str(form.get(key, "")).strip()  # noqa: E731
    name = get("host").lower().strip(".")
    if host["domain_suffix"] and "." not in name and name:
        name = f"{name}.{host['domain_suffix']}"
    route = {"type": get("type"), "host": name, "port": get("port"), "tls": get("tls")}
    if not HOSTNAME_RE.match(name) or ".." in name or len(name) > 253:
        return route, "The hostname may only contain lowercase letters, digits, '-' and '.'."
    if route["port"] and not valid_port(route["port"]):
        return route, "The port has to be a number between 1 and 65535."
    if route["tls"] not in TLS_MODES:
        return route, "Unknown TLS mode."
    if route["tls"] == "acme_ca" and not acme_ca_available(host):
        return route, "This host has no TLS snippet in its base Caddyfile, so 'Own ACME CA' is not available."
    if route["type"] == "reverse_proxy":
        route["upstream"] = get("upstream")
        match = UPSTREAM_RE.match(route["upstream"])
        if not match or (match.group(4) and not valid_port(match.group(4))):
            return route, "The target has to look like host, host:port or http://host:port."
        if auth_user := get("auth_user"):
            if not AUTH_USER_RE.match(auth_user):
                return route, "The basic auth username may only contain letters, digits, '.', '_', '@' and '-'."
            route["auth_user"] = auth_user
            # Not stripped: a password may start or end with a space.
            password = str(form.get("auth_password", ""))
            kept = previous.get("auth_hash", "") if previous and previous.get("auth_user") == auth_user else ""
            if password:
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
    return route, None


def render_route(route: dict, host: dict) -> str:
    """The complete file for a route. Expects metadata that passed route_from_form."""
    address = route["host"] + (f":{route['port']}" if route["port"] else "")
    lines = []
    if route["tls"] == "none":
        # Caddy has no directive that turns TLS off; an http:// address does.
        address = f"http://{address}"
    elif route["tls"] == "acme_ca":
        lines.append(f"import {host['tls_snippet']}")
    elif route["tls"] == "internal":
        lines.append("tls internal")
    if route["type"] == "reverse_proxy":
        if route.get("auth_user"):
            lines += ["basic_auth {", f"\t{route['auth_user']} {route['auth_hash']}", "}"]
        if route.get("host_header"):
            lines += [f"reverse_proxy {route['upstream']} {{", "\theader_up Host {upstream_hostport}", "}"]
        else:
            lines.append(f"reverse_proxy {route['upstream']}")
    elif route["type"] == "redirect":
        lines.append(f"redir {route['target']}{{uri}} {route['code']}")
    else:
        lines += [f"root * {route['root']}", "file_server"]
    body = "".join(f"\t{line}\n" for line in lines)
    return f"{META_PREFIX}{json.dumps(route, separators=(',', ':'))}\n{address} {{\n{body}}}\n"


def route_file_name(route: dict, host: dict) -> str:
    """File name without extension: the hostname without the host's suffix."""
    name = route["host"].removesuffix(f".{host['domain_suffix']}") if host["domain_suffix"] else route["host"]
    return name + (f"_{route['port']}" if route["port"] else "")


def route_path(host: dict, name: str) -> Path | None:
    """The file for a route name, or None when the name would leave the sites directory."""
    if not ROUTE_NAME_RE.match(name) or ".." in name:
        return None
    sites = Path(host["sites_dir"]).resolve()
    path = (sites / f"{name}.caddy").resolve()
    return path if path.parent == sites else None


def read_route(path: Path, host: dict) -> dict | None:
    """Metadata of a file this tool wrote and nobody changed since, else None."""
    try:
        content = path.read_text(encoding="utf-8")
        first = content.split("\n", 1)[0]
        if not first.startswith(META_PREFIX):
            return None
        route = json.loads(first[len(META_PREFIX):])
        # No hash, no parser: a file is ours exactly when its metadata reproduces it.
        return route if render_route(route, host) == content else None
    except (OSError, ValueError, KeyError, TypeError):
        return None


def list_routes(host: dict) -> list[dict]:
    try:
        paths = sorted(Path(host["sites_dir"]).glob("*.caddy"))
    except OSError:
        return []
    return [{"name": path.stem, "route": read_route(path, host)} for path in paths]


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
    auth = admin_auth(host)
    try:
        response = httpx.post(
            f"{host['admin_url']}/load",
            content=caddy_body(host),
            headers={"Content-Type": "text/caddyfile"},
            timeout=LOAD_TIMEOUT,
            auth=auth,
            verify=admin_verify(host),
        )
    except (OSError, httpx.HTTPError) as error:
        return str(error) or type(error).__name__
    if response.status_code == 200:
        if host.get("storage") == "managed":
            # Remembered so the status page can tell when Caddy has fallen back to another config.
            try:
                running = httpx.get(f"{host['admin_url']}/config/", timeout=ADMIN_TIMEOUT, auth=auth, verify=admin_verify(host))
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
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
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


class Conflict(Exception):
    """The file changed on disk after it was loaded into the editor."""


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
    expect: tuple[Path, int] | None = None,
) -> str | None:
    """Write the files (None deletes one), reload Caddy, undo everything on failure.

    Every write path goes through here. With expect, the change is refused when that
    file no longer has the modification time it had when it was loaded.
    """
    with WRITE_LOCK:
        if expect and file_mtime(expect[0]) != expect[1]:
            raise Conflict
        previous = {path: path.read_bytes() if path.exists() else None for path in changes}
        try:
            for path, content in changes.items():
                if content is None:
                    path.unlink()
                else:
                    path.write_bytes(content.encode())
            error = caddy_load(host)
        except OSError as os_error:
            error = str(os_error)
        if error:
            # A broken file left on disk would stop Caddy from starting the next time.
            for path, content in previous.items():
                if content is None:
                    path.unlink(missing_ok=True)
                else:
                    path.write_bytes(content)
            # If the reload only timed out, Caddy may hold the new config: bring it back in line.
            caddy_load(host)
        audit(host, label, action, error)
        return error


def adopt_route(content: str, host: dict) -> tuple[dict | None, str]:
    """Metadata for a hand-written file, or the reason it cannot be taken over.

    This is no Caddyfile parser: it accepts exactly what render_route would produce,
    give or take whitespace and line order, and refuses everything else.
    """
    lines = [line.split() for line in content.splitlines() if line.strip() and not line.startswith(META_PREFIX)]
    if len(lines) < 3 or len(lines[0]) != 2 or lines[0][1] != "{" or lines[-1] != ["}"]:
        return None, "it is not a single site block"
    address = re.match(r"^(http://)?([^:/]+)(?::([0-9]+))?$", lines[0][0])
    if not address:
        return None, "its address is not a plain hostname"
    form = {"host": address.group(2), "port": address.group(3) or "", "tls": "none" if address.group(1) else "default"}
    for tokens in lines[1:-1]:
        if tokens == ["import", host["tls_snippet"]]:
            form["tls"] = "acme_ca"
        elif tokens == ["tls", "internal"]:
            form["tls"] = "internal"
        elif tokens[0] == "reverse_proxy" and len(tokens) == 2:
            form.update(type="reverse_proxy", upstream=tokens[1])
        elif tokens[0] == "redir" and len(tokens) == 3 and tokens[1].endswith("{uri}"):
            form.update(type="redirect", target=tokens[1].removesuffix("{uri}"), code=tokens[2])
        elif tokens[:2] == ["root", "*"] and len(tokens) == 3:
            form.update(type="static", root=tokens[2])
        elif tokens != ["file_server"]:
            return None, f"it contains a line Caddyman would not write: {' '.join(tokens)}"
    if "type" not in form:
        return None, "it has no reverse_proxy, redir or root line"
    route, error = route_from_form(form, host)
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
        certificate = served_certificate(address, int(route["port"] or 443), route["host"])
    except ssl.SSLError:
        # Caddy answers the handshake with an alert as long as it has no certificate for the name.
        return {"level": "fail", "text": "No certificate", "detail": "Caddy has not obtained one yet. Its log says why."}
    except (OSError, ValueError) as error:
        return {"level": "unknown", "text": "Not checked", "detail": f"{address} is not reachable for a TLS handshake: {error}"}
    issuer = display_name(certificate.issuer)
    expires = certificate.not_valid_after_utc
    detail = f"Expires {expires:%Y-%m-%d %H:%M} UTC"
    if expires <= datetime.now(timezone.utc):
        return {"level": "fail", "text": f"Expired - {issuer}", "detail": detail}
    status = {"level": "ok", "text": f"{issuer} - {time_left(expires)} left", "detail": detail}
    if route["tls"] == "acme_ca" and CADDY_INTERNAL_ISSUER in issuer:
        # The failure that went unnoticed longest: a route quietly served from Caddy's own CA.
        status.update(level="warn", detail=f"Issued by Caddy's internal CA instead of your ACME CA. {detail}")
    return status


def route_links(route: dict | None) -> tuple[str, str]:
    """Where a click on the hostname and on the target leads. Empty where there is nothing to open."""
    if not route:
        return "", ""
    port = f":{route['port']}" if route.get("port") else ""
    site = f"{'http' if route['tls'] == 'none' else 'https'}://{route['host']}{port}"
    target = route.get("upstream") or route.get("target") or ""
    if route["type"] == "reverse_proxy" and "://" not in target:
        target = f"http://{target}"
    # Only ever a web address: the value comes from a file somebody may have edited.
    return site, target if target.startswith(("http://", "https://")) else ""


def pick_host(host_id: str | None) -> tuple[list[dict], dict | None]:
    hosts = load_hosts()
    return hosts, next((item for item in hosts if item["id"] == host_id), hosts[0] if hosts else None)


def route_form_page(request: Request, host: dict, route: dict, error: str | None = None, **context):
    context.setdefault("status_code", 400 if error else 200)
    # Hostnames and targets of the real routes, for the game hidden in this form.
    proxied = [item["route"] for item in list_routes(host) if item["route"] and item["route"]["type"] == "reverse_proxy"]
    context["game_routes"] = [[item["host"], item["upstream"]] for item in proxied]
    return page(request, "route_form.html", host=host, route=route, error=error, acme_ca=acme_ca_available(host), **context)


def existing_route(host_id: str | None, name: str) -> tuple[dict | None, Path | None]:
    """The host and the file of a route that is on disk, or a None for what is missing."""
    _, current = pick_host(host_id)
    path = route_path(current, name) if current else None
    return current, path if path and path.is_file() else None


@app.get("/")
def index(request: Request, host: str | None = None):
    hosts, current = pick_host(host)
    if current is None:
        return RedirectResponse("/hosts/new", status_code=303)
    routes = list_routes(current)
    # One handshake and one connection to the target per route on every page load,
    # nothing cached. Fine for the dozens of routes a homelab has; cache for a minute
    # if the list ever feels slow.
    proxied = lambda item: item["route"] and item["route"]["type"] == "reverse_proxy"  # noqa: E731
    with ThreadPoolExecutor(max_workers=8) as pool:
        statuses = pool.map(lambda item: certificate_status(current, item["route"]), routes)
        down = pool.map(lambda item: bool(proxied(item)) and not target_reachable(item["route"]["upstream"]), routes)
    for item, status, target_down in zip(routes, statuses, down):
        item["certificate"] = status
        item["target_down"] = target_down
        item["site"], item["link"] = route_links(item["route"])
    return page(request, "index.html", hosts=hosts, host=current, routes=routes)


@app.get("/routes/new")
def route_new(request: Request, host: str | None = None, own: bool = False):
    _, current = pick_host(host)
    if current is None:
        return RedirectResponse("/hosts/new", status_code=303)
    tls = "acme_ca" if acme_ca_available(current) else "default"
    route = {"type": "reverse_proxy", "tls": tls, "code": "308"}
    if own:
        # A Caddy next door reaches this container by name, one elsewhere by the address the browser used.
        there = request.url.hostname if current.get("storage") == "managed" else "caddyman"
        route.update(host="caddyman" if current["domain_suffix"] else "", upstream=f"{there}:{OWN_PORT}")
    return route_form_page(request, current, route)


def reached_without_https(request: Request, host: dict) -> bool:
    """True while this page came in over plain HTTP and no route points at Caddyman itself.

    The scheme alone is not enough: behind Caddy it still reads http unless
    CADDYMAN_FORWARDED_ALLOW_IPS trusts Caddy. Any route file naming this port counts,
    hand-written ones too; another service on the same port hides the hint, which is harmless.
    """
    if request.url.scheme == "https":
        return False
    try:
        return not any(f":{OWN_PORT}".encode() in path.read_bytes() for path in Path(host["sites_dir"]).glob("*.caddy"))
    except OSError:
        return True


@app.post("/routes/new")
async def route_create(request: Request, host: str | None = None):
    _, current = pick_host(host)
    if current is None:
        return RedirectResponse("/hosts/new", status_code=303)
    route, error = route_from_form(await request.form(), current)
    if error:
        return route_form_page(request, current, route, error)
    path = route_path(current, route_file_name(route, current))
    if path is None:
        return route_form_page(request, current, route, "This hostname cannot be used as a file name.")
    if path.exists():
        return route_form_page(request, current, route, f"A route file {path.name} already exists.")
    if error := apply_route(current, {path: render_route(route, current)}, "create", path.stem):
        return route_form_page(request, current, route, f"Caddy rejected the route, nothing was changed: {error}")
    url = f"/?host={current['id']}"
    if route["type"] == "reverse_proxy" and not target_reachable(route["upstream"]):
        return redirect(url, "warn", f"{route['host']} is saved, but {route['upstream']} does not answer yet.")
    return redirect(url, "ok", f"{route['host']} is live.")


@app.post("/routes/{name}/delete")
def route_delete(name: str, host: str | None = None):
    _, current = pick_host(host)
    path = route_path(current, name) if current else None
    if path is None or not path.exists():
        return redirect("/", "error", "This route does not exist.")
    url = f"/?host={current['id']}"
    if error := apply_route(current, {path: None}, "delete", path.stem):
        return redirect(url, "error", f"Caddy rejected the reload, {path.name} was kept: {error}")
    return redirect(url, "ok", f"{path.name} was removed.")


def raw_page(request: Request, host: dict, name: str, content: str, mtime: int, **context):
    adoptable = adopt_route(content, host)[0] is not None
    return page(request, "route_raw.html", host=host, name=name, content=content, mtime=mtime, adoptable=adoptable, **context)


@app.get("/routes/{name}/edit")
def route_edit(request: Request, name: str, host: str | None = None, raw: bool = False):
    current, path = existing_route(host, name)
    if path is None:
        return redirect("/", "error", "This route does not exist.")
    # Read the time first: a change between the two reads then shows up as a conflict on save.
    mtime = file_mtime(path)
    route = None if raw else read_route(path, current)
    if route:
        return route_form_page(request, current, route, name=name, mtime=mtime)
    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return redirect(f"/?host={current['id']}", "error", f"{path.name} is not UTF-8 text and cannot be edited here.")
    return raw_page(request, current, name, content, mtime)


@app.post("/routes/{name}/edit")
async def route_update(request: Request, name: str, host: str | None = None):
    current, path = existing_route(host, name)
    if path is None:
        return redirect("/", "error", "This route does not exist.")
    form = await request.form()
    mtime = int(form["mtime"]) if str(form.get("mtime", "")).isdigit() else 0
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
        error = apply_route(current, changes, "update", label, expect=(path, mtime))
    except Conflict:
        # Saving once more from this page overwrites what is on disk, knowingly.
        disk = path.read_text(encoding="utf-8", errors="replace") if path.exists() else "(the file was deleted)"
        return again(conflict={"disk": disk, "yours": content}, mtime=file_mtime(path), status_code=409)
    if error:
        return again(error=f"Caddy rejected the change, nothing was changed: {error}", status_code=400)
    url = f"/?host={current['id']}"
    if route and route["type"] == "reverse_proxy" and not target_reachable(route["upstream"]):
        return redirect(url, "warn", f"{new_path.name} is saved, but {route['upstream']} does not answer yet.")
    return redirect(url, "ok", f"{new_path.name} is saved and live.")


@app.post("/routes/{name}/adopt")
def route_adopt(name: str, host: str | None = None):
    current, path = existing_route(host, name)
    if path is None:
        return redirect("/", "error", "This route does not exist.")
    url = f"/?host={current['id']}"
    route, reason = adopt_route(path.read_text(encoding="utf-8", errors="replace"), current)
    if route is None:
        return redirect(url, "warn", f"{path.name} was left as it is: {reason}.")
    if error := apply_route(current, {path: render_route(route, current)}, "adopt", name):
        return redirect(url, "error", f"Caddy rejected the reload, {path.name} was left as it is: {error}")
    return redirect(url, "ok", f"{path.name} now opens in the form.")


def host_settings_url() -> str:
    """Caddyman manages one Caddy: its settings if it is set up, the setup dialog if not."""
    hosts = load_hosts()
    return f"/hosts/{hosts[0]['id']}/edit" if hosts else "/hosts/new"


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
    host = {**HOST_DEFAULTS, "storage": "mounted", **host}
    if host["storage"] == "managed":
        try:
            host["form_base"] = Path(host["caddyfile"]).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            host["form_base"] = ""
    return page(request, "host_form.html", host=host)


@app.post("/hosts/new")
@app.post("/hosts/{host_id}/edit")
async def host_save(request: Request, host_id: str | None = None):
    hosts = load_hosts()
    host = await host_from_form(request)
    existing = next((item for item in hosts if item["id"] == host_id), None)
    # A second host cannot be added, and an id that is not the one host is not edited.
    if existing is None and (host_id is not None or hosts):
        return RedirectResponse("/hosts", status_code=303)
    # Routes live in different places per layout, so it is fixed once the host exists.
    host["storage"] = existing.get("storage", "mounted") if existing else host["storage"] or "mounted"
    password, base = host.pop("form_password"), host.pop("form_base")
    error = None if host["storage"] in STORAGES else "Unknown layout."
    error = error or host_problem(host)
    if not error and host["storage"] == "managed" and not base:
        error = "This layout needs the base Caddyfile: global options, snippets and the site that exposes the admin API."
    if not error and host["admin_user"]:
        if password:
            host["admin_password_enc"] = VAULT.encrypt(password.encode()).decode()
        elif existing and existing.get("admin_user") == host["admin_user"] and existing.get("admin_password_enc"):
            host["admin_password_enc"] = existing["admin_password_enc"]
        else:
            error = "The admin API login needs a password."
    if error:
        context = {**host, "id": host_id, "form_base": base}
        return page(request, "host_form.html", status_code=400, error=error, host=context)
    host = with_paths({"id": host_id or secrets.token_hex(4), **host})
    if admin_ca := remember_admin_ca(host, existing.get("admin_ca", "") if existing else ""):
        host["admin_ca"] = admin_ca
    if host["storage"] == "managed":
        # The one base Caddyfile this tool writes: its own copy, which Caddy never reads from disk.
        Path(host["sites_dir"]).mkdir(parents=True, exist_ok=True)
        write_private(Path(host["caddyfile"]), base + "\n")
    # Before the host is rewritten without them: keep the root CA switches an older version stored in it.
    save_settings()
    save_hosts([host if item["id"] == host["id"] else item for item in hosts] if existing else [*hosts, host])
    return RedirectResponse("/status", status_code=303)


@app.post("/hosts/{host_id}/delete")
def host_delete(host_id: str):
    save_hosts([item for item in load_hosts() if item["id"] != host_id])
    return RedirectResponse("/hosts/new", status_code=303)


@app.post("/hosts/{host_id}/push")
def host_push(host_id: str):
    host = next((item for item in load_hosts() if item["id"] == host_id), None)
    if host is None:
        return RedirectResponse("/hosts", status_code=303)
    with WRITE_LOCK:
        error = caddy_load(host)
        audit(host, "-", "reload", error)
    if error:
        return redirect(f"/status#host-{host_id}", "error", f"Caddy rejected the configuration: {error}")
    return redirect(f"/status#host-{host_id}", "ok", "Caddy now runs the configuration from Caddyman.")


PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL)


def fetch_root_ca(host: dict) -> tuple[str, str, bool]:
    """Root certificates as PEM, where they came from, and whether that is Caddy's own CA.

    Raises ValueError with a message for the page when nothing usable comes back.
    """
    internal = not host["root_ca_url"]
    source = f"{host['admin_url']}/pki/ca/local" if internal else host["root_ca_url"]
    try:
        # Not verified on purpose: this is the download of the very certificate that would be
        # needed to verify it. The fingerprint on the page is what gets compared instead.
        response = httpx.get(source, timeout=ADMIN_TIMEOUT, verify=False, auth=admin_auth(host) if internal else None)
        text = response.json().get("root_certificate", "") if internal else response.text
    except (httpx.HTTPError, ValueError, AttributeError) as error:
        raise ValueError(f"{source} did not answer with a certificate: {error or type(error).__name__}") from None
    certificates = PEM_RE.findall(text) if isinstance(text, str) else []
    if response.status_code != 200 or not certificates:
        raise ValueError(f"{source} did not answer with a certificate (HTTP {response.status_code}).")
    return "\n".join(certificates) + "\n", source, internal


def fingerprints(pem: str) -> list[dict]:
    result = []
    for certificate in PEM_RE.findall(pem):
        try:
            der = ssl.PEM_cert_to_DER_cert(certificate)
        except ValueError:
            raise ValueError("The source returned something that is not a certificate.") from None
        pairs = lambda digest: ":".join(digest[i : i + 2] for i in range(0, len(digest), 2)).upper()  # noqa: E731
        entry = {"sha256": pairs(hashlib.sha256(der).hexdigest()), "sha1": pairs(hashlib.sha1(der).hexdigest())}
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


def ca_context(host: dict, fetch=fetch_root_ca) -> dict:
    context = {"host": host}
    try:
        pem, context["source"], context["internal"] = fetch(host)
        context["fingerprints"] = fingerprints(pem)
        # The check code and the install command cover the first certificate only.
        # A source that hands out several is still downloaded whole.
        der = ssl.PEM_cert_to_DER_cert(PEM_RE.search(pem).group(0))
        digest = hashlib.sha256(der).hexdigest().upper()
        # 48 bits: short enough to say on the phone, too long to hit with a forged certificate by trying.
        context["check_code"] = " ".join(digest[i : i + 4] for i in (0, 4, 8))
        context["der_base64"] = base64.b64encode(der).decode()
    except ValueError as error:
        context["error"] = str(error)
    return context


@app.get("/ca")
def ca_page(request: Request, host: str | None = None):
    hosts, current = pick_host(host)
    if current is None:
        return RedirectResponse("/hosts/new", status_code=303)
    return page(request, "ca.html", hosts=hosts, **ca_context(current))


@app.get("/trust")
def trust_page(request: Request):
    _, current = pick_host(None)
    if current is None:
        return Response(status_code=404)
    context = ca_context(current, public_root_ca)
    return page(request, "ca.html", public=True, status_code=503 if "error" in context else 200, **context)


@app.get("/root-ca.crt")
def root_ca_public():
    _, current = pick_host(None)
    if current is None:
        return Response(status_code=404)
    try:
        pem, _, _ = public_root_ca(current)
        fingerprints(pem)
    except ValueError:
        # No details here: the message names the admin API.
        return Response("The certificate is not available right now.", status_code=503, media_type="text/plain")
    headers = {"Content-Disposition": 'attachment; filename="root-ca.crt"'}
    return Response(pem, media_type="application/x-x509-ca-cert", headers=headers)


@app.get("/ca/root-ca.crt")
def ca_download(host: str | None = None):
    _, current = pick_host(host)
    if current is None:
        return RedirectResponse("/hosts/new", status_code=303)
    try:
        pem, _, _ = fetch_root_ca(current)
        fingerprints(pem)
    except ValueError as error:
        return Response(str(error), status_code=502, media_type="text/plain")
    headers = {"Content-Disposition": 'attachment; filename="root-ca.crt"'}
    return Response(pem, media_type="application/x-x509-ca-cert", headers=headers)


# The archive travels through the confirmation page as a form field, so it has to
# stay small. Route files are a few hundred bytes each; switch to a temp file if this ever pinches.
BACKUP_MAX_BYTES = 512 * 1024
BACKUP_MAX_UNPACKED = 5 * 1024 * 1024
BACKUP_MAX_FILES = 2000
BACKUP_README = """Caddyman backup
Created: {created} UTC
Caddyman version: {version}

sites/       one file per route. This is what a restore writes back.
Caddyfile    the base Caddyfile, as a copy for reference. Caddyman never writes it.
hosts.json   where Caddy is reachable. Only used when restoring into an empty install.

NOT IN HERE: the root CA.
It lives in the volume of your CA (for step-ca: the volume mounted at /home/step),
not with Caddy and not with Caddyman. Back that volume up separately. It matters more
than this file: routes are retyped in an hour, but a lost root has to be imported on
every device again.
"""


def build_backup(host: dict) -> bytes:
    buffer = io.BytesIO()
    created = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    # Field by field, so nothing that is ever added to a host ends up in a backup by accident.
    keys = ("id", *HOST_DEFAULTS, "storage")
    hosts = [{key: item.get(key, HOST_DEFAULTS.get(key, "")) for key in keys} for item in load_hosts()]
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("README.txt", BACKUP_README.format(created=created, version=VERSION))
        archive.writestr("backup.json", json.dumps({"created": created, "version": VERSION, "host_id": host["id"]}))
        archive.writestr("hosts.json", json.dumps(hosts, indent=2))
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
        routes, ignored, extra = {}, [], {}
        for item in members:
            name = item.filename[len("sites/") : -len(".caddy")]
            if item.filename == f"sites/{name}.caddy" and ROUTE_NAME_RE.match(name) and ".." not in name:
                routes[name] = archive.read(item).decode("utf-8")
            elif item.filename in ("hosts.json", "backup.json"):
                extra[item.filename] = json.loads(archive.read(item))
            elif item.filename == "Caddyfile":
                extra["Caddyfile"] = archive.read(item).decode("utf-8")
            elif item.filename != "README.txt":
                ignored.append(item.filename)
    except (zipfile.BadZipFile, UnicodeDecodeError, json.JSONDecodeError, RuntimeError, NotImplementedError):
        raise ValueError("This is not a readable Caddyman backup.") from None
    hosts = []
    saved = extra.get("hosts.json")
    for item in saved if isinstance(saved, list) else []:
        if not isinstance(item, dict):
            continue
        host = {key: str(item.get(key, default)) for key, default in HOST_DEFAULTS.items()}
        host["storage"] = item.get("storage") if item.get("storage") in STORAGES else "mounted"
        if host_problem(host) is None:
            host_id = str(item.get("id", ""))
            host_id = host_id if re.fullmatch(r"[0-9a-f]{8}", host_id) else secrets.token_hex(4)
            hosts.append(with_paths({"id": host_id, **host}))
    meta = extra.get("backup.json")
    return {
        "routes": routes,
        "hosts": hosts,
        "meta": meta if isinstance(meta, dict) else {},
        "ignored": ignored,
        "caddyfile": extra.get("Caddyfile", ""),
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
def backup_page(request: Request, host: str | None = None):
    hosts, current = pick_host(host)
    return page(request, "backup.html", hosts=hosts, host=current)


@app.get("/backup/download")
def backup_download(host: str | None = None):
    _, current = pick_host(host)
    if current is None:
        return RedirectResponse("/hosts/new", status_code=303)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    headers = {"Content-Disposition": f'attachment; filename="caddyman-{stamp}.zip"'}
    return Response(build_backup(current), media_type="application/zip", headers=headers)


@app.post("/backup/restore")
async def backup_restore(request: Request, host: str | None = None):
    hosts, current = pick_host(host)
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
        return page(request, "backup.html", status_code=400, hosts=hosts, host=current, error=str(error))
    # Into an empty install the hosts come back too; otherwise the routes go to the chosen host.
    fresh = not hosts
    target = current
    if fresh:
        target = next((item for item in backup["hosts"] if item["id"] == backup["meta"].get("host_id")), None)
        target = target or (backup["hosts"][0] if backup["hosts"] else None)
    if target is None:
        error = "Add a Caddy host first: this archive has no usable host settings to restore the routes into."
        return page(request, "backup.html", status_code=400, hosts=hosts, host=current, error=error)
    plan = backup_plan(backup, target)
    if not confirmed:
        payload = base64.b64encode(data).decode()
        context = {"plan": plan, "target": target, "fresh": fresh, "ignored": backup["ignored"], "payload": payload}
        return page(request, "backup.html", hosts=hosts, host=current, **context)
    if any(item["path"] is None for item in plan):
        return page(request, "backup.html", status_code=400, hosts=hosts, host=current, error="A route name in the archive is not usable.")
    if fresh:
        save_hosts([target])
        if target["storage"] == "managed":
            # A managed host keeps its base Caddyfile here, so this copy is restored with it.
            Path(target["sites_dir"]).mkdir(parents=True, exist_ok=True)
            write_private(Path(target["caddyfile"]), backup["caddyfile"])
    url = f"/?host={target['id']}"
    changes = {item["path"]: item["content"] for item in plan if item["state"] != "unchanged"}
    if not changes:
        return redirect(url, "ok", "Everything in the archive is already in place.")
    # One reload for all files: either the whole backup is live afterwards or none of it.
    if error := apply_route(target, changes, "restore", f"{len(changes)} routes"):
        return redirect(url, "error", f"Caddy rejected the restored routes, nothing was changed: {error}")
    return redirect(url, "ok", f"{len(changes)} routes restored and live.")


LOG_SNIPPET = (
    "{\n\tlog caddyman {\n\t\toutput file /var/log/caddy/caddy.log {\n\t\t\troll_size 10MiB\n"
    "\t\t\troll_keep 3\n\t\t}\n\t\tformat json\n\t}\n}"
)
# For a Caddy elsewhere: its log is served by the same site that guards the admin API.
LOG_REMOTE_SNIPPET = (
    "admin.home.example {\n\tbasic_auth {\n\t\tcaddyman <bcrypt hash>\n\t}\n"
    "\thandle_path /caddyman-logs/* {\n\t\troot * /var/log/caddy\n\t\tfile_server\n\t}\n"
    "\thandle {\n\t\treverse_proxy localhost:2019 {\n\t\t\theader_up Host {upstream_hostport}\n\t\t}\n\t}\n}"
)
# Where Caddy's log directory is mounted in this container. Found there, the Logs page just works.
LOG_DIR = Path(os.getenv("CADDYMAN_LOG_DIR", "/var/log/caddy"))
LOG_REMOTE_PATH = "/caddyman-logs/caddy.log"
# The end of a file is where the answer is; a log of any size costs the same to show.
LOG_TAIL_BYTES = 512 * 1024
LOG_SHOWN = 300
LOG_LEVELS = ("debug", "info", "warn", "error")


def local_log_files() -> list[Path]:
    """The .log files directly in the mounted log directory, newest first."""
    try:
        files = [path for path in LOG_DIR.iterdir() if path.suffix == ".log" and path.is_file()]
        return sorted(files, key=file_mtime, reverse=True)
    except OSError:
        return []


def read_log_tail(path: Path) -> list[str]:
    try:
        with open(path, "rb") as handle:
            start = max(0, handle.seek(0, os.SEEK_END) - LOG_TAIL_BYTES)
            handle.seek(start)
            lines = handle.read().decode("utf-8", errors="replace").splitlines()
    except OSError:
        return []
    # Starting in the middle of the file means the first line is only the end of one.
    return lines[1:] if start else lines


def load_log(host: dict, wanted: str) -> tuple[list[str], str, list[str]]:
    """The available log names, the one that was read, and the lines at its end.

    A Caddy on this machine is read from the mounted directory. A Caddy elsewhere is asked
    for the end of its log over the address and login that already reach its admin API.
    """
    if host.get("storage") != "managed":
        files = local_log_files()
        # Only a name from the listing is ever opened, so the parameter cannot point anywhere else.
        chosen = next((path for path in files if path.name == wanted), files[0] if files else None)
        return [path.name for path in files], chosen.name if chosen else "", read_log_tail(chosen) if chosen else []
    try:
        response = httpx.get(
            f"{host['admin_url']}{LOG_REMOTE_PATH}",
            headers={"Range": f"bytes=-{LOG_TAIL_BYTES}"},
            timeout=ADMIN_TIMEOUT,
            auth=admin_auth(host),
            verify=admin_verify(host),
        )
    except httpx.HTTPError:
        return [], "", []
    if response.status_code not in (200, 206):
        return [], "", []
    content = response.content
    # A partial answer starts in the middle of a line, unless the file was shorter than what was asked for.
    partial = response.status_code == 206 and not str(response.headers.get("content-range", "")).startswith("bytes 0-")
    if len(content) > LOG_TAIL_BYTES:
        content, partial = content[-LOG_TAIL_BYTES:], True
    lines = content.decode("utf-8", errors="replace").splitlines()
    return ["caddy.log"], "caddy.log", lines[1:] if partial else lines


def parse_log_line(line: str) -> dict:
    """One line of Caddy's JSON log as columns. Anything else is shown as it is."""
    try:
        entry = json.loads(line)
        stamp = entry.pop("ts", "")
        if isinstance(stamp, (int, float)):
            stamp = datetime.fromtimestamp(stamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        level = str(entry.pop("level", "")).lower()
        logger, message = str(entry.pop("logger", "")), str(entry.pop("msg", ""))
        extra = json.dumps(entry, ensure_ascii=False) if entry else ""
        return {"time": str(stamp), "level": level, "logger": logger, "msg": message, "extra": extra}
    except (ValueError, AttributeError, TypeError, OverflowError, OSError):
        return {"time": "", "level": "", "logger": "", "msg": line, "extra": ""}


@app.get("/logs")
def logs_page(request: Request, file: str = "", level: str = "", q: str = "", quiet: str = ""):
    _, current = pick_host(None)
    if current is None:
        return RedirectResponse("/hosts/new", status_code=303)
    names, chosen, lines = load_log(current, file)
    entries = []
    needle = q.strip().lower()
    threshold = LOG_LEVELS.index(level) if level in LOG_LEVELS else 0
    for line in reversed(lines):
        if needle and needle not in line.lower():
            continue
        entry = parse_log_line(line)
        if threshold and (entry["level"] not in LOG_LEVELS or LOG_LEVELS.index(entry["level"]) < threshold):
            continue
        # Caddyman's own polling of the admin API would otherwise bury everything else.
        if quiet and entry["logger"] in ("admin.api", "http.log.access"):
            continue
        entries.append(entry)
        if len(entries) == LOG_SHOWN:
            break
    context = {"files": names, "chosen": chosen, "entries": entries, "level": level, "q": q, "quiet": quiet}
    snippets = {"snippet": LOG_SNIPPET, "remote_snippet": LOG_REMOTE_SNIPPET, "log_dir": str(LOG_DIR)}
    return page(request, "logs.html", host=current, shown=LOG_SHOWN, **snippets, **context)


@app.get("/status")
def status(request: Request):
    hosts = [{**host, "checks": preflight(host)} for host in load_hosts()]
    no_https = bool(hosts) and reached_without_https(request, hosts[0])
    return page(request, "status.html", hosts=hosts, audit=read_audit(), no_https=no_https)
