#!/usr/bin/env python3
"""purrbrews-bootstrap: hand SSH public keys to machines, and keep them in step.

One small server, two listeners:

  client port (HTTPS, self-signed, pinned by clients)
      /bootstrap.sh            one-line installer for a new client
      /client/sync.sh          the key-sync script the installer puts on the client
      /keys/authorized_keys    the current public keys
      /files/...               optional payload (data/payload/), with SHA256SUMS
      /pin, /healthz

  admin port (HTTP, loopback by default, token login)
      /                        the admin page: keys, clients, the client command
      /api/...                 what the page talks to

Python standard library only. The one outside tool is the `openssl` command,
used once to make the TLS key. Nothing served on the client port is secret.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
def _version() -> str:
    """The release this is: the VERSION file, which the release tag must match."""
    try:
        return (HERE / "VERSION").read_text(encoding="utf-8").strip() or "dev"
    except OSError:
        return "dev"


VERSION = _version()

MAX_BODY = 64 * 1024
MAX_KEYS = 200
MAX_CLIENTS = 1000
SESSION_HOURS = 12

KEY_TYPES = (
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
)
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
ID_RE = re.compile(r"^[a-f0-9]{16,64}$")
USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
HOST_RE = re.compile(r"^(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.-]+)(:[0-9]{1,5})?$")
URL_RE = re.compile(r"^https://(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.-]+)(:[0-9]{1,5})?$")
PAYLOAD_PATH_RE = re.compile(r"^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$")


def log(msg: str) -> None:
    try:
        print(f"[bootstrap] {msg}", flush=True)
    except (OSError, ValueError):
        pass  # a closed log pipe must never take a request down with it


class BadRequest(Exception):
    """Something the caller sent is not acceptable; the message is shown to them."""


# ---------------------------------------------------------------------------
# SSH public keys
# ---------------------------------------------------------------------------
def parse_public_key(line: str) -> dict:
    """Validate one public key line and return its parts.

    Only plain keys are accepted: `type base64 [comment]`. Lines carrying
    authorized_keys options (command=, from=, ...) are refused, so the admin
    page can never be used to smuggle one onto every client.
    """
    line = line.strip()
    if not line:
        raise BadRequest("Empty key.")
    if "PRIVATE KEY" in line:
        raise BadRequest("That is a private key. Paste the .pub file instead, and treat this key as exposed.")
    if "\n" in line or "\r" in line:
        raise BadRequest("One key per line.")
    parts = line.split(None, 2)
    if len(parts) < 2 or parts[0] not in KEY_TYPES:
        raise BadRequest("Not a public key this server accepts (expected e.g. 'ssh-ed25519 AAAA... comment').")
    ktype, b64 = parts[0], parts[1]
    comment = parts[2].strip() if len(parts) > 2 else ""
    try:
        blob = base64.b64decode(b64, validate=True)
    except Exception:
        raise BadRequest("The key data is not valid base64.") from None
    # The blob starts with its own type as a length-prefixed string.
    if len(blob) < 4:
        raise BadRequest("The key data is too short.")
    (n,) = struct.unpack(">I", blob[:4])
    if blob[4 : 4 + n].decode("ascii", "replace") != ktype:
        raise BadRequest("The key type does not match the key data.")
    if ktype == "ssh-ed25519" and len(blob) != 51:
        raise BadRequest("That ed25519 key is the wrong length; it looks truncated or altered.")
    if not re.fullmatch(r"[\x20-\x7e]{0,200}", comment):
        raise BadRequest("The key comment has unusual characters or is too long.")
    fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return {"type": ktype, "data": b64, "comment": comment, "fingerprint": fp}


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
class Store:
    """Keys, clients and settings, kept in one JSON file under the data dir."""

    def __init__(self, data_dir: Path):
        self.dir = data_dir
        self.path = data_dir / "state.json"
        self.payload_dir = data_dir / "payload"
        self.lock = threading.RLock()
        self.state = {"keys": [], "clients": {}, "settings": {}}
        self._dirty_clients = False
        data_dir.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            self.state.update(json.loads(self.path.read_text(encoding="utf-8")))
        s = self.state["settings"]
        s.setdefault("sync_minutes", 60)
        s.setdefault("public_url", os.environ.get("BOOTSTRAP_PUBLIC_URL", "").rstrip("/"))
        s.setdefault("default_user", "")
        s.setdefault("payload_entry", "")
        self._import_seed()

    def _import_seed(self) -> None:
        """First start only: take keys from data/authorized_keys if it exists."""
        seed = self.dir / "authorized_keys"
        if self.state["keys"] or not seed.exists():
            return
        added = 0
        for line in seed.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            try:
                self.add_key(line, save=False)
                added += 1
            except BadRequest as e:
                log(f"seed key skipped: {e}")
        if added:
            self.save()
            log(f"imported {added} key(s) from {seed}")

    def save(self) -> None:
        with self.lock:
            tmp = self.path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(self.state, indent=2, sort_keys=True), encoding="utf-8")
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
            self._dirty_clients = False

    def flush_clients(self) -> None:
        with self.lock:
            if self._dirty_clients:
                self.save()

    # -- keys ---------------------------------------------------------------
    def add_key(self, line: str, label: str = "", save: bool = True) -> dict:
        key = parse_public_key(line)
        label = label.strip()
        if not re.fullmatch(r"[^\x00-\x1f]{0,80}", label):
            raise BadRequest("The label is too long or has control characters.")
        with self.lock:
            if any(k["fingerprint"] == key["fingerprint"] for k in self.state["keys"]):
                raise BadRequest("That key is already in the list.")
            if len(self.state["keys"]) >= MAX_KEYS:
                raise BadRequest(f"Key limit reached ({MAX_KEYS}).")
            key.update(id=secrets.token_hex(8), label=label or key["comment"], added=int(time.time()))
            self.state["keys"].append(key)
            if save:
                self.save()
        return key

    def remove_key(self, key_id: str) -> None:
        with self.lock:
            before = len(self.state["keys"])
            self.state["keys"] = [k for k in self.state["keys"] if k["id"] != key_id]
            if len(self.state["keys"]) == before:
                raise BadRequest("No such key.")
            self.save()

    def authorized_keys(self) -> bytes:
        with self.lock:
            lines = [f'{k["type"]} {k["data"]} {k["comment"]}'.rstrip() for k in self.state["keys"]]
        return ("\n".join(lines) + "\n").encode() if lines else b""

    def keys_version(self) -> str:
        return hashlib.sha256(self.authorized_keys()).hexdigest()[:16]

    # -- clients --------------------------------------------------------------
    def record_pull(self, client_id: str, name: str, user: str, ip: str, version: str) -> None:
        now = int(time.time())
        with self.lock:
            clients = self.state["clients"]
            c = clients.get(client_id)
            if c is None:
                if len(clients) >= MAX_CLIENTS:
                    return
                c = clients[client_id] = {"first_seen": now, "pulls": 0}
            c.update(name=name, user=user, ip=ip, last_seen=now, keys_version=version)
            c["pulls"] = int(c.get("pulls", 0)) + 1
            self._dirty_clients = True

    def forget_client(self, client_id: str) -> None:
        with self.lock:
            if self.state["clients"].pop(client_id, None) is None:
                raise BadRequest("No such client.")
            self.save()

    # -- settings -------------------------------------------------------------
    def update_settings(self, new: dict) -> None:
        with self.lock:
            s = dict(self.state["settings"])
            if "sync_minutes" in new:
                try:
                    m = int(new["sync_minutes"])
                except (TypeError, ValueError):
                    raise BadRequest("The sync interval must be a number of minutes.") from None
                if not 5 <= m <= 1440:
                    raise BadRequest("The sync interval must be between 5 and 1440 minutes.")
                s["sync_minutes"] = m
            if "public_url" in new:
                u = str(new["public_url"]).strip().rstrip("/")
                if u and not URL_RE.fullmatch(u):
                    raise BadRequest("The server address must look like https://host:port (no path).")
                s["public_url"] = u
            if "default_user" in new:
                u = str(new["default_user"]).strip()
                if u and not USER_RE.fullmatch(u):
                    raise BadRequest("That is not a valid user name.")
                s["default_user"] = u
            if "payload_entry" in new:
                p = str(new["payload_entry"]).strip()
                if p:
                    if not PAYLOAD_PATH_RE.fullmatch(p) or ".." in p.split("/"):
                        raise BadRequest("The payload entry must be a plain relative path.")
                    if not (self.payload_dir / p).is_file():
                        raise BadRequest("That file is not in the payload folder.")
                s["payload_entry"] = p
            self.state["settings"] = s
            self.save()

    # -- payload ----------------------------------------------------------------
    def payload_files(self) -> list[str]:
        root = self.payload_dir
        if not root.is_dir():
            return []
        out = []
        for p in sorted(root.rglob("*")):
            rel = p.relative_to(root).as_posix()
            if p.is_file() and not p.is_symlink() and PAYLOAD_PATH_RE.fullmatch(rel) and rel != "SHA256SUMS":
                out.append(rel)
        return out

    def payload_sums(self) -> bytes:
        lines = []
        for rel in self.payload_files():
            digest = hashlib.sha256((self.payload_dir / rel).read_bytes()).hexdigest()
            lines.append(f"{digest}  {rel}")
        return ("\n".join(lines) + "\n").encode() if lines else b""

    def payload_entry(self) -> str:
        entry = self.state["settings"].get("payload_entry", "")
        return entry if entry and entry in self.payload_files() else ""


# ---------------------------------------------------------------------------
# TLS key and pin
# ---------------------------------------------------------------------------
def ensure_tls(data_dir: Path) -> tuple[Path, Path, str]:
    """Create the TLS key once and return (cert, key, pin).

    The pin is what clients remember: sha256 of the public key, the form
    `curl --pinnedpubkey` takes. It survives restarts because the key is kept
    in the data dir. Delete data/certs only if you mean to re-pin every client.
    """
    certs = data_dir / "certs"
    certs.mkdir(parents=True, exist_ok=True)
    key, crt = certs / "bootstrap.key", certs / "bootstrap.crt"
    if not (key.exists() and crt.exists()):
        log("generating the TLS key and self-signed certificate (one time)")
        run = lambda *a: subprocess.run(a, check=True, capture_output=True)  # noqa: E731
        try:
            run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key))
            run("openssl", "req", "-x509", "-new", "-key", str(key), "-out", str(crt),
                "-days", "3650", "-subj", "/CN=purrbrews-bootstrap")
        except FileNotFoundError:
            sys.exit("[bootstrap] ERROR: the 'openssl' command is needed once, to create the TLS key.")
        except subprocess.CalledProcessError as e:
            sys.exit(f"[bootstrap] ERROR: openssl failed: {e.stderr.decode(errors='replace').strip()}")
        os.chmod(key, 0o600)
    pub = subprocess.run(["openssl", "x509", "-in", str(crt), "-pubkey", "-noout"],
                         check=True, capture_output=True).stdout
    der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "der"],
                         input=pub, check=True, capture_output=True).stdout
    pin = "sha256//" + base64.b64encode(hashlib.sha256(der).digest()).decode()
    return crt, key, pin


def admin_token(data_dir: Path) -> str:
    env = os.environ.get("BOOTSTRAP_ADMIN_TOKEN", "").strip()
    if env:
        if len(env) < 16:
            sys.exit("[bootstrap] ERROR: BOOTSTRAP_ADMIN_TOKEN must be at least 16 characters.")
        return env
    path = data_dir / "admin-token"
    if not path.exists():
        path.write_text(secrets.token_urlsafe(24) + "\n", encoding="utf-8")
        os.chmod(path, 0o600)
    return path.read_text(encoding="utf-8").strip()


# ---------------------------------------------------------------------------
# HTTP plumbing
# ---------------------------------------------------------------------------
class App:
    def __init__(self, data_dir: Path):
        self.store = Store(data_dir)
        self.cert, self.key, self.pin = ensure_tls(data_dir)
        self.token = admin_token(data_dir)
        self.sessions: dict[str, float] = {}
        self.sessions_lock = threading.Lock()
        self.login_failures: list[float] = []
        self.started = int(time.time())
        self.admin_hosts = {"localhost", "127.0.0.1", "[::1]"} | {
            h.strip().lower() for h in os.environ.get("BOOTSTRAP_ADMIN_HOSTS", "").split(",") if h.strip()
        }
        self.client_port = int(os.environ.get("BOOTSTRAP_PORT", "8443"))

    def base_url(self, host_header: str | None) -> str:
        """Where clients should reach this server: the configured address, or
        the Host header the request came in on (validated: it lands in a script)."""
        configured = self.store.state["settings"].get("public_url", "")
        if configured:
            return configured
        if host_header and HOST_RE.fullmatch(host_header):
            return f"https://{host_header}"
        return ""

    def guess_address(self) -> str:
        """Best guess at a LAN address, for the admin page's hint. Useless in a
        container (it would be the container's own address), so skipped there."""
        if Path("/.dockerenv").exists():
            return ""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("192.0.2.1", 9))
                return s.getsockname()[0]
        except OSError:
            return ""


class Handler(BaseHTTPRequestHandler):
    server_version = "purrbrews-bootstrap"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 30
    app: App

    def log_message(self, fmt, *args):  # quieter, one line, no client-controlled text
        pass

    def send_body(self, status: int, body: bytes, ctype: str = "text/plain; charset=utf-8", headers: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def text(self, status: int, msg: str, headers: dict | None = None):
        self.send_body(status, (msg.rstrip("\n") + "\n").encode(), headers=headers)

    def json(self, status: int, obj, headers: dict | None = None):
        self.send_body(status, json.dumps(obj).encode(), "application/json", headers)

    def read_json(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise BadRequest("Bad Content-Length.") from None
        if n > MAX_BODY:
            raise BadRequest("Request too large.")
        try:
            obj = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            raise BadRequest("The request body is not valid JSON.") from None
        if not isinstance(obj, dict):
            raise BadRequest("The request body must be a JSON object.")
        return obj


class ClientHandler(Handler):
    """The open, pinned side. Read-only: nothing here changes configuration."""

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        app, store = self.app, self.app.store
        path = self.path.split("?", 1)[0]

        if path == "/healthz":
            return self.text(200, "ok")
        if path == "/pin":
            return self.text(200, app.pin)

        if path == "/keys/authorized_keys":
            body = store.authorized_keys()
            version = store.keys_version()
            self.note_client(version)
            return self.send_body(200, body, headers={"X-Keys-Version": version, "X-Keys-Count": str(body.count(b"\n"))})

        if path == "/bootstrap.sh":
            base = app.base_url(self.headers.get("Host"))
            if not base:
                return self.text(400, "Cannot work out this server's address from the request. Set the server address on the admin page.")
            script = (HERE / "client" / "bootstrap.sh").read_text(encoding="utf-8")
            s = store.state["settings"]
            script = (script.replace("__BASE_URL__", base)
                      .replace("__SYNC_MINUTES__", str(int(s["sync_minutes"])))
                      .replace("__DEFAULT_USER__", s.get("default_user", ""))
                      .replace("__PAYLOAD_ENTRY__", store.payload_entry())
                      .replace("__HAS_PAYLOAD__", "1" if store.payload_files() else "0"))
            return self.send_body(200, script.encode())

        if path == "/client/sync.sh":
            return self.send_body(200, (HERE / "client" / "sync.sh").read_bytes())

        if path == "/files/SHA256SUMS":
            return self.send_body(200, store.payload_sums())
        if path.startswith("/files/"):
            rel = path[len("/files/"):]
            if rel in store.payload_files():  # exact match against a listing: no traversal
                return self.send_body(200, (store.payload_dir / rel).read_bytes(), "application/octet-stream")

        return self.text(404, "not found")

    def note_client(self, version: str) -> None:
        """Remember who pulled the keys. Self-reported by the client, so this is
        for visibility, not for access control: the keys are public either way."""
        h = self.headers
        ip = self.client_address[0]
        cid = h.get("X-Bootstrap-Id", "")
        name = h.get("X-Bootstrap-Client", "")
        user = h.get("X-Bootstrap-User", "")
        if not ID_RE.fullmatch(cid):
            cid, name = "addr-" + hashlib.sha256(ip.encode()).hexdigest()[:16], ""
        if not NAME_RE.fullmatch(name):
            name = ""
        if not USER_RE.fullmatch(user):
            user = ""
        self.app.store.record_pull(cid, name, user, ip, version)


class AdminHandler(Handler):
    """The configuration side: loopback by default, token login, same-site only."""

    # -- guards -------------------------------------------------------------
    def host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").lower()
        name = host.rsplit(":", 1)[0] if not host.endswith("]") else host
        return name in self.app.admin_hosts

    def session_ok(self) -> bool:
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        sid = cookie["pb_session"].value if "pb_session" in cookie else ""
        with self.app.sessions_lock:
            exp = self.app.sessions.get(sid)
            return bool(exp and exp > time.time())

    def guard(self, need_session: bool = True, writing: bool = False) -> bool:
        if not self.host_ok():
            self.text(403, "This admin page only answers to its own address. Add yours to BOOTSTRAP_ADMIN_HOSTS if that is intended.")
            return False
        if writing and self.headers.get("X-Bootstrap-Admin") != "1":
            self.text(403, "Missing admin request header.")
            return False
        if need_session and not self.session_ok():
            self.json(401, {"error": "Sign in first."})
            return False
        return True

    # -- routes -------------------------------------------------------------
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            if not self.guard(need_session=False):
                return
            return self.send_body(200, (HERE / "web" / "admin.html").read_bytes(), "text/html; charset=utf-8", {
                "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
                "Referrer-Policy": "no-referrer",
            })
        if path == "/api/state":
            if not self.guard():
                return
            return self.json(200, self.state_view())
        self.text(404, "not found")

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        try:
            if path == "/api/login":
                if not self.guard(need_session=False, writing=True):
                    return
                return self.login()
            if not self.guard(writing=True):
                return
            body = self.read_json()
            store = self.app.store
            if path == "/api/keys":
                text = str(body.get("keys", ""))
                lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
                if not lines:
                    raise BadRequest("Paste at least one public key.")
                if len(lines) > 20:
                    raise BadRequest("At most 20 keys at a time.")
                # All-or-nothing: validate every line before adding any.
                fps = [parse_public_key(ln)["fingerprint"] for ln in lines]
                with store.lock:
                    have = {k["fingerprint"] for k in store.state["keys"]}
                if len(set(fps)) != len(fps) or have & set(fps):
                    raise BadRequest("A key is already in the list, or appears twice in what you pasted.")
                label = str(body.get("label", "")) if len(lines) == 1 else ""
                added = [store.add_key(ln, label) for ln in lines]
                log(f"admin: added {len(added)} key(s): " + ", ".join(k["fingerprint"] for k in added))
                return self.json(200, self.state_view())
            if path == "/api/settings":
                store.update_settings(body)
                log("admin: settings changed")
                return self.json(200, self.state_view())
            if path == "/api/logout":
                cookie = SimpleCookie(self.headers.get("Cookie", ""))
                if "pb_session" in cookie:
                    with self.app.sessions_lock:
                        self.app.sessions.pop(cookie["pb_session"].value, None)
                return self.json(200, {"ok": True}, {"Set-Cookie": "pb_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"})
            self.text(404, "not found")
        except BadRequest as e:
            self.json(400, {"error": str(e)})

    def do_DELETE(self):
        path = self.path.split("?", 1)[0]
        if not self.guard(writing=True):
            return
        store = self.app.store
        try:
            m = re.fullmatch(r"/api/keys/([a-f0-9]{16})", path)
            if m:
                with store.lock:
                    if len(store.state["keys"]) == 1 and store.state["clients"]:
                        raise BadRequest("That is the last key. Clients refuse an empty list, so add its replacement first.")
                store.remove_key(m.group(1))
                log(f"admin: removed key {m.group(1)}")
                return self.json(200, self.state_view())
            m = re.fullmatch(r"/api/clients/([A-Za-z0-9-]{1,80})", path)
            if m:
                store.forget_client(m.group(1))
                return self.json(200, self.state_view())
            self.text(404, "not found")
        except BadRequest as e:
            self.json(400, {"error": str(e)})

    # -- helpers --------------------------------------------------------------
    def login(self):
        app = self.app
        now = time.time()
        with app.sessions_lock:
            app.login_failures = [t for t in app.login_failures if now - t < 300]
            if len(app.login_failures) >= 10:
                return self.json(429, {"error": "Too many failed attempts. Wait a few minutes."})
        token = str(self.read_json().get("token", ""))
        if not hmac.compare_digest(token.encode(), app.token.encode()):
            with app.sessions_lock:
                app.login_failures.append(now)
            return self.json(401, {"error": "That is not the admin token."})
        sid = secrets.token_urlsafe(32)
        with app.sessions_lock:
            app.sessions = {k: v for k, v in app.sessions.items() if v > now}
            app.sessions[sid] = now + SESSION_HOURS * 3600
        self.json(200, {"ok": True}, {
            "Set-Cookie": f"pb_session={sid}; Path=/; Max-Age={SESSION_HOURS * 3600}; HttpOnly; SameSite=Strict"})

    def state_view(self) -> dict:
        app, store = self.app, self.app.store
        now = int(time.time())
        with store.lock:
            s = dict(store.state["settings"])
            version = store.keys_version()
            window = s["sync_minutes"] * 60 * 2 + 300  # two missed syncs, plus slack
            clients = []
            for cid, c in store.state["clients"].items():
                age = now - int(c.get("last_seen", 0))
                clients.append({
                    "id": cid, "name": c.get("name", ""), "user": c.get("user", ""), "ip": c.get("ip", ""),
                    "first_seen": c.get("first_seen", 0), "last_seen": c.get("last_seen", 0),
                    "pulls": c.get("pulls", 0),
                    "active": age <= window,
                    "current": c.get("keys_version") == version,
                    "identified": not cid.startswith("addr-"),
                })
            clients.sort(key=lambda c: (not c["active"], (c["name"] or c["ip"]).lower()))
            keys = [{k: key[k] for k in ("id", "type", "comment", "label", "fingerprint", "added")}
                    for key in store.state["keys"]]
        return {
            "version": VERSION, "now": now, "pin": app.pin, "settings": s, "keys": keys, "clients": clients,
            "keys_version": version, "client_port": app.client_port, "address_guess": app.guess_address(),
            "payload": {"files": store.payload_files(), "entry": store.payload_entry()},
            "active_window_minutes": window // 60,
        }


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    tls: ssl.SSLContext | None = None

    def finish_request(self, request, client_address):
        # The TLS handshake happens here, in the request's own thread, so one
        # slow client cannot hold up the accept loop.
        if self.tls is None:
            self.RequestHandlerClass(request, client_address, self)
            return
        request.settimeout(20)
        try:
            tls = self.tls.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        try:
            self.RequestHandlerClass(tls, client_address, self)
        finally:
            try:
                tls.close()
            except OSError:
                pass

    def handle_error(self, request, client_address):
        pass  # dropped connections are routine


def build(data_dir: Path, bind: str, port: int, admin_bind: str, admin_port: int) -> tuple[App, Server, Server]:
    app = App(data_dir)
    ch = type("BoundClientHandler", (ClientHandler,), {"app": app})
    ah = type("BoundAdminHandler", (AdminHandler,), {"app": app})
    client = Server((bind, port), ch)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(app.cert), str(app.key))
    client.tls = ctx
    admin = Server((admin_bind, admin_port), ah)
    app.client_port = client.server_address[1]
    return app, client, admin


def main() -> None:
    env = os.environ.get
    data_dir = Path(env("BOOTSTRAP_DATA", str(HERE / "data"))).resolve()
    app, client, admin = build(
        data_dir,
        env("BOOTSTRAP_BIND", "0.0.0.0"), int(env("BOOTSTRAP_PORT", "8443")),
        env("BOOTSTRAP_ADMIN_BIND", "127.0.0.1"), int(env("BOOTSTRAP_ADMIN_PORT", "8444")),
    )
    cport, aport = client.server_address[1], admin.server_address[1]
    log(f"version {VERSION}, data in {data_dir}")
    log(f"clients:  https://<this-machine>:{cport}/   ({len(app.store.state['keys'])} key(s))")
    log(f"admin:    http://localhost:{aport}/")
    if env("BOOTSTRAP_ADMIN_TOKEN"):
        log("admin token: taken from BOOTSTRAP_ADMIN_TOKEN")
    else:
        log(f"admin token: {app.token}   (also in {data_dir / 'admin-token'})")
    log(f"TLS pin: {app.pin}")

    def flusher():
        while True:
            time.sleep(30)
            try:
                app.store.flush_clients()
            except OSError as e:
                log(f"could not save client list: {e}")

    threading.Thread(target=flusher, daemon=True).start()
    threading.Thread(target=admin.serve_forever, daemon=True).start()
    try:
        client.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.store.flush_clients()


if __name__ == "__main__":
    main()
