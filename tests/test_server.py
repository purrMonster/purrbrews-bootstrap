"""End-to-end checks against a real server on throwaway ports.

    python3 -m unittest discover -s tests

Needs the `openssl` and `curl` commands (the client scripts use both).
"""

import http.client
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import server  # noqa: E402



def _ed25519(seed: int, comment: str) -> str:
    """A well-formed ed25519 public key line (the key itself is arbitrary bytes)."""
    import base64, struct
    t = b"ssh-ed25519"
    blob = struct.pack(">I", len(t)) + t + struct.pack(">I", 32) + bytes([seed]) * 32
    return f"ssh-ed25519 {base64.b64encode(blob).decode()} {comment}"


KEY1 = _ed25519(1, "one@test")
KEY2 = _ed25519(2, "two@test")


class Live(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="pb-test-"))
        os.environ.pop("BOOTSTRAP_ADMIN_TOKEN", None)
        cls.app, cls.client, cls.admin = server.build(cls.tmp / "data", "127.0.0.1", 0, "127.0.0.1", 0)
        for s in (cls.client, cls.admin):
            threading.Thread(target=s.serve_forever, daemon=True).start()
        cls.cport = cls.client.server_address[1]
        cls.aport = cls.admin.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.client.shutdown(); cls.admin.shutdown()
        cls.client.server_close(); cls.admin.server_close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # -- helpers ----------------------------------------------------------------
    def get(self, path, headers=None):
        ctx = ssl._create_unverified_context()
        c = http.client.HTTPSConnection("127.0.0.1", self.cport, context=ctx, timeout=10)
        c.request("GET", path, headers=headers or {})
        r = c.getresponse()
        out = r.status, r.read(), dict(r.getheaders())
        c.close()
        return out

    def adm(self, method, path, body=None, cookie=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.aport, timeout=10)
        h = {"Content-Type": "application/json", "X-Bootstrap-Admin": "1"}
        if cookie:
            h["Cookie"] = cookie
        h.update(headers or {})
        c.request(method, path, body=json.dumps(body) if body is not None else None, headers=h)
        r = c.getresponse()
        raw = r.read()
        c.close()
        try:
            data = json.loads(raw)
        except ValueError:
            data = raw.decode()
        return r.status, data, dict(r.getheaders())

    def login(self):
        st, _, hdr = self.adm("POST", "/api/login", {"token": self.app.token})
        self.assertEqual(st, 200)
        return hdr["Set-Cookie"].split(";")[0]

    def reset(self):
        with self.app.store.lock:
            self.app.store.state["keys"] = []
            self.app.store.state["clients"] = {}
            self.app.store.state["settings"].update(public_url="", payload_entry="", default_user="", sync_minutes=60)

    def setUp(self):
        self.reset()

    # -- admin ---------------------------------------------------------------------
    def test_admin_needs_login(self):
        self.assertEqual(self.adm("GET", "/api/state")[0], 401)
        self.assertEqual(self.adm("POST", "/api/keys", {"keys": KEY1})[0], 401)
        self.assertEqual(self.adm("POST", "/api/login", {"token": "wrong-token-wrong-token"})[0], 401)

    def test_admin_refuses_foreign_host_and_missing_header(self):
        st, _, _ = self.adm("GET", "/", headers={"Host": "evil.example"})
        self.assertEqual(st, 403)
        cookie = self.login()
        c = http.client.HTTPConnection("127.0.0.1", self.aport, timeout=10)
        c.request("POST", "/api/keys", body=json.dumps({"keys": KEY1}),
                  headers={"Content-Type": "application/json", "Cookie": cookie})  # no X-Bootstrap-Admin
        self.assertEqual(c.getresponse().status, 403)
        c.close()

    def test_keys_add_list_remove(self):
        cookie = self.login()
        st, data, _ = self.adm("POST", "/api/keys", {"keys": KEY1, "label": "laptop"}, cookie)
        self.assertEqual(st, 200, data)
        self.assertEqual(data["keys"][0]["label"], "laptop")
        self.assertTrue(data["keys"][0]["fingerprint"].startswith("SHA256:"))
        self.assertEqual(self.adm("POST", "/api/keys", {"keys": KEY1}, cookie)[0], 400)  # duplicate
        st, body, hdr = self.get("/keys/authorized_keys")
        self.assertEqual((st, body), (200, (KEY1 + "\n").encode()))
        self.assertEqual(hdr["X-Keys-Count"], "1")
        self.adm("POST", "/api/keys", {"keys": KEY2}, cookie)
        kid = data["keys"][0]["id"]
        st, data, _ = self.adm("DELETE", f"/api/keys/{kid}", cookie=cookie)
        self.assertEqual(st, 200)
        self.assertEqual(self.get("/keys/authorized_keys")[1], (KEY2 + "\n").encode())

    def test_bad_keys_refused(self):
        cookie = self.login()
        for bad in ("-----BEGIN OPENSSH PRIVATE KEY-----",
                    'command="/bin/sh" ' + KEY1,
                    "ssh-ed25519 not-base64!! x",
                    "ssh-rsa " + KEY1.split()[1],          # type does not match the data
                    KEY1.split()[0] + " " + KEY1.split()[1][:-8] + " cut@short",   # truncated
                    "hello world"):
            st, data, _ = self.adm("POST", "/api/keys", {"keys": bad}, cookie)
            self.assertEqual(st, 400, bad)
        self.assertEqual(self.get("/keys/authorized_keys")[1], b"")

    def test_last_key_kept_while_clients_exist(self):
        cookie = self.login()
        _, data, _ = self.adm("POST", "/api/keys", {"keys": KEY1}, cookie)
        self.get("/keys/authorized_keys", {"X-Bootstrap-Id": "a" * 32, "X-Bootstrap-Client": "box"})
        st, data2, _ = self.adm("DELETE", f"/api/keys/{data['keys'][0]['id']}", cookie=cookie)
        self.assertEqual(st, 400)

    def test_settings_validation(self):
        cookie = self.login()
        self.assertEqual(self.adm("POST", "/api/settings", {"public_url": "https://10.0.0.5:8443"}, cookie)[0], 200)
        for bad in ({"public_url": "http://x"}, {"public_url": "https://x/$(id)"}, {"sync_minutes": 1},
                    {"default_user": "Bad User"}, {"payload_entry": "../etc/passwd"}, {"payload_entry": "missing.sh"}):
            self.assertEqual(self.adm("POST", "/api/settings", bad, cookie)[0], 400, bad)

    # -- clients ---------------------------------------------------------------------
    def test_client_list_tracks_pulls(self):
        cookie = self.login()
        self.adm("POST", "/api/keys", {"keys": KEY1}, cookie)
        self.get("/keys/authorized_keys", {"X-Bootstrap-Id": "b" * 32, "X-Bootstrap-Client": "web-1", "X-Bootstrap-User": "ops"})
        self.get("/keys/authorized_keys", {"X-Bootstrap-Id": "b" * 32, "X-Bootstrap-Client": "web-1", "X-Bootstrap-User": "ops"})
        self.get("/keys/authorized_keys", {"X-Bootstrap-Client": "<script>alert(1)</script>"})  # no id, bad name
        _, data, _ = self.adm("GET", "/api/state", cookie=cookie)
        by_name = {c["name"]: c for c in data["clients"]}
        self.assertEqual(by_name["web-1"]["pulls"], 2)
        self.assertEqual(by_name["web-1"]["user"], "ops")
        self.assertTrue(by_name["web-1"]["active"] and by_name["web-1"]["current"])
        self.assertIn("", by_name)                       # the unidentified one, name dropped
        self.assertFalse(by_name[""]["identified"])
        # A key change makes every client "pending" until it pulls again.
        self.adm("POST", "/api/keys", {"keys": KEY2}, cookie)
        _, data, _ = self.adm("GET", "/api/state", cookie=cookie)
        self.assertFalse(any(c["current"] for c in data["clients"]))
        # Not seen for longer than the window: no longer active.
        with self.app.store.lock:
            self.app.store.state["clients"]["b" * 32]["last_seen"] -= 3 * 3600
        _, data, _ = self.adm("GET", "/api/state", cookie=cookie)
        self.assertFalse({c["name"]: c for c in data["clients"]}["web-1"]["active"])
        st, data, _ = self.adm("DELETE", "/api/clients/" + "b" * 32, cookie=cookie)
        self.assertEqual(st, 200)
        self.assertNotIn("web-1", [c["name"] for c in data["clients"]])

    # -- client endpoints ---------------------------------------------------------------
    def test_bootstrap_script_is_filled_in(self):
        st, body, _ = self.get("/bootstrap.sh", {"Host": f"192.0.2.7:{self.cport}"})
        text = body.decode()
        self.assertEqual(st, 200)
        self.assertIn(f'BASE_URL="https://192.0.2.7:{self.cport}"', text)
        self.assertNotIn("__", text.split("set -Eeuo pipefail", 1)[1].split("have_tty", 1)[0])
        self.assertIn("/client/bootstrap.sh", text)        # the wrapper fetches the installer
        self.assertEqual(self.get("/bootstrap.sh", {"Host": 'x";rm -rf /;"'})[0], 400)
        self.app.store.update_settings({"public_url": "https://boot.example:9000"})
        self.assertIn('BASE_URL="https://boot.example:9000"', self.get("/bootstrap.sh", {"Host": "whatever"})[1].decode())

    def test_payload_served_with_checksums_and_no_traversal(self):
        pdir = self.app.store.payload_dir
        (pdir / "lib").mkdir(parents=True, exist_ok=True)
        (pdir / "init.sh").write_text("#!/bin/sh\necho hi\n")
        (pdir / "lib" / "x.sh").write_text("x\n")
        try:
            sums = self.get("/files/SHA256SUMS")[1].decode()
            self.assertIn("  init.sh", sums); self.assertIn("  lib/x.sh", sums)
            self.assertEqual(self.get("/files/lib/x.sh")[1], b"x\n")
            for bad in ("/files/../state.json", "/files/%2e%2e/state.json", "/files/../admin-token", "/files/missing"):
                self.assertEqual(self.get(bad)[0], 404, bad)
            self.app.store.update_settings({"payload_entry": "init.sh"})
            text = self.get("/bootstrap.sh", {"Host": "h:1"})[1].decode()
            self.assertIn('PAYLOAD_ENTRY="init.sh"', text); self.assertIn('HAS_PAYLOAD="1"', text)
        finally:
            shutil.rmtree(pdir)

    def test_client_scripts_are_read_live_from_their_folder(self):
        """The installer is a file beside the server, not part of it: a change on
        disk is what the next client gets, with no restart."""
        real = self.app.client_dir
        tmp = self.tmp / "client-dir"
        shutil.copytree(real, tmp)
        self.app.client_dir = tmp
        try:
            self.assertEqual(self.get("/client/bootstrap.sh")[1], (real / "bootstrap.sh").read_bytes())
            (tmp / "bootstrap.sh").write_text("#!/bin/sh\necho changed\n")
            self.assertEqual(self.get("/client/bootstrap.sh")[1], b"#!/bin/sh\necho changed\n")
            (tmp / "bootstrap.sh").unlink()
            st, body, _ = self.get("/client/bootstrap.sh")
            self.assertEqual(st, 503)
            cookie = self.login()
            _, data, _ = self.adm("GET", "/api/state", cookie=cookie)
            self.assertEqual(data["client_scripts"]["missing"], ["bootstrap.sh"])
            # nothing but plain script names is served from that folder
            (tmp / "notes.txt").write_text("x")
            os.symlink(self.tmp / "data" / "admin-token", tmp / "leak.sh")
            for bad in ("/client/notes.txt", "/client/leak.sh", "/client/../server.py", "/client/sub/x.sh"):
                self.assertIn(self.get(bad)[0], (404, 503), bad)
                self.assertNotIn(self.app.token.encode(), self.get(bad)[1])
        finally:
            self.app.client_dir = real
            shutil.rmtree(tmp)

    def test_wrapper_is_the_only_script_in_the_image(self):
        dockerfile = (ROOT / "Dockerfile").read_text()
        copies = [ln for ln in dockerfile.splitlines() if ln.startswith("COPY")]
        self.assertTrue(any("wrapper.sh" in ln for ln in copies))
        self.assertFalse(any("client" in ln for ln in copies), copies)
        self.assertNotIn("client", (ROOT / ".dockerignore").read_text())

    def test_secrets_not_reachable_from_client_port(self):
        for p in ("/api/state", "/", "/admin-token", "/state.json", "/certs/bootstrap.key"):
            self.assertEqual(self.get(p)[0], 404, p)

    # -- the real sync script, against the real server ----------------------------------
    def test_sync_script_manages_a_block(self):
        if not shutil.which("curl"):
            self.skipTest("curl not installed")
        cookie = self.login()
        self.adm("POST", "/api/keys", {"keys": KEY1}, cookie)
        user = subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip()
        ak = self.tmp / "home" / ".ssh" / "authorized_keys"
        ak.parent.mkdir(parents=True)
        ak.write_text(_ed25519(9, "mine@by-hand") + "\n")
        conf = self.tmp / "client.conf"

        def write_conf(pin):
            conf.write_text(f"SERVER_URL=https://127.0.0.1:{self.cport}\nSERVER_PIN={pin}\nKEY_USER={user}\n"
                            f"CLIENT_NAME=test-box\nCLIENT_ID={'c' * 32}\nAUTHORIZED_KEYS_FILE={ak}\n")

        def sync():
            return subprocess.run(["bash", str(ROOT / "client" / "sync.sh"), "--config", str(conf)],
                                  capture_output=True, text=True)

        write_conf(self.app.pin)
        r = sync(); self.assertEqual(r.returncode, 0, r.stderr)
        text = ak.read_text()
        self.assertIn("mine@by-hand", text); self.assertIn(KEY1, text)
        self.assertEqual(oct(ak.stat().st_mode & 0o777), "0o600")

        # key swapped on the server: the block follows, the hand-added line stays
        self.adm("POST", "/api/keys", {"keys": KEY2}, cookie)
        _, data, _ = self.adm("GET", "/api/state", cookie=cookie)
        kid = [k for k in data["keys"] if k["comment"] == "one@test"][0]["id"]
        self.adm("DELETE", f"/api/keys/{kid}", cookie=cookie)
        r = sync(); self.assertEqual(r.returncode, 0, r.stderr)
        text = ak.read_text()
        self.assertNotIn(KEY1, text); self.assertIn(KEY2, text); self.assertIn("mine@by-hand", text)
        self.assertEqual(text.count(">>> purrbrews-bootstrap managed keys"), 1)

        # the server lists it as an active, current client
        _, data, _ = self.adm("GET", "/api/state", cookie=cookie)
        c = [c for c in data["clients"] if c["name"] == "test-box"][0]
        self.assertTrue(c["active"] and c["current"] and c["identified"])

        # A UTF-8 locale must not change which keys are accepted (1.0.0 rejected
        # every key with a comment there: its pattern used a locale-sorted range).
        loc = self.tmp / "loc"
        loc.mkdir()
        made = shutil.which("localedef") and subprocess.run(
            ["localedef", "-i", "en_US", "-f", "UTF-8", str(loc / "en_US.UTF-8")], capture_output=True).returncode == 0
        if made:
            ak.unlink()
            r = subprocess.run(["bash", str(ROOT / "client" / "sync.sh"), "--config", str(conf)], capture_output=True, text=True,
                               env={**os.environ, "LOCPATH": str(loc), "LC_ALL": "en_US.UTF-8", "LANG": "en_US.UTF-8"})
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn(KEY2, ak.read_text())

        # zero keys on the server: nothing changes on the client
        self.reset()
        before = ak.read_text()
        r = sync(); self.assertEqual(r.returncode, 1)
        self.assertEqual(ak.read_text(), before)

        # wrong pin: hard failure, nothing changes
        write_conf("sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        r = sync(); self.assertEqual(r.returncode, 1, r.stderr)
        self.assertEqual(ak.read_text(), before)

        # server unreachable: exit 75, nothing changes
        conf.write_text(conf.read_text().replace(f":{self.cport}", ":9"))
        r = sync(); self.assertEqual(r.returncode, 75, r.stderr)
        self.assertEqual(ak.read_text(), before)


class Keys(unittest.TestCase):
    def test_fingerprint_matches_ssh_keygen(self):
        if not shutil.which("ssh-keygen"):
            self.skipTest("ssh-keygen not installed")
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "real@key", "-f", f"{d}/k"], check=True)
            pub = Path(f"{d}/k.pub").read_text().strip()
            want = subprocess.run(["ssh-keygen", "-lf", f"{d}/k.pub"], capture_output=True, text=True).stdout.split()[1]
            self.assertEqual(server.parse_public_key(pub)["fingerprint"], want)


class Scripts(unittest.TestCase):
    def test_scripts_pin_the_c_locale(self):
        for path in (ROOT / "client" / "sync.sh", ROOT / "client" / "bootstrap.sh", ROOT / "wrapper.sh"):
            head = "\n".join(path.read_text().splitlines()[:45])
            self.assertIn("export LC_ALL=C", head, path.name)

    def test_installer_lists_its_steps(self):
        r = subprocess.run(["bash", str(ROOT / "client" / "bootstrap.sh"), "--list-steps"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        steps = r.stdout.split()
        self.assertEqual(steps, ["hostname", "timezone", "packages", "user", "keys", "ssh", "power",
                                 "journald", "docker", "firewall", "payload"])
        text = (ROOT / "client" / "bootstrap.sh").read_text()
        for s in steps:                              # every listed step has a function
            self.assertIn(f"step_{s}() {{", text, s)
        self.assertLess(steps.index("keys"), steps.index("ssh"))          # never harden before keys exist
        self.assertLess(steps.index("docker"), steps.index("firewall"))   # ufw-docker needs Docker

    def test_installer_refuses_to_run_outside_the_wrapper(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith("PB_")}
        r = subprocess.run(["bash", str(ROOT / "client" / "bootstrap.sh")], capture_output=True, text=True, env=env)
        self.assertNotEqual(r.returncode, 0)

    def test_shell_syntax(self):
        for path in (ROOT / "client" / "sync.sh", ROOT / "client" / "bootstrap.sh", ROOT / "wrapper.sh"):
            r = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)


class Release(unittest.TestCase):
    """The version must agree everywhere, or a tag publishes the wrong thing."""

    def test_version_is_consistent(self):
        import re
        version = (ROOT / "VERSION").read_text().strip()
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")
        self.assertEqual(server.VERSION, version)
        self.assertIn(f"BOOTSTRAP_VERSION:-{version}}}", (ROOT / "compose.yaml").read_text())
        self.assertIn(f"#BOOTSTRAP_VERSION={version}", (ROOT / ".env.example").read_text())
        self.assertTrue(re.search(rf"^## {re.escape(version)}\b", (ROOT / "CHANGELOG.md").read_text(), re.M))


if __name__ == "__main__":
    unittest.main()
