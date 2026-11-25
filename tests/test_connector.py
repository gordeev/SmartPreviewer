"""SmartPreview connector checks. Standard library only:

    python3 -m unittest discover -s tests

The PhotoCraft integration test runs when photocraft-cli is installed (set PHOTOCRAFT_CLI
to its path elsewhere) and is skipped otherwise.
"""
import hashlib
import hmac
import http.client
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "connector"))
import smartpreview as sp  # noqa: E402


def fake_jpeg(width, height):
    """Markers only: SOI, APP0, SOF0 and EOI, enough for jpeg_size()."""
    app0 = b"\xff\xe0" + (16).to_bytes(2, "big") + b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    sof0 = (b"\xff\xc0" + (17).to_bytes(2, "big") + b"\x08" + height.to_bytes(2, "big")
            + width.to_bytes(2, "big") + b"\x03" + b"\x01\x22\x00\x02\x11\x01\x03\x11\x01")
    return b"\xff\xd8" + app0 + sof0 + b"\xff\xd9"


def fake_png(width, height):
    return b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + width.to_bytes(4, "big") + height.to_bytes(4, "big") + b"\x08\x02\x00\x00\x00"


def fake_convert(path, max_side, size):
    """Stands in for sips/Pillow: checks the export exists and 'scales' it."""
    assert os.path.isfile(path) and path.endswith(".tif"), path
    w, h = size
    if max_side and max(w, h) > max_side:
        k = max_side / max(w, h)
        w, h = round(w * k), round(h * k)
    return fake_jpeg(w, h)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class FakePhotoCraft:
    """The desktop control server, as much as the connector uses of it."""

    def __init__(self, token, write_root, prove_with=None):
        self.token, self.write_root = token, write_root
        self.prove_with = prove_with or token
        self.revision, self.saves, self.name = 1, [], "Poster"
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    def _client(self, conn):
        f = conn.makefile("rwb")
        authed, cn, sn = False, None, None

        def reply(rid, result=None, error=None):
            msg = {"id": rid, "ok": error is None}
            msg["result" if error is None else "error"] = result if error is None else error
            f.write(json.dumps(msg).encode() + b"\n")
            f.flush()

        for line in f:
            req = json.loads(line)
            rid, method, params = req["id"], req["method"], req.get("params") or {}
            if not authed:
                if method == "auth.challenge":
                    cn, sn = params["clientNonce"], secrets.token_hex(32)
                    reply(rid, {"serverNonce": sn, "serverProof": sp.proof(self.prove_with, sp.SERVER_LABEL, cn, sn)})
                elif method == "auth" and cn and hmac.compare_digest(
                        params.get("proof", ""), sp.proof(self.token, sp.CLIENT_LABEL, cn, sn)):
                    authed = True
                    reply(rid, {"authenticated": True})
                else:
                    reply(rid, error="authentication required")
                    conn.close()
                    return
                continue
            if method == "engine.execute" and params.get("command") == "session.inspect":
                reply(rid, {"active": 0, "documents": [{"index": 0, "name": self.name, "revision": self.revision,
                                                        "width": 1080, "height": 2400, "dirty": True}]})
            elif method == "app.save":
                path = os.path.join(self.write_root, params["path"])
                with open(path, "wb") as out:
                    out.write(fake_png(1080, 2400) if path.endswith(".png") else b"II*\x00fake tiff")
                self.saves.append(params)
                reply(rid, {"path": path, "warnings": []})
            else:
                reply(rid, error=f"unknown method {method}")

    def close(self):
        self.sock.close()


class FakePhone:
    def __init__(self):
        self.frames = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                outer.frames.append((self.path, body))
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


def make_args(**kw):
    base = dict(phones=None, size=None, control_port=None, token_file=None, http_port=0,
                no_launch=True, no_browser=True, once=False, discover=False, fast=False)
    base.update(kw)
    return SimpleNamespace(**base)


class Helpers(unittest.TestCase):
    def test_proof_is_hmac_sha256_over_label_and_nonces(self):
        token, cn, sn = "ab" * 32, "01" * 32, "02" * 32
        expected = hmac.new(token.encode(), f"photocraft-control-v1 client\n{cn}\n{sn}".encode(),
                            hashlib.sha256).hexdigest()
        self.assertEqual(sp.proof(token, sp.CLIENT_LABEL, cn, sn), expected)
        self.assertEqual(sp.proof(token.upper(), sp.CLIENT_LABEL, cn.upper(), sn), expected)
        self.assertNotEqual(sp.proof(token, sp.SERVER_LABEL, cn, sn), expected)

    def test_targets(self):
        self.assertEqual(sp.split_target("192.168.1.5"), ("192.168.1.5", sp.PHONE_PORT))
        self.assertEqual(sp.split_target("192.168.1.5:8765"), ("192.168.1.5", 8765))
        self.assertEqual(sp.split_target("http://phone.local:9000/x"), ("phone.local", 9000))
        self.assertEqual(sp.split_target("[fe80::1]:8767"), ("fe80::1", 8767))
        self.assertEqual(sp.parse_targets("a, b;b  c"), ["a", "b", "c"])
        with self.assertRaises(ValueError):
            sp.parse_targets("host:port")

    def test_image_size_and_type(self):
        self.assertEqual(sp.image_size(fake_jpeg(1080, 2400)), (1080, 2400))
        self.assertEqual(sp.image_size(fake_png(1170, 2532)), (1170, 2532))
        self.assertIsNone(sp.image_size(b"GIF89a"))
        self.assertEqual(sp.image_type(fake_png(1, 1)), "image/png")
        self.assertEqual(sp.image_type(fake_jpeg(1, 1)), "image/jpeg")

    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("sips"), "sips is macOS only")
    def test_sips_converts_tiff_to_scaled_jpeg(self):
        with tempfile.TemporaryDirectory() as tmp:
            tif = os.path.join(tmp, "a.tif")
            ppm = os.path.join(tmp, "a.ppm")
            with open(ppm, "wb") as f:
                f.write(b"P6 300 600 255\n" + bytes([200, 80, 20]) * (300 * 600))
            subprocess.run(["sips", "-s", "format", "tiff", ppm, "--out", tif], capture_output=True, check=True)
            out = sp.sips_convert(tif, 200, (300, 600))
            self.assertEqual(sp.image_type(out), "image/jpeg")
            self.assertEqual(sp.image_size(out), (100, 200))
            out = sp.sips_convert(tif, 2400, (300, 600))   # never scaled up
            self.assertEqual(sp.image_size(out), (300, 600))

    def test_signature_follows_revision_and_document(self):
        s = {"active": 0, "documents": [{"index": 0, "name": "A", "revision": 3, "width": 10, "height": 20}]}
        a = sp.document_signature(s)
        s["documents"][0]["revision"] = 4
        self.assertNotEqual(a, sp.document_signature(s))
        self.assertIsNone(sp.document_signature({"active": None, "documents": []}))

    def test_token_file_is_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "sub", "control.token")
            token = sp.ensure_token(path)
            self.assertRegex(token, r"^[0-9a-f]{64}$")
            self.assertEqual(sp.ensure_token(path), token)
            if os.name != "nt":
                self.assertEqual(os.stat(path).st_mode & 0o077, 0)


class BridgeFlow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="smartpreview-test-")
        self._app_dir = sp.app_dir
        sp.app_dir = lambda: self.tmp
        self.phone = FakePhone()

    def tearDown(self):
        sp.app_dir = self._app_dir
        self.phone.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_edit_is_exported_and_sent_to_the_phone(self):
        token = sp.ensure_token(os.path.join(self.tmp, "control.token"))
        os.makedirs(os.path.join(self.tmp, "frames"), exist_ok=True)
        pc = FakePhotoCraft(token, os.path.join(self.tmp, "frames"))
        try:
            bridge = sp.Bridge(make_args(control_port=pc.port, phones=f"127.0.0.1:{self.phone.port}", size=1600))
            bridge.convert = fake_convert
            self.assertTrue(bridge._connect())
            bridge.step()
            self.assertEqual(len(self.phone.frames), 1)
            path, body = self.phone.frames[0]
            self.assertEqual(path, "/frame?name=Poster")
            self.assertEqual(sp.image_size(body), (720, 1600))
            self.assertTrue(pc.saves[0]["path"].endswith(".tif"))
            self.assertTrue(pc.saves[0]["tiffLayers"])          # quiet: no notices in PhotoCraft
            self.assertEqual(bridge.hub.version, 1)
            self.assertEqual(os.listdir(os.path.join(self.tmp, "frames")), [])  # frame file removed

            bridge.step()                       # nothing changed: nothing sent
            self.assertEqual(len(self.phone.frames), 1)
            pc.revision += 1                    # an edit
            bridge.step()
            self.assertEqual(len(self.phone.frames), 2)

            bridge.update_settings(mode="fast")
            bridge.step()
            self.assertFalse(pc.saves[-1]["tiffLayers"])
            self.assertEqual(len(self.phone.frames), 3)

            bridge.update_settings(live=False)
            pc.revision += 1
            bridge.step()                       # stopped: edits are not sent
            self.assertEqual(len(self.phone.frames), 3)
            bridge.send_once()                  # Send once works while stopped
            bridge.step()
            self.assertEqual(len(self.phone.frames), 4)
            self.assertTrue(bridge.snapshot()["targets"][f"127.0.0.1:{self.phone.port}"]["ok"])
        finally:
            pc.close()

    def test_server_without_the_token_is_rejected_before_proof_is_sent(self):
        token = sp.ensure_token(os.path.join(self.tmp, "control.token"))
        pc = FakePhotoCraft(token, self.tmp, prove_with="cd" * 32)
        try:
            client = sp.ControlClient(pc.port, token)
            with self.assertRaises(sp.AuthError):
                client.connect()
        finally:
            pc.close()

    def test_without_a_converter_frames_are_png(self):
        token = sp.ensure_token(os.path.join(self.tmp, "control.token"))
        os.makedirs(os.path.join(self.tmp, "frames"), exist_ok=True)
        pc = FakePhotoCraft(token, os.path.join(self.tmp, "frames"))
        try:
            bridge = sp.Bridge(make_args(control_port=pc.port, phones=f"127.0.0.1:{self.phone.port}"))
            bridge.convert = None
            self.assertTrue(bridge._connect())
            bridge.step()
            self.assertTrue(pc.saves[0]["path"].endswith(".png"))
            self.assertEqual(sp.image_type(self.phone.frames[0][1]), "image/png")
            self.assertEqual(os.listdir(os.path.join(self.tmp, "frames")), [])
        finally:
            pc.close()

    def test_unreachable_phone_is_reported(self):
        token = sp.ensure_token(os.path.join(self.tmp, "control.token"))
        os.makedirs(os.path.join(self.tmp, "frames"), exist_ok=True)
        pc = FakePhotoCraft(token, os.path.join(self.tmp, "frames"))
        dead = f"127.0.0.1:{free_port()}"
        try:
            bridge = sp.Bridge(make_args(control_port=pc.port, phones=f"127.0.0.1:{self.phone.port},{dead}"))
            bridge.convert = fake_convert
            self.assertTrue(bridge._connect())
            bridge.step()
            targets = bridge.snapshot()["targets"]
            self.assertTrue(targets[f"127.0.0.1:{self.phone.port}"]["ok"])
            self.assertFalse(targets[dead]["ok"])
        finally:
            pc.close()

    def test_panel_api_is_local_and_needs_its_header(self):
        bridge = sp.Bridge(make_args())
        server = sp.start_http(bridge, 0)
        port = bridge.http_port
        try:
            def req(method, path, host="localhost", headers=None, body=None):
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                h = {"Host": f"{host}:{port}"}
                h.update(headers or {})
                c.request(method, path, body=body, headers=h)
                r = c.getresponse()
                data = r.read()
                c.close()
                return r.status, data

            self.assertEqual(req("GET", "/api/state")[0], 200)
            self.assertEqual(req("GET", "/panel")[0], 200)
            self.assertEqual(req("GET", "/api/state", host="evil.example")[0], 403)
            self.assertEqual(req("POST", "/api/settings", body=b'{"live": false}')[0], 403)
            status, data = req("POST", "/api/settings", headers={"X-SmartPreview": "1"},
                               body=b'{"phones": "10.0.0.7", "maxSide": 1600, "mode": "fast"}')
            self.assertEqual(status, 200)
            state = json.loads(data)
            self.assertEqual(state["phones"], ["10.0.0.7"])
            self.assertEqual(state["maxSide"], 1600)
            self.assertEqual(state["mode"], "fast")
            self.assertEqual(req("POST", "/api/settings", headers={"X-SmartPreview": "1"},
                                 body=b'{"mode": "turbo"}')[0], 400)
            self.assertEqual(req("GET", "/")[0], 200)              # browser viewer, for the LAN
            self.assertEqual(req("GET", "/cutouts.json")[0], 200)
            with open(os.path.join(self.tmp, "settings.json")) as f:
                self.assertEqual(json.load(f)["phones"], ["10.0.0.7"])
        finally:
            server.shutdown()


def find_cli():
    for p in (os.environ.get("PHOTOCRAFT_CLI"), "/Applications/PhotoCraft.app/Contents/MacOS/photocraft-cli",
              shutil.which("photocraft-cli")):
        if p and os.path.isfile(p):
            return p
    return None


@unittest.skipUnless(find_cli(), "photocraft-cli is not installed")
class RealPhotoCraft(unittest.TestCase):
    """Challenge authentication and revision tracking against PhotoCraft's own server."""

    def test_headless_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            token_file = os.path.join(tmp, "control.token")
            token = sp.ensure_token(token_file)
            port = free_port()
            proc = subprocess.Popen([find_cli(), "serve", "--port", str(port), "--control-token-file", token_file],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                client = sp.ControlClient(port, token)
                deadline = time.time() + 20
                while True:
                    try:
                        client.connect()
                        break
                    except OSError:
                        if time.time() > deadline:
                            raise
                        time.sleep(0.2)
                client.call("doc.new", {"width": 1080, "height": 1920, "name": "Probe"})
                s1 = client.call("engine.execute", {"command": "session.inspect"})
                self.assertEqual(sp.active_document(s1)["name"], "Probe")
                client.call("engine.execute", {"command": "filter.render.clouds"})
                s2 = client.call("engine.execute", {"command": "session.inspect"})
                self.assertNotEqual(sp.document_signature(s1), sp.document_signature(s2))
                with self.assertRaises(sp.AuthError):
                    sp.ControlClient(port, "ef" * 32).connect()
            finally:
                proc.terminate()
                proc.wait(10)


if __name__ == "__main__":
    unittest.main()
