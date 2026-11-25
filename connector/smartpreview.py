#!/usr/bin/env python3
"""SmartPreview connector: the live PhotoCraft canvas on a phone.

PhotoCraft plug-ins are sandboxed WebAssembly filters with no network or file access,
so the preview runs beside PhotoCraft instead. This script talks to PhotoCraft's
localhost control server (JSON lines, HMAC challenge authentication), exports the
active document whenever its revision changes, and sends the JPEG to the SmartPreview
Android app and to phone browsers. A small panel at http://localhost:8766/panel
controls it.

Python 3.8+, standard library only.
"""
import argparse
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote

VERSION = "1.0.0"
CONTROL_PORT = 8975        # PhotoCraft control server when SmartPreview launches PhotoCraft
PHONE_PORT = 8767          # SmartPreview Android app
HTTP_PORT = 8766           # this connector: panel (localhost) and browser viewer (LAN)
POLL_SECONDS = 0.35        # how often the document revision is checked
SEND_TIMEOUT = 8
LONG_POLL_SECONDS = 25
DISCOVERY_TIMEOUT = 3
DISCOVERY_QUERY = b"SMARTPREVIEW?"
DISCOVERY_REPLY = b"SMARTPREVIEW!"
SIZES = (0, 1080, 1600, 2400, 4000)   # longest side; 0 = the document's own size
MODES = ("quiet", "fast")             # see Bridge.capture
JPEG_QUALITY = 85                     # frames sent to the phone

SERVER_LABEL = "photocraft-control-v1 server"
CLIENT_LABEL = "photocraft-control-v1 client"

HERE = os.path.dirname(os.path.abspath(__file__))


# ------------------------------------------------------------------ folders

def app_dir():
    if sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
        return os.path.join(base, "SmartPreview")
    if os.name == "nt":
        return os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "SmartPreview")
    base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return os.path.join(base, "smartpreview")


def photocraft_settings_dirs():
    """Where PhotoCraft may keep agent-connection.json (newer versions publish it)."""
    dirs = []
    if os.environ.get("PHOTOCRAFT_CONFIG_DIR"):
        dirs.append(os.environ["PHOTOCRAFT_CONFIG_DIR"])
    if sys.platform == "darwin":
        dirs.append(os.path.expanduser("~/Library/Application Support/Photocraft"))
    elif os.name == "nt":
        for var in ("APPDATA", "LOCALAPPDATA"):
            if os.environ.get(var):
                dirs.append(os.path.join(os.environ[var], "Photocraft"))
                dirs.append(os.path.join(os.environ[var], "PhotoCraft"))
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
        dirs.append(os.path.join(base, "photocraft"))
        dirs.append(os.path.join(base, "Photocraft"))
    return dirs


def ensure_token(path):
    """A 64-hex control token in a 0600 file; PhotoCraft refuses group/other-readable ones."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        with open(path, "r", encoding="ascii") as f:
            token = f.read().strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", token):
            if os.name != "nt":
                os.chmod(path, 0o600)
            return token
        os.remove(path)
    except FileNotFoundError:
        pass
    token = secrets.token_hex(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(token + "\n")
    return token


def read_token(path):
    with open(path, "r", encoding="ascii") as f:
        token = f.read().strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise ValueError("the control token must be 64 hexadecimal characters")
    return token


# ---------------------------------------------------------- control client

class ControlError(Exception):
    pass


class AuthError(ControlError):
    pass


def proof(token, label, client_nonce, server_nonce):
    message = f"{label}\n{client_nonce.lower()}\n{server_nonce.lower()}".encode("ascii")
    return hmac.new(token.lower().encode("ascii"), message, hashlib.sha256).hexdigest()


class ControlClient:
    """PhotoCraft's control protocol: one JSON request per line, one reply per line.

    Uses challenge authentication, so the token never leaves this process and a program
    squatting on the port learns nothing.
    """

    def __init__(self, port, token, host="127.0.0.1", timeout=60):
        self.host, self.port, self.token, self.timeout = host, port, token, timeout
        self._sock = None
        self._file = None
        self._next_id = 0
        self._lock = threading.Lock()

    @property
    def connected(self):
        return self._file is not None

    def close(self):
        for thing in (self._file, self._sock):
            try:
                if thing:
                    thing.close()
            except OSError:
                pass
        self._sock = self._file = None

    def connect(self):
        self.close()
        sock = socket.create_connection((self.host, self.port), timeout=3)
        sock.settimeout(self.timeout)
        self._sock, self._file = sock, sock.makefile("rwb")
        try:
            client_nonce = secrets.token_hex(32)
            reply = self._exchange("auth.challenge", {"clientNonce": client_nonce})
            if not reply.get("ok"):
                raise AuthError(reply.get("error") or "authentication refused")
            result = reply.get("result") or {}
            server_nonce = str(result.get("serverNonce", "")).lower()
            server_proof = str(result.get("serverProof", "")).lower()
            expected = proof(self.token, SERVER_LABEL, client_nonce, server_nonce)
            if not re.fullmatch(r"[0-9a-f]{64}", server_nonce) or not hmac.compare_digest(server_proof, expected):
                raise AuthError("the program on this port does not know the SmartPreview token")
            reply = self._exchange("auth", {"proof": proof(self.token, CLIENT_LABEL, client_nonce, server_nonce)})
            if not reply.get("ok"):
                raise AuthError(reply.get("error") or "authentication refused")
        except Exception:
            self.close()
            raise

    def _exchange(self, method, params):
        self._next_id += 1
        rid = self._next_id
        line = json.dumps({"id": rid, "method": method, "params": params if params is not None else {}})
        self._file.write(line.encode("utf-8") + b"\n")
        self._file.flush()
        while True:
            raw = self._file.readline()
            if not raw:
                raise ConnectionError("PhotoCraft closed the connection")
            try:
                reply = json.loads(raw)
            except ValueError:
                continue
            if reply.get("id") == rid:
                return reply

    def call(self, method, params=None, retry=True):
        with self._lock:
            for attempt in (0, 1):
                try:
                    if not self.connected:
                        self.connect()
                    reply = self._exchange(method, params)
                    break
                except AuthError:
                    raise
                except (OSError, ValueError) as e:
                    # PhotoCraft drops connections idle for 30 s; reconnect once.
                    self.close()
                    if attempt or not retry:
                        raise ControlError(f"no connection to PhotoCraft ({e})") from e
        if not reply.get("ok"):
            raise ControlError(str(reply.get("error") or "PhotoCraft refused the request"))
        return reply.get("result")


def pid_alive(pid):
    try:
        pid = int(pid)
        if pid <= 0:
            return False
        if os.name == "nt":
            out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True)
            return str(pid) in out.stdout
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except (OSError, ValueError, TypeError):
        return False


def connection_candidates(args, own_token_path):
    """(label, port, token-file) pairs to try, most specific first."""
    out = []
    if args.token_file:
        out.append(("--token-file", args.control_port or CONTROL_PORT, args.token_file))
    else:
        out.append(("SmartPreview", args.control_port or CONTROL_PORT, own_token_path))
        # PhotoCraft versions with Preferences > AI Integrations publish their connection.
        for d in photocraft_settings_dirs():
            path = os.path.join(d, "agent-connection.json")
            try:
                with open(path, "r", encoding="utf-8") as f:
                    info = json.load(f)
            except (OSError, ValueError):
                continue
            if info.get("version") == 1 and pid_alive(info.get("pid")) and info.get("tokenFile"):
                out.append(("AI Integrations", int(info.get("port", 0)), info["tokenFile"]))
    return out


# --------------------------------------------------------------- PhotoCraft

def find_photocraft_app():
    if sys.platform == "darwin":
        for p in ("/Applications/PhotoCraft.app", os.path.expanduser("~/Applications/PhotoCraft.app")):
            if os.path.isdir(p):
                return p
        return None
    for name in ("photocraft", "PhotoCraft", "photocraft.exe", "PhotoCraft.exe"):
        p = shutil.which(name)
        if p:
            return p
    if os.name == "nt":
        for var in ("ProgramFiles", "LOCALAPPDATA"):
            base = os.environ.get(var)
            if base:
                for p in (os.path.join(base, "PhotoCraft", "PhotoCraft.exe"),
                          os.path.join(base, "Programs", "PhotoCraft", "PhotoCraft.exe")):
                    if os.path.isfile(p):
                        return p
    return None


def photocraft_running():
    try:
        if sys.platform == "darwin":
            return subprocess.run(["pgrep", "-x", "PhotoCraft"], capture_output=True).returncode == 0
        if os.name == "nt":
            out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq PhotoCraft.exe", "/NH"], capture_output=True, text=True)
            return "photocraft" in out.stdout.lower()
        return subprocess.run(["pgrep", "-ix", "photocraft"], capture_output=True).returncode == 0
    except OSError:
        return False


def launch_photocraft(port, token_file, write_root):
    app = find_photocraft_app()
    if not app:
        raise ControlError("PhotoCraft was not found; start it yourself with "
                           f"--control {port} --control-token-file \"{token_file}\" "
                           f"--automation-write-root \"{write_root}\"")
    flags = ["--control", str(port), "--control-token-file", token_file, "--automation-write-root", write_root]
    if sys.platform == "darwin":
        subprocess.Popen(["open", "-a", app, "--args", *flags])
    else:
        kwargs = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "stdin": subprocess.DEVNULL}
        if os.name == "nt":
            kwargs["creationflags"] = 0x00000008 | 0x00000200  # DETACHED_PROCESS | NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
        subprocess.Popen([app, *flags], **kwargs)


def active_document(session):
    if not isinstance(session, dict):
        return None
    active = session.get("active")
    for doc in session.get("documents") or []:
        if doc.get("index") == active:
            return doc
    return None


def document_signature(session):
    """Changes with every edit, undo, resize and document switch."""
    doc = active_document(session)
    if not doc:
        return None
    return "{}|{}|{}|{}x{}".format(session.get("active"), doc.get("name"), doc.get("revision"),
                                   doc.get("width"), doc.get("height"))


# ------------------------------------------------------------------- images

def image_size(data):
    """(width, height) of a JPEG or PNG, or None."""
    if data.startswith(b"\x89PNG\r\n\x1a\n") and len(data) >= 24:
        return int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")
    if not data.startswith(b"\xff\xd8"):
        return None
    i, n = 2, len(data)
    while i + 9 < n:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7 or marker == 0xFF:
            i += 1 if marker == 0xFF else 2
            continue
        length = int.from_bytes(data[i + 2:i + 4], "big")
        if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            h = int.from_bytes(data[i + 5:i + 7], "big")
            w = int.from_bytes(data[i + 7:i + 9], "big")
            return w, h
        i += 2 + length
    return None


def image_type(data):
    return "image/png" if data.startswith(b"\x89PNG") else "image/jpeg"


def sips_convert(src, max_side, size):
    """macOS: an exported TIFF -> JPEG bytes, scaled down to max_side (never up)."""
    with tempfile.TemporaryDirectory(prefix="smartpreview-") as tmp:
        dst = os.path.join(tmp, "frame.jpg")
        cmd = ["sips", "-s", "format", "jpeg", "-s", "formatOptions", str(JPEG_QUALITY)]
        if max_side and size and max(size) > max_side:
            cmd += ["-Z", str(max_side)]
        r = subprocess.run(cmd + [src, "--out", dst], capture_output=True)
        if r.returncode != 0 or not os.path.exists(dst):
            raise OSError("sips could not convert the frame: " + r.stderr.decode("utf-8", "replace").strip())
        with open(dst, "rb") as f:
            return f.read()


def pillow_convert(src, max_side, size):
    from io import BytesIO
    from PIL import Image
    with Image.open(src) as img:
        img.load()
        if max_side and max(img.size) > max_side:
            img.thumbnail((max_side, max_side), Image.LANCZOS)
        out = BytesIO()
        img.convert("RGB").save(out, "JPEG", quality=JPEG_QUALITY)
        return out.getvalue()


def find_converter():
    """TIFF -> JPEG converter, or None (then frames are PNG at the document's size)."""
    if sys.platform == "darwin" and shutil.which("sips"):
        return sips_convert
    try:
        import PIL.Image  # noqa: F401  optional
        return pillow_convert
    except ImportError:
        return None


# ----------------------------------------------------------------- network

def lan_addresses():
    addrs = set()
    for probe in ("10.255.255.255", "192.168.255.255", "100.100.100.100"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((probe, 1))
            addrs.add(s.getsockname()[0])
            s.close()
        except OSError:
            pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addrs.add(info[4][0])
    except OSError:
        pass
    return sorted(a for a in addrs if not a.startswith(("127.", "169.254.", "0.")))


def split_target(target):
    """'192.168.1.5', '192.168.1.5:8767', 'http://phone.local:8767/' -> (host, port)."""
    t = re.sub(r"^\w+://", "", target.strip()).split("/", 1)[0]
    if t.startswith("["):
        host, _, rest = t[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    elif t.count(":") == 1:
        host, port = t.split(":")
    else:
        host, port = t, ""
    if not host:
        raise ValueError("empty address")
    return host, int(port) if port else PHONE_PORT


def parse_targets(text):
    if isinstance(text, (list, tuple)):
        items = text
    else:
        items = re.split(r"[,\s;]+", text or "")
    out = []
    for item in items:
        item = str(item).strip()
        if item and item not in out:
            split_target(item)  # validates
            out.append(item)
    return out


def post_frame(target, jpeg, name):
    host, port = split_target(target)
    conn = http.client.HTTPConnection(host, port, timeout=SEND_TIMEOUT)
    try:
        conn.request("POST", "/frame?name=" + quote(name or "", safe=""), body=jpeg,
                     headers={"Content-Type": image_type(jpeg), "Content-Length": str(len(jpeg))})
        r = conn.getresponse()
        body = r.read(200)
        if r.status != 200:
            raise OSError(f"HTTP {r.status} {body.decode('utf-8', 'replace').strip()}")
    finally:
        conn.close()


def discover_phones(timeout=DISCOVERY_TIMEOUT, port=PHONE_PORT):
    """Ask SmartPreview phones on the local networks to answer.

    Phones in Wi-Fi power saving often sleep through broadcasts, so the broadcast is
    repeated, and each address of this computer's private /24 networks also gets one
    unicast query, which the access point holds until the phone wakes.
    """
    found = {}
    lan = [ip for ip in lan_addresses() if ip.startswith(("10.", "192.168.")) or re.match(r"172\.(1[6-9]|2\d|3[01])\.", ip)]
    broadcasts = ["255.255.255.255"] + [ip.rsplit(".", 1)[0] + ".255" for ip in lan]
    unicast = [f"{ip.rsplit('.', 1)[0]}.{n}" for ip in lan for n in range(1, 255) if f"{ip.rsplit('.', 1)[0]}.{n}" != ip]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(dests):
        for d in dests:
            try:
                s.sendto(DISCOVERY_QUERY, (d, port))
            except OSError:
                pass

    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.bind(("", 0))
        s.settimeout(0.1)
        send(broadcasts)
        send(unicast)
        deadline, next_broadcast = time.time() + timeout, time.time() + 0.3
        while time.time() < deadline:
            if time.time() >= next_broadcast:
                send(broadcasts)
                next_broadcast = time.time() + 0.3
            try:
                data, addr = s.recvfrom(512)
            except OSError:
                # Timeouts, and ICMP errors from queries to other networks, which macOS
                # reports on the next receive.
                continue
            if not data.startswith(DISCOVERY_REPLY):
                continue
            parts = data[len(DISCOVERY_REPLY):].decode("utf-8", "replace").strip().split(" ", 1)
            try:
                p = int(parts[0])
            except (ValueError, IndexError):
                p = port
            address = addr[0] if p == PHONE_PORT else f"{addr[0]}:{p}"
            found[address] = {"address": address, "name": parts[1] if len(parts) > 1 else addr[0]}
    finally:
        s.close()
    return sorted(found.values(), key=lambda x: x["address"])


# ------------------------------------------------------------------ bridge

class FrameHub:
    """The latest frame, for browsers that long-poll /frame?v=N."""

    def __init__(self):
        self.version, self.jpeg = 0, b""
        self.cond = threading.Condition()

    def publish(self, image):
        with self.cond:
            self.version += 1
            self.jpeg = image
            self.cond.notify_all()

    def wait_newer(self, seen, timeout):
        with self.cond:
            self.cond.wait_for(lambda: self.version > seen, timeout=timeout)
            return self.version, self.jpeg


class Bridge:
    def __init__(self, args):
        self.args = args
        self.dir = app_dir()
        self.frames_dir = os.path.join(self.dir, "frames")
        self.token_path = os.path.join(self.dir, "control.token")
        self.settings_path = os.path.join(self.dir, "settings.json")
        os.makedirs(self.frames_dir, exist_ok=True)
        self.own_token = ensure_token(self.token_path)
        self.hub = FrameHub()
        self.pool = ThreadPoolExecutor(max_workers=8)
        self.lock = threading.Lock()
        self.wake = threading.Event()
        self.stop_event = threading.Event()
        self.client = None
        self.client_label = None
        self.convert = find_converter()
        self.seq = 0
        self.last_signature = None
        self.force = False
        self.launched_at = 0
        self.auto_launch_done = False
        self.http_port = None
        self.found = []
        self.state = {
            "photocraft": "connecting", "message": "", "document": None,
            "frame": None, "targets": {}, "frames": 0,
        }
        self.settings = {"phones": [], "maxSide": 2400, "live": True, "mode": "quiet"}
        self._load_settings()
        if args.phones is not None:
            self.settings["phones"] = parse_targets(args.phones)
        if args.size is not None:
            self.settings["maxSide"] = args.size
        if getattr(args, "fast", False):
            self.settings["mode"] = "fast"
        self._clean_frames()

    # settings ---------------------------------------------------------

    def _load_settings(self):
        try:
            with open(self.settings_path, "r", encoding="utf-8") as f:
                saved = json.load(f)
            self.settings["phones"] = parse_targets(saved.get("phones", []))
            if saved.get("maxSide") in SIZES:
                self.settings["maxSide"] = saved["maxSide"]
            self.settings["live"] = bool(saved.get("live", True))
            if saved.get("mode") in MODES:
                self.settings["mode"] = saved["mode"]
        except (OSError, ValueError):
            pass

    def save_settings(self):
        try:
            tmp = self.settings_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.settings, f, indent=1)
            os.replace(tmp, self.settings_path)
        except OSError:
            pass

    def update_settings(self, phones=None, max_side=None, live=None, mode=None):
        with self.lock:
            if phones is not None:
                self.settings["phones"] = parse_targets(phones)
                self.state["targets"] = {}
            if max_side is not None:
                if max_side not in SIZES:
                    raise ValueError("unsupported size")
                self.settings["maxSide"] = max_side
            if live is not None:
                self.settings["live"] = bool(live)
            if mode is not None:
                if mode not in MODES:
                    raise ValueError("unsupported export mode")
                self.settings["mode"] = mode
            self.last_signature = None  # resend with the new settings
        self.save_settings()
        self.wake.set()

    def send_once(self):
        with self.lock:
            self.force = True
        self.wake.set()

    def _clean_frames(self):
        for name in os.listdir(self.frames_dir):
            if name.startswith("smartpreview-"):
                try:
                    os.remove(os.path.join(self.frames_dir, name))
                except OSError:
                    pass

    def _set(self, **kw):
        with self.lock:
            self.state.update(kw)

    # connection -------------------------------------------------------

    def _connect(self):
        last_error = None
        for label, port, token_file in connection_candidates(self.args, self.token_path):
            try:
                token = self.own_token if token_file == self.token_path else read_token(token_file)
                client = ControlClient(port, token)
                client.connect()
                self.client, self.client_label = client, label
                self.auto_launch_done = True
                self._log(f"connected to PhotoCraft on 127.0.0.1:{port} ({label})")
                return True
            except (OSError, ValueError, ControlError) as e:
                last_error = e
        running = photocraft_running()
        # Start PhotoCraft once, when SmartPreview starts; never reopen it after the user quits it.
        if not running and not self.args.no_launch and not self.auto_launch_done:
            self.auto_launch_done = True
            try:
                self.launch()
                return False
            except ControlError as e:
                self._set(photocraft="error", message=str(e))
                return False
        self.auto_launch_done = True
        if not running:
            if time.time() - self.launched_at < 60:
                self._set(photocraft="starting", message="Waiting for PhotoCraft to start")
            else:
                self._set(photocraft="stopped", message="PhotoCraft is not running")
        elif time.time() - self.launched_at < 60:
            self._set(photocraft="starting", message="Waiting for PhotoCraft to start")
        else:
            self._set(photocraft="no-access",
                      message="PhotoCraft is running without SmartPreview access. Save your work, quit "
                              "PhotoCraft and press Open PhotoCraft here (or restart SmartPreview).")
        if isinstance(last_error, AuthError):
            self._log_once(f"PhotoCraft refused access: {last_error}")
        return False

    def launch(self):
        if photocraft_running():
            raise ControlError("PhotoCraft is already running; quit it first so it can start with the control server")
        launch_photocraft(self.args.control_port or CONTROL_PORT, self.token_path, self.frames_dir)
        self.launched_at = time.time()
        self._set(photocraft="starting", message="Starting PhotoCraft")
        self._log("starting PhotoCraft with the control server on")

    # frames -----------------------------------------------------------

    def capture(self, doc):
        """Export the active document through PhotoCraft's write root and return the frame.

        PhotoCraft's desktop control has no render call, so the frame is an export, and
        every export warning pops up as a notice card in PhotoCraft. Flat formats always
        warn for layered documents ("N layer(s) flattened"), JPEG also about lossy
        compression. A layered TIFF exports without warnings and without retargeting the
        document's path (PSD/PSB would make Cmd+S save into the frames folder), so it is
        the "quiet" mode; it costs more as layers add up. The "fast" mode exports a flat
        TIFF (about 35 ms) and PhotoCraft shows a notice for each frame of a layered
        document. Either TIFF is converted to JPEG here; without a converter the frame
        is a PNG.
        """
        self.seq += 1
        w, h = int(doc.get("width") or 0), int(doc.get("height") or 0)
        if self.convert:
            name = f"smartpreview-{os.getpid()}-{self.seq}.tif"
            params = {"path": name, "tiffLayers": self.settings["mode"] == "quiet",
                      "tiffCompression": "lzw" if w * h > 4_000_000 else "none"}
        else:
            name = f"smartpreview-{os.getpid()}-{self.seq}.png"
            params = {"path": name}
        result = self.client.call("app.save", params)
        written = result.get("path") if isinstance(result, dict) else None
        candidates = []
        if written:
            candidates.append(written if os.path.isabs(written) else os.path.join(self.frames_dir, written))
        candidates.append(os.path.join(self.frames_dir, name))
        path = next((p for p in candidates if os.path.isfile(p)), None)
        if not path:
            raise ControlError("PhotoCraft saved the frame outside the SmartPreview folder "
                               f"({written or name}); start PhotoCraft from SmartPreview")
        try:
            if self.convert:
                try:
                    return self.convert(path, self.settings["maxSide"], (w, h))
                except Exception as e:  # noqa: BLE001  any converter failure
                    raise ControlError(f"cannot convert the frame: {e}") from e
            with open(path, "rb") as f:
                return f.read()
        finally:
            try:
                os.remove(path)
            except OSError:
                pass

    def deliver(self, jpeg, doc_name):
        self.hub.publish(jpeg)
        phones = list(self.settings["phones"])
        results = {}

        def one(target):
            try:
                post_frame(target, jpeg, doc_name)
                return target, {"ok": True, "message": "ok", "time": time.time()}
            except (OSError, ValueError, http.client.HTTPException) as e:
                return target, {"ok": False, "message": str(e) or e.__class__.__name__, "time": time.time()}

        for target, res in self.pool.map(one, phones):
            results[target] = res
        return results

    def step(self):
        session = self.client.call("engine.execute", {"command": "session.inspect"})
        doc = active_document(session)
        signature = document_signature(session)
        with self.lock:
            live, force = self.settings["live"], self.force
            self.state["photocraft"] = "connected"
            self.state["message"] = ""
            self.state["document"] = None if not doc else {
                "name": doc.get("name"), "width": doc.get("width"),
                "height": doc.get("height"), "revision": doc.get("revision"),
            }
        if not doc:
            self.last_signature = None
            return
        if not force and (not live or signature == self.last_signature):
            return
        with self.lock:
            self.force = False
        started = time.time()
        jpeg = self.capture(doc)
        results = self.deliver(jpeg, doc.get("name") or "")
        self.last_signature = signature
        size = image_size(jpeg) or (0, 0)
        with self.lock:
            self.state["targets"].update(results)
            self.state["frames"] += 1
            self.state["frame"] = {"time": time.time(), "kb": round(len(jpeg) / 1024),
                                   "width": size[0], "height": size[1],
                                   "ms": round((time.time() - started) * 1000)}
        failed = [t for t, r in results.items() if not r["ok"]]
        self._log(f"frame {size[0]}x{size[1]} {len(jpeg) // 1024} KB "
                  f"{self.state['frame']['ms']} ms -> "
                  f"{len(results) - len(failed)}/{len(results)} phone(s)"
                  + (f"; unavailable: {', '.join(failed)}" if failed else ""))

    def run(self):
        while not self.stop_event.is_set():
            if self.client is None or not self.client.connected:
                if self.client is not None:
                    self.client = None
                if not self._connect():
                    self.wake.wait(2)
                    self.wake.clear()
                    continue
            try:
                self.step()
                delay = POLL_SECONDS
            except AuthError as e:
                self._set(photocraft="no-access", message=str(e))
                self.client = None
                delay = 2
            except ControlError as e:
                text = str(e)
                if self.client is not None and not self.client.connected:
                    self.client = None
                    self._set(photocraft="connecting", message=text)
                else:
                    # A modal dialog, a running command... try again on the next change.
                    self._set(message=text)
                    self.last_signature = None
                delay = 1
            self.wake.wait(delay)
            self.wake.clear()

    # status -----------------------------------------------------------

    _last_logged = None

    def _log(self, text):
        print(time.strftime("%H:%M:%S ") + text, flush=True)

    def _log_once(self, text):
        if text != self._last_logged:
            self._last_logged = text
            self._log(text)

    def snapshot(self):
        with self.lock:
            s = json.loads(json.dumps(self.state))
            s.update({
                "live": self.settings["live"], "phones": self.settings["phones"],
                "maxSide": self.settings["maxSide"], "sizes": list(SIZES),
                "mode": self.settings["mode"], "converter": self.convert is not None,
                "found": self.found, "version": VERSION,
                "viewerUrls": [f"http://{a}:{self.http_port}/" for a in lan_addresses()],
                "canLaunch": s["photocraft"] in ("stopped", "no-access", "error"),
                "frameFolder": self.frames_dir,
            })
        return s


# -------------------------------------------------------------- web server

def make_handler(bridge):
    with open(os.path.join(HERE, "viewer.html"), "rb") as f:
        viewer_html = f.read()
    with open(os.path.join(HERE, "panel.html"), "rb") as f:
        panel_html = f.read()
    with open(os.path.join(HERE, "cutouts.json"), "rb") as f:
        cutouts_json = f.read()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            pass

        def send_body(self, status, body, content_type, extra=None):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def send_json(self, obj, status=200):
            self.send_body(status, json.dumps(obj).encode("utf-8"), "application/json; charset=utf-8")

        def local_only(self):
            """The panel and its API answer only this computer, and only under a local Host
            name, so other devices and web pages (DNS rebinding) cannot reach them."""
            client = self.client_address[0]
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
            ok = client in ("127.0.0.1", "::1", "::ffff:127.0.0.1") and host in ("127.0.0.1", "localhost", "::1")
            if not ok:
                self.send_body(403, b"SmartPreview panel is available only on this computer", "text/plain")
            return ok

        def do_GET(self):
            path, _, query = self.path.partition("?")
            if path in ("/", "/index.html"):
                return self.send_body(200, viewer_html, "text/html; charset=utf-8")
            if path == "/cutouts.json":
                return self.send_body(200, cutouts_json, "application/json; charset=utf-8")
            if path == "/frame":
                params = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
                try:
                    seen = int(params.get("v", "0"))
                except ValueError:
                    seen = 0
                version, jpeg = bridge.hub.wait_newer(seen, LONG_POLL_SECONDS)
                if version <= seen or not jpeg:
                    return self.send_body(204, b"", "text/plain", {"X-Version": str(version)})
                return self.send_body(200, jpeg, image_type(jpeg), {"X-Version": str(version)})
            if path == "/panel":
                if self.local_only():
                    self.send_body(200, panel_html, "text/html; charset=utf-8")
                return
            if path == "/api/state":
                if self.local_only():
                    self.send_json(bridge.snapshot())
                return
            self.send_body(404, b"not found", "text/plain")

        def do_POST(self):
            if not self.local_only():
                return
            # A custom header forces a CORS preflight, which is never answered: web pages
            # cannot drive the panel API, only the panel itself (same origin).
            if self.headers.get("X-SmartPreview") != "1":
                return self.send_body(403, b"missing X-SmartPreview header", "text/plain")
            try:
                length = min(int(self.headers.get("Content-Length", "0")), 64 * 1024)
            except ValueError:
                length = 0
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(body, dict):
                    raise ValueError("expected an object")
            except ValueError:
                return self.send_json({"error": "bad JSON"}, 400)
            path = self.path.split("?")[0]
            try:
                if path == "/api/settings":
                    max_side = body.get("maxSide")
                    bridge.update_settings(phones=body.get("phones"),
                                           max_side=None if max_side is None else int(max_side),
                                           live=body.get("live"), mode=body.get("mode"))
                elif path == "/api/send":
                    bridge.send_once()
                elif path == "/api/discover":
                    bridge.found = discover_phones()
                elif path == "/api/launch":
                    bridge.launch()
                else:
                    return self.send_json({"error": "not found"}, 404)
            except (ValueError, ControlError) as e:
                return self.send_json({"error": str(e)}, 400)
            self.send_json(bridge.snapshot())

    return Handler


def start_http(bridge, port):
    handler = make_handler(bridge)
    last = None
    for p in [port] + ([] if port == 0 else list(range(port + 1, port + 10))):
        try:
            server = ThreadingHTTPServer(("0.0.0.0", p), handler)
            break
        except OSError as e:
            last = e
    else:
        raise SystemExit(f"cannot open the SmartPreview web server: {last}")
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, name="http", daemon=True).start()
    bridge.http_port = server.server_address[1]
    return server


# -------------------------------------------------------------------- main

def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Live PhotoCraft canvas preview on Android and phone browsers.")
    p.add_argument("--phones", help="phone addresses, comma-separated (default: the saved ones)")
    p.add_argument("--size", type=int, choices=SIZES, help="longest side in px, 0 = document size (default 2400)")
    p.add_argument("--fast", action="store_true",
                   help="flat export: faster, but PhotoCraft shows a notice for each frame of a layered document")
    p.add_argument("--control-port", type=int, help=f"PhotoCraft control port (default {CONTROL_PORT})")
    p.add_argument("--token-file", help="PhotoCraft control token file, for a PhotoCraft you started yourself")
    p.add_argument("--http-port", type=int, default=int(os.environ.get("SMARTPREVIEW_PORT", HTTP_PORT)),
                   help=f"panel and browser viewer port (default {HTTP_PORT})")
    p.add_argument("--no-launch", action="store_true", help="never start PhotoCraft")
    p.add_argument("--no-browser", action="store_true", help="do not open the panel in the browser")
    p.add_argument("--once", action="store_true", help="send one frame and exit")
    p.add_argument("--discover", action="store_true", help="list SmartPreview phones on the network and exit")
    p.add_argument("--version", action="version", version=VERSION)
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.discover:
        phones = discover_phones()
        for ph in phones:
            print(f"{ph['address']}\t{ph['name']}")
        if not phones:
            print("No SmartPreview phones answered. Open the app on the phone; same Wi-Fi network.")
        return 0 if phones else 1

    bridge = Bridge(args)

    if args.once:
        deadline = time.time() + 90
        while time.time() < deadline:
            if bridge._connect():
                bridge.send_once()
                try:
                    bridge.step()
                except ControlError as e:
                    print(f"error: {e}", file=sys.stderr)
                    return 1
                return 0 if all(r["ok"] for r in bridge.state["targets"].values()) else 1
            if bridge.state["photocraft"] not in ("starting",):
                print(f"error: {bridge.state['message']}", file=sys.stderr)
                return 1
            time.sleep(2)
        print("error: PhotoCraft did not start in time", file=sys.stderr)
        return 1

    start_http(bridge, args.http_port)
    panel = f"http://localhost:{bridge.http_port}/panel"
    print(f"\n  SmartPreview {VERSION}\n\n  Panel:            {panel}")
    for url in bridge.snapshot()["viewerUrls"]:
        print(f"  Phone browser:    {url}")
    phones = bridge.settings["phones"]
    print(f"  Android phones:   {', '.join(phones) if phones else '(none yet: add them in the panel)'}")
    print("\n  Close this window or press Ctrl+C to stop.\n", flush=True)
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(panel)).start()
    try:
        bridge.run()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
