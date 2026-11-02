"""App logic + a tiny local web server (127.0.0.1 only) that serves the Persian UI."""
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
import secrets

from . import builder, scanner, sysproxy, xray
from .parser import parse_line

DEFAULTS = {"max_ping": 150, "max_real": 1500, "bypass_ir": True, "mode": "proxy", "extra_sources": ""}
BACKUP = xray.APP_DIR / "proxy_backup.json"


def pick_port(preferred):
    """The preferred port if it is free, otherwise any free one."""
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", preferred))
        return preferred
    except OSError:
        return scanner.free_port()
    finally:
        s.close()


class App:
    def __init__(self, sources=None, xray_cmd=None, test_url=None):
        self.token = secrets.token_urlsafe(16)
        self.sources = list(sources if sources is not None else scanner.DEFAULT_SOURCES)
        self._xray_cmd_override = xray_cmd
        self.test_url = test_url or scanner.TEST_URL
        self.settings = dict(DEFAULTS)
        self.lock = threading.RLock()
        self.conn_lock = threading.Lock()
        self.cancel = threading.Event()
        self.scan_gen = 0
        self.conn_gen = 0
        self.scan = {"phase": "idle", "message": "", "done": 0, "total": 0, "found": 0}
        self.results = []
        self.conn = {"state": "disconnected", "message": "", "delay": 0, "index": -1}
        self.session = None
        self.sys_saved = None
        self.recover_proxy()
        threading.Thread(target=self._watchdog, daemon=True).start()

    # ------------------------------------------------------------ helpers
    def _xray_cmd(self):
        if self._xray_cmd_override:
            return list(self._xray_cmd_override)
        p = xray.find_xray()
        return [p] if p else None

    def snapshot(self):
        with self.lock:
            res = [{"idx": i, "protocol": c.protocol, "host": c.host, "port": c.port,
                    "name": c.name, "ping_ms": c.ping_ms, "real_ms": c.real_ms,
                    "tested": c.tested_source, "raw": c.raw} for i, c in enumerate(self.results)]
            return {"scan": dict(self.scan), "results": res, "conn": dict(self.conn),
                    "settings": dict(self.settings),
                    "env": {"xray": self._xray_cmd() is not None, "windows": sysproxy.IS_WINDOWS,
                            "admin": sysproxy.is_admin(), "wintun": xray.has_wintun()}}

    def update_settings(self, data):
        with self.lock:
            s = self.settings
            if "max_ping" in data:
                s["max_ping"] = max(20, min(1000, int(data["max_ping"])))
            if "max_real" in data:
                s["max_real"] = max(100, min(10000, int(data["max_real"])))
            if "bypass_ir" in data:
                s["bypass_ir"] = bool(data["bypass_ir"])
            if data.get("mode") in ("proxy", "tun"):
                s["mode"] = data["mode"]
            if "extra_sources" in data:
                s["extra_sources"] = str(data["extra_sources"])[:5000]

    def _set_scan(self, gen, phase, message, done=0, total=0, found=0):
        with self.lock:
            if gen == self.scan_gen:
                self.scan = {"phase": phase, "message": message, "done": done, "total": total, "found": found}

    def _set_conn(self, state, message="", delay=0, index=-1):
        with self.lock:
            self.conn = {"state": state, "message": message, "delay": delay, "index": index}

    # ------------------------------------------------------------ scanning
    def start_scan(self, auto=False):
        with self.lock:
            self.cancel.set()
            self.cancel = threading.Event()
            self.scan_gen += 1
            gen, cancel = self.scan_gen, self.cancel
            self.results = []
            self.scan = {"phase": "loading", "message": "در حال دریافت لیست کانفیگ‌ها…",
                         "done": 0, "total": 0, "found": 0}
        threading.Thread(target=self._scan, args=(gen, cancel, auto), daemon=True).start()

    def cancel_scan(self):
        with self.lock:
            self.cancel.set()
            self.scan_gen += 1
            self.scan = {"phase": "idle", "message": "لغو شد.", "done": 0, "total": 0, "found": 0}

    def _scan(self, gen, cancel, auto):
        try:
            s = dict(self.settings)
            urls = list(self.sources)
            for line in s["extra_sources"].splitlines():
                u = line.strip()
                if u.startswith(("http://", "https://")):
                    urls.append(u)
            configs, ok = scanner.load_configs(urls)
            if cancel.is_set():
                return
            if not configs:
                self._set_scan(gen, "error", "لیستی دریافت نشد (%d از %d منبع در دسترس بود). "
                               "اینترنت رو چک کن یا در تنظیمات منبع اضافه کن." % (ok, len(urls)))
                return
            self._set_scan(gen, "tcp", "مرحله ۱: تست اتصال روی %d کانفیگ…" % len(configs))
            reachable = scanner.scan_tcp(
                configs, s["max_ping"], cancel=cancel,
                progress=lambda d, t, f: self._set_scan(gen, "tcp", "مرحله ۱: تست اتصال", d, t, f))
            if cancel.is_set():
                return
            if not reachable:
                self._set_scan(gen, "error", "هیچ سروری با پینگ اتصال زیر %d ms جواب نداد. "
                               "VPN/پروکسی رو خاموش کن و دوباره بزن، یا سقف پینگ رو بالاتر ببر." % s["max_ping"])
                return
            cmd = self._xray_cmd()
            if cmd is None:
                with self.lock:
                    self.results = reachable
                self._set_scan(gen, "done", "⚠️ هسته‌ی Xray پیدا نشد؛ فقط پینگ اتصال نشون داده میشه و "
                               "ممکنه کانفیگ‌ها وصل نشن. %d کانفیگ." % len(reachable), found=len(reachable))
                return
            verified = scanner.verify_real(
                reachable, cmd, s["max_real"], cancel=cancel, url=self.test_url,
                progress=lambda d, t, f: self._set_scan(gen, "real", "مرحله ۲: تست واقعی با هسته‌ی Xray", d, t, f))
            if cancel.is_set():
                return
            with self.lock:
                self.results = verified
            if not verified:
                self._set_scan(gen, "error", "هیچ کانفیگی تست واقعی رو پاس نکرد (زیر %d ms). "
                               "یه بار دیگه بزن یا «حداکثر پینگ واقعی» رو بالاتر ببر." % s["max_real"])
                return
            self._set_scan(gen, "done", "✔ %d کانفیگ واقعاً کار کرد." % len(verified), found=len(verified))
            if auto:
                self.connect(0, auto=True)
        except Exception as e:  # never let a thread die silently
            self._set_scan(gen, "error", "خطا: %s" % e)

    # ------------------------------------------------------------ connecting
    def connect(self, index, auto=False):
        with self.lock:
            self.conn_gen += 1
            g = self.conn_gen
            self.conn = {"state": "connecting", "message": "در حال اتصال…", "delay": 0, "index": index}
        threading.Thread(target=self._connect_worker, args=(g, index, auto), daemon=True).start()

    def disconnect(self):
        with self.lock:
            self.conn_gen += 1
            self.conn = {"state": "disconnected", "message": "", "delay": 0, "index": -1}

        def work():
            with self.conn_lock:
                self._teardown()
        threading.Thread(target=work, daemon=True).start()

    def _connect_worker(self, g, index, auto):
        with self.conn_lock:
            tries = 0
            while True:
                if g != self.conn_gen:
                    return
                self._teardown()
                with self.lock:
                    cfgs = list(self.results)
                if not 0 <= index < len(cfgs):
                    self._set_conn("failed", "کانفیگی انتخاب نشده.")
                    return
                self._set_conn("connecting", "در حال اتصال به %s…" % cfgs[index].host, 0, index)
                ok, msg, delay = self._try_connect(cfgs[index])
                if g != self.conn_gen:
                    self._teardown()
                    return
                if ok:
                    c = cfgs[index]
                    self._set_conn("connected", "%s  %s" % (c.protocol.upper(), c.host), delay, index)
                    return
                self._set_conn("failed", msg, 0, index)
                if not (auto and tries < 4 and index + 1 < len(cfgs)):
                    return
                tries += 1
                index += 1

    def _try_connect(self, c):
        cmd = self._xray_cmd()
        if cmd is None:
            return False, "هسته‌ی Xray (xray.exe) کنار برنامه نیست.", 0
        try:
            ip = scanner.resolve(c.host)  # resolve now, before any tunnel exists
        except Exception:
            return False, "آدرس سرور پیدا نشد.", 0
        s = dict(self.settings)
        sess = xray.Session(cmd)
        try:
            if s["mode"] == "tun":
                if sysproxy.IS_WINDOWS and not sysproxy.is_admin():
                    return False, "برای VPN کامل برنامه رو با Run as administrator باز کن.", 0
                if sysproxy.IS_WINDOWS and not xray.has_wintun():
                    return False, "فایل wintun.dll کنار xray.exe نیست.", 0
                check = scanner.free_port()
                conf = builder.tun_config(c, ip, check, s["bypass_ir"])
                if conf is None:
                    return False, "این نوع کانفیگ پشتیبانی نمیشه.", 0
                sess.start(conf, wait_port=check)
                delay = scanner.http_via_proxy(check, self.test_url)
            else:
                socks, http = pick_port(10808), pick_port(10809)
                conf = builder.proxy_mode_config(c, ip, socks, http, s["bypass_ir"])
                if conf is None:
                    return False, "این نوع کانفیگ پشتیبانی نمیشه.", 0
                sess.start(conf, wait_port=http)
                delay = scanner.http_via_proxy(http, self.test_url)
            if delay <= 0:
                sess.stop()
                return False, "وصل شد ولی ترافیک رد نمیشه؛ کانفیگ بعدی رو امتحان کن.", 0
            if s["mode"] != "tun":
                self.sys_saved = sysproxy.get_state()
                self._write_backup(self.sys_saved)
                sysproxy.enable("127.0.0.1:%d" % http)
            self.session = sess
            return True, "", delay
        except Exception as e:
            sess.stop()
            return False, str(e)[:300], 0

    def _teardown(self):
        """Stop the core and give the PC its old proxy settings back."""
        if self.session is not None:
            self.session.stop()
            self.session = None
        if self.sys_saved is not None:
            try:
                sysproxy.restore(self.sys_saved)
            finally:
                self.sys_saved = None
                try:
                    BACKUP.unlink()
                except OSError:
                    pass

    def _watchdog(self):
        """If the core dies while 'connected', undo the system proxy so the internet is not left broken."""
        while True:
            time.sleep(2)
            with self.lock:
                connected = self.conn["state"] == "connected"
            if connected and self.session is not None and not self.session.alive():
                with self.conn_lock:
                    self._teardown()
                self._set_conn("failed", "هسته‌ی Xray متوقف شد؛ اتصال قطع شد.")

    # ------------------------------------------------------------ crash safety
    def _write_backup(self, state):
        try:
            BACKUP.parent.mkdir(parents=True, exist_ok=True)
            BACKUP.write_text(json.dumps(state), encoding="utf-8")
        except OSError:
            pass

    def recover_proxy(self):
        """A previous run may have crashed with our proxy still switched on."""
        try:
            if BACKUP.exists():
                sysproxy.restore(json.loads(BACKUP.read_text(encoding="utf-8")))
                BACKUP.unlink()
        except Exception:
            pass

    def shutdown(self):
        self.cancel.set()
        with self.conn_lock:
            self._teardown()


# ====================================================================== HTTP

def make_server(app, ui_dir, port=0):
    ui_dir = Path(ui_dir)

    class Handler(BaseHTTPRequestHandler):
        server_version = "ConfigFinder"

        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json; charset=utf-8"):
            data = body if isinstance(body, bytes) else body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _host_ok(self):
            # blocks DNS-rebinding: only our own address is accepted
            p = self.server.server_address[1]
            return (self.headers.get("Host") or "").lower() in ("127.0.0.1:%d" % p, "localhost:%d" % p)

        def _token_ok(self):
            return secrets.compare_digest(self.headers.get("X-Token", ""), app.token)

        def do_GET(self):
            if not self._host_ok():
                return self._send(403, "forbidden", "text/plain")
            u = urlparse(self.path)
            if u.path == "/":
                if parse_qs(u.query).get("t", [""])[0] != app.token:
                    return self._send(403, "Open the link printed in the console window.", "text/plain")
                html = (ui_dir / "index.html").read_text(encoding="utf-8").replace("__TOKEN__", app.token)
                return self._send(200, html, "text/html; charset=utf-8")
            if u.path.startswith("/api/"):
                if not self._token_ok():
                    return self._send(403, "forbidden", "text/plain")
                if u.path == "/api/state":
                    return self._send(200, json.dumps(app.snapshot()))
            self._send(404, "not found", "text/plain")

        def do_POST(self):
            if not self._host_ok() or not self._token_ok():
                return self._send(403, "forbidden", "text/plain")
            try:
                n = min(int(self.headers.get("Content-Length") or 0), 100_000)
                data = json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                return self._send(400, '{"error":"bad json"}')
            path = urlparse(self.path).path
            try:
                if path == "/api/scan":
                    app.start_scan(auto=bool(data.get("auto")))
                elif path == "/api/cancel":
                    app.cancel_scan()
                elif path == "/api/connect":
                    app.connect(int(data.get("index", 0)))
                elif path == "/api/disconnect":
                    app.disconnect()
                elif path == "/api/settings":
                    app.update_settings(data)
                else:
                    return self._send(404, '{"error":"unknown"}')
            except (ValueError, TypeError):
                return self._send(400, '{"error":"bad value"}')
            self._send(200, '{"ok":true}')

    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.daemon_threads = True
    return srv
