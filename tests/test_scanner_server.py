import base64
import http.client
import http.server
import json
import os
import socket
import sys
import threading
import time
import unittest
from pathlib import Path

from cf import scanner, server
from cf.parser import parse_line

FAKE = [sys.executable, str(Path(__file__).with_name("fake_xray.py"))]
URL = "http://probe.test/generate_204"


def vless(port, name="n", extra="security=none&type=tcp"):
    return parse_line("vless://11111111-2222-3333-4444-555555555555@127.0.0.1:%d?%s#%s" % (port, extra, name))


class Listeners:
    """Open TCP ports that accept and close, like a live proxy server would."""
    def __init__(self, n):
        self.socks = [socket.socket() for _ in range(n)]
        for s in self.socks:
            s.bind(("127.0.0.1", 0))
            s.listen(50)
        self.ports = [s.getsockname()[1] for s in self.socks]
        self.stop = False
        for s in self.socks:
            threading.Thread(target=self._acc, args=(s,), daemon=True).start()

    def _acc(self, s):
        while not self.stop:
            try:
                c, _ = s.accept()
                c.close()
            except OSError:
                return

    def close(self):
        self.stop = True
        for s in self.socks:
            s.close()


class Lists:
    """A local HTTP server that serves config lists."""
    def __init__(self, files):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = files.get(self.path)
                if body is None:
                    self.send_response(404); self.end_headers(); return
                self.send_response(200); self.end_headers(); self.wfile.write(body.encode())
            def log_message(self, *a):
                pass
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.srv.server_address[1]

    def close(self):
        self.srv.shutdown()


class ScannerTests(unittest.TestCase):
    def test_tcp_scan_keeps_only_live_endpoints(self):
        L = Listeners(1)
        closed = socket.socket(); closed.bind(("127.0.0.1", 0)); dead_port = closed.getsockname()[1]; closed.close()
        good, dead = vless(L.ports[0], "good"), vless(dead_port, "dead")
        tls_on_plain = vless(L.ports[0], "tlsfail", "security=tls&sni=example.com&type=tcp")
        res = scanner.scan_tcp([dead, good, tls_on_plain], max_ping=150)
        L.close()
        self.assertEqual([c.name for c in res], ["good"])
        self.assertTrue(0 <= res[0].ping_ms <= 150)
        self.assertEqual(scanner.scan_tcp([good], max_ping=-1), [])
        ev = threading.Event(); ev.set()
        self.assertEqual(scanner.scan_tcp([good], cancel=ev), [])

    def test_load_configs(self):
        a, b = vless(1111, "a"), vless(2222, "b")
        blob = base64.b64encode(("\n".join([a.raw, b.raw, "junk"])).encode()).decode()
        lists = Lists({"/sub": blob, "/top100.txt": a.raw + "\n"})
        cfgs, ok = scanner.load_configs([lists.base + "/sub", lists.base + "/top100.txt", lists.base + "/missing"])
        lists.close()
        self.assertEqual(ok, 2)
        self.assertEqual(len(cfgs), 2)
        self.assertTrue([c for c in cfgs if c.name == "a"][0].tested_source)
        self.assertFalse([c for c in cfgs if c.name == "b"][0].tested_source)

    def test_real_probe_and_verify(self):
        os.environ["FAKE_BAD"], os.environ["FAKE_HANG"] = "2003", "2004"
        try:
            ok, bad = vless(2001, "ok"), vless(2003, "bad")
            self.assertGreater(scanner.real_probe(ok, "127.0.0.1", FAKE, url=URL), 0)
            self.assertEqual(scanner.real_probe(bad, "127.0.0.1", FAKE, url=URL), -1)
            self.assertEqual(scanner.real_probe(vless(2005, "kcp", "type=kcp"), "127.0.0.1", FAKE, url=URL), -1)

            cands = [vless(2002, "slow"), vless(2003, "bad"), vless(2004, "hang"), vless(2001, "fast"),
                     vless(2005, "unsupported", "type=kcp")]
            res = scanner.verify_real(cands, FAKE, max_real=1500, want=99, url=URL, probe_timeout=1.5)
            self.assertEqual([c.name for c in res], ["fast", "slow"])
            self.assertTrue(0 < res[0].real_ms <= res[1].real_ms)
            strict = scanner.verify_real([vless(2001, "fast")], FAKE, max_real=1, url=URL)
            self.assertEqual(strict, [])
        finally:
            os.environ.pop("FAKE_BAD"); os.environ.pop("FAKE_HANG")


def wait_for(cond, secs=30):
    end = time.time() + secs
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.1)
    return False


class AppFlowTests(unittest.TestCase):
    def setUp(self):
        self.L = Listeners(3)
        p1, p2, p3 = self.L.ports
        links = [vless(p1, "one").raw, vless(p2, "two").raw, vless(p3, "three").raw]
        self.lists = Lists({"/list": "\n".join(links)})
        os.environ["FAKE_BAD"] = str(p3)
        self.app = server.App(sources=[self.lists.base + "/list"], xray_cmd=FAKE, test_url=URL)

    def tearDown(self):
        self.app.shutdown()
        self.lists.close(); self.L.close()
        os.environ.pop("FAKE_BAD", None)

    def test_scan_connect_disconnect(self):
        a = self.app
        a.start_scan()
        self.assertTrue(wait_for(lambda: a.scan["phase"] in ("done", "error")), a.scan)
        self.assertEqual(a.scan["phase"], "done", a.scan)
        names = [c.name for c in a.results]
        self.assertEqual(sorted(names), ["one", "two"])          # 'three' answers 502 -> dropped
        self.assertTrue(all(c.real_ms > 0 and c.ping_ms >= 0 for c in a.results))

        a.connect(0)
        self.assertTrue(wait_for(lambda: a.conn["state"] in ("connected", "failed")), a.conn)
        self.assertEqual(a.conn["state"], "connected", a.conn)
        self.assertGreater(a.conn["delay"], 0)
        self.assertTrue(a.session.alive())

        a.disconnect()
        self.assertTrue(wait_for(lambda: a.session is None))
        self.assertEqual(a.conn["state"], "disconnected")

    def test_auto_connect_skips_a_config_that_fails(self):
        a = self.app
        a.start_scan(auto=False)
        self.assertTrue(wait_for(lambda: a.scan["phase"] == "done"))
        first = a.results[0]
        os.environ["FAKE_BAD"] = str(first.port)       # the best one stops working before we connect
        a.connect(0, auto=True)
        self.assertTrue(wait_for(lambda: a.conn["state"] == "connected" and a.conn["index"] == 1), a.conn)
        self.assertIn(a.results[1].host, a.conn["message"])

    def test_tcp_ceiling_is_applied(self):
        a = self.app
        a.update_settings({"max_ping": 20})
        self.assertEqual(a.settings["max_ping"], 20)
        a.update_settings({"max_ping": 5, "max_real": 99999, "mode": "nonsense"})
        self.assertEqual((a.settings["max_ping"], a.settings["max_real"], a.settings["mode"]), (20, 10000, "proxy"))

    def test_http_api_security(self):
        srv = server.make_server(self.app, Path(__file__).resolve().parent.parent / "cf" / "ui")
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        port = srv.server_address[1]
        tok = self.app.token

        def req(method, path, headers=None, body=None):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            h = {"Host": "127.0.0.1:%d" % port}
            h.update(headers or {})
            c.request(method, path, body=body, headers=h)
            r = c.getresponse()
            return r.status, r.read().decode()

        self.assertEqual(req("GET", "/")[0], 403)                                   # page needs the token
        st, html = req("GET", "/?t=" + tok)
        self.assertEqual(st, 200)
        self.assertIn(tok, html); self.assertIn("حمید بوکانیان", html)
        self.assertEqual(req("GET", "/api/state")[0], 403)                          # API needs the header
        st, body = req("GET", "/api/state", {"X-Token": tok})
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(body)["conn"]["state"], "disconnected")
        self.assertEqual(req("GET", "/api/state", {"X-Token": tok, "Host": "evil.example:80"})[0], 403)  # DNS rebinding
        self.assertEqual(req("POST", "/api/settings", {"X-Token": tok}, json.dumps({"max_ping": 120}))[0], 200)
        self.assertEqual(self.app.settings["max_ping"], 120)
        self.assertEqual(req("POST", "/api/settings", {"X-Token": tok}, "{not json")[0], 400)
        self.assertEqual(req("POST", "/api/settings", {}, "{}")[0], 403)
        self.assertEqual(req("POST", "/api/nope", {"X-Token": tok}, "{}")[0], 404)
        srv.shutdown()


if __name__ == "__main__":
    unittest.main()
