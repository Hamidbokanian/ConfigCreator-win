"""Download config lists, then test them in two stages:

1. TCP connect time (+ TLS handshake for tls/reality) measured from THIS PC.
2. Real delay: each survivor is run through the Xray core and an HTTPS request is sent THROUGH it.
"""
import concurrent.futures as futures
import json
import os
import socket
import ssl
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request

from . import builder
from .parser import parse_blob

H = "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/"
B = "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/"
N = "https://raw.githubusercontent.com/nyeinkokoaung404/V2ray-Configs/main/configs/proxy_configs_tested.txt"
# the first two are lists their maintainers already checked with a real proxy test
DEFAULT_SOURCES = [H + "top100.txt", N,
                   H + "vless.txt", H + "vmess.txt", H + "trojan.txt", H + "ss.txt",
                   B + "vless.txt", B + "vmess.txt", B + "trojan.txt", B + "ss.txt"]
TEST_URL = "https://www.gstatic.com/generate_204"
MAX_BYTES = 6 * 1024 * 1024
CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


def is_tested_source(url):
    u = url.lower()
    return "top100" in u or "tested" in u


# ------------------------------------------------------------------ download

def fetch(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": "ConfigFinder/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read(MAX_BYTES)
    return data.decode("utf-8", errors="replace")


def load_configs(urls, cancel=None):
    """Returns (configs, ok_sources). A dead source never stops the others."""
    uniq = {}
    ok = 0

    def one(u):
        lst = parse_blob(fetch(u))
        tested = is_tested_source(u)
        for c in lst:
            c.tested_source = tested
        return lst

    with futures.ThreadPoolExecutor(max_workers=max(1, min(6, len(urls)))) as ex:
        futs = [ex.submit(one, u) for u in urls]
        for f in futs:
            try:
                lst = f.result(timeout=45)
            except Exception:
                continue
            ok += 1
            for c in lst:
                k = c.dedupe_key()
                prev = uniq.get(k)
                if prev is None:
                    uniq[k] = c
                elif c.tested_source:
                    prev.tested_source = True
    return list(uniq.values()), ok


# ------------------------------------------------------------------ stage 1: TCP + TLS

def resolve(host):
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    for fam, _, _, _, sa in infos:
        if fam == socket.AF_INET:
            return sa[0]
    return infos[0][4][0]


def _is_ip(s):
    try:
        socket.inet_pton(socket.AF_INET, s)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, s)
        return True
    except OSError:
        return False


def _tls_ok(ip, port, sni, timeout):
    """Handshake only; certificates are not checked (proxy servers often use unrelated ones)."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with ctx.wrap_socket(raw, server_hostname=None if _is_ip(sni) else sni):
                return True
    except Exception:
        return False


def tcp_probe(c, connect_timeout=0.4, rounds=3, tls_timeout=2.5, tls_probe=True):
    """Median TCP connect time in ms, or -1."""
    try:
        ip = resolve(c.host)
    except Exception:
        return -1
    samples = []
    for i in range(rounds):
        t0 = time.perf_counter()
        try:
            s = socket.create_connection((ip, c.port), timeout=connect_timeout)
            samples.append(int((time.perf_counter() - t0) * 1000))
            s.close()
        except OSError:
            if i == 0:
                return -1
    if len(samples) < rounds // 2 + 1:
        return -1
    if tls_probe and c.security in ("tls", "reality") and not _tls_ok(ip, c.port, c.sni, tls_timeout):
        return -1
    return int(statistics.median(samples))


def scan_tcp(configs, max_ping=150, want=40, max_candidates=800, threads=64,
             deadline=40.0, cancel=None, progress=None, **probe_kw):
    import random
    tested = [c for c in configs if c.tested_source]
    rest = [c for c in configs if not c.tested_source]
    random.shuffle(rest)
    ordered = (tested + rest)[:max_candidates]

    groups = {}
    for c in ordered:  # many links share one server: probe each endpoint once
        groups.setdefault((c.host.lower(), c.port, c.security, c.sni.lower()), []).append(c)
    total = len(groups)
    good, found, done = [], 0, 0
    if not total:
        return good

    ex = futures.ThreadPoolExecutor(max_workers=max(1, min(threads, total)))
    futs = {ex.submit(tcp_probe, g[0], **probe_kw): k for k, g in groups.items()}
    end = time.monotonic() + deadline
    try:
        for f in futures.as_completed(futs, timeout=deadline):
            if cancel is not None and cancel.is_set():
                break
            done += 1
            try:
                ms = f.result()
            except Exception:
                ms = -1
            if 0 <= ms <= max_ping:
                for c in groups[futs[f]]:
                    c.ping_ms = ms
                    good.append(c)
                found += 1
            if progress:
                progress(done, total, found)
            if found >= want or time.monotonic() > end:
                break
    except futures.TimeoutError:
        pass
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    good.sort(key=lambda c: (not c.tested_source, c.ping_ms))
    return good[:120]


# ------------------------------------------------------------------ stage 2: real delay

def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def port_open(port, timeout=0.2):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=timeout).close()
        return True
    except OSError:
        return False


def wait_port(port, proc, secs):
    end = time.monotonic() + secs
    while time.monotonic() < end:
        if proc is not None and proc.poll() is not None:
            return False
        if port_open(port):
            return True
        time.sleep(0.05)
    return False


def http_via_proxy(port, url, timeout=10.0):
    """Delay in ms of one request sent through the local HTTP proxy, or -1."""
    proxy = "http://127.0.0.1:%d" % port
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    try:
        t0 = time.perf_counter()
        with opener.open(urllib.request.Request(url, headers={"User-Agent": "ConfigFinder/1.0"}),
                         timeout=timeout) as r:
            r.read(256)
            if r.status not in (200, 204):
                return -1
        return max(1, int((time.perf_counter() - t0) * 1000))
    except Exception:
        return -1


def start_process(xray_cmd, conf_path, log=None):
    return subprocess.Popen(list(xray_cmd) + ["run", "-c", conf_path],
                            stdout=log or subprocess.DEVNULL, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW)


def stop_process(proc):
    if proc is None:
        return
    try:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
    except Exception:
        pass


def real_probe(c, ip, xray_cmd, url=TEST_URL, timeout=10.0):  # timeout: seconds for the request
    """Run one config in its own Xray process and send a request through it. -1 = does not work."""
    port = free_port()
    conf = builder.test_config(c, ip, port)
    if conf is None:
        return -1
    fd, path = tempfile.mkstemp(suffix=".json", prefix="cf_")
    proc = None
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(conf, f)
        proc = start_process(xray_cmd, path)
        if not wait_port(port, proc, 4.0):
            return -1
        return http_via_proxy(port, url, timeout)
    except Exception:
        return -1
    finally:
        stop_process(proc)
        try:
            os.remove(path)
        except OSError:
            pass


def verify_real(configs, xray_cmd, max_real=1500, want=8, max_candidates=60, threads=6,
                deadline=90.0, cancel=None, progress=None, url=TEST_URL, probe_timeout=10.0):
    cand = [c for c in configs if builder.outbound(c, "0.0.0.0") is not None][:max_candidates]
    total = len(cand)
    good, done = [], 0
    if not total:
        return good

    def work(c):
        if cancel is not None and cancel.is_set():
            return -1
        try:
            ip = resolve(c.host)
        except Exception:
            return -1
        return real_probe(c, ip, xray_cmd, url=url, timeout=probe_timeout)

    ex = futures.ThreadPoolExecutor(max_workers=max(1, min(threads, total)))
    futs = {ex.submit(work, c): c for c in cand}
    try:
        for f in futures.as_completed(futs, timeout=deadline):
            if cancel is not None and cancel.is_set():
                break
            done += 1
            try:
                ms = f.result()
            except Exception:
                ms = -1
            if 0 < ms <= max_real:
                futs[f].real_ms = ms
                good.append(futs[f])
            if progress:
                progress(done, total, len(good))
            if len(good) >= want:
                break
    except futures.TimeoutError:
        pass
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    good.sort(key=lambda c: c.real_ms)
    return good[:20]
