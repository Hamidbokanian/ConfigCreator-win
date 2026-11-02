"""Finding, downloading and running xray.exe."""
import io
import json
import os
import shutil
import sys
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path

from . import scanner

APP_DIR = Path(os.environ.get("APPDATA") or (Path.home() / ".config")) / "ConfigFinder"
EXE = "xray.exe" if sys.platform == "win32" else "xray"
API = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
WINTUN_URL = "https://www.wintun.net/builds/wintun-0.14.1.zip"


def _dirs():
    here = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent.parent
    return [here, Path.cwd(), APP_DIR / "xray"]


def find_xray():
    for d in _dirs():
        p = d / EXE
        if p.is_file():
            return str(p)
    return shutil.which("xray")


def has_wintun():
    x = find_xray()
    return bool(x) and (Path(x).parent / "wintun.dll").is_file()


def _download(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": "ConfigFinder/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def download_xray(want_wintun=False):
    """Fallback when xray.exe is not bundled. Returns the path to xray.exe."""
    dest = APP_DIR / "xray"
    dest.mkdir(parents=True, exist_ok=True)
    rel = json.loads(_download(API, 30).decode("utf-8"))
    asset = next(a for a in rel["assets"] if a["name"].lower() == "xray-windows-64.zip")
    with zipfile.ZipFile(io.BytesIO(_download(asset["browser_download_url"], 180))) as z:
        for n in z.namelist():
            if n.lower() in ("xray.exe", "geoip.dat", "geosite.dat"):
                (dest / n).write_bytes(z.read(n))
    if want_wintun:
        with zipfile.ZipFile(io.BytesIO(_download(WINTUN_URL, 60))) as z:
            (dest / "wintun.dll").write_bytes(z.read("wintun/bin/amd64/wintun.dll"))
    return str(dest / EXE)


class Session:
    """A long-running Xray process (the VPN / system-proxy connection)."""

    def __init__(self, xray_cmd):
        self.xray_cmd = list(xray_cmd)
        self.proc = None
        self.log_path = APP_DIR / "xray.log"

    def start(self, conf, wait_port=None, settle=2.5):
        APP_DIR.mkdir(parents=True, exist_ok=True)
        fd, path = tempfile.mkstemp(suffix=".json", prefix="cf_run_")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(conf, f)
        log = open(self.log_path, "wb")
        try:
            self.proc = scanner.start_process(self.xray_cmd, path, log)
            if wait_port:
                ok = scanner.wait_port(wait_port, self.proc, 8.0)
            else:
                time.sleep(settle)
                ok = self.proc.poll() is None
            if not ok:
                self.stop()
                raise RuntimeError(self.log_tail() or "هسته اجرا نشد.")
        finally:
            log.close()
            try:
                os.remove(path)  # it holds the credentials; the core has read it by now
            except OSError:
                pass

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def stop(self):
        scanner.stop_process(self.proc)
        self.proc = None

    def log_tail(self, n=6):
        try:
            lines = self.log_path.read_text(encoding="utf-8", errors="replace").strip().splitlines()
            return " | ".join(lines[-n:])[:400]
        except OSError:
            return ""
