"""Config Finder for Windows: finds proxy configs that REALLY work and connects with them.

Run:  python main.py        (or the packaged ConfigFinder.exe)
"""
import argparse
import atexit
import os
import signal
import sys
import threading
import webbrowser
from pathlib import Path

from cf import server, sysproxy


def ui_dir():
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base / "cf" / "ui"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    app = server.App()
    srv = server.make_server(app, ui_dir(), args.port)
    port = srv.server_address[1]
    url = "http://127.0.0.1:%d/?t=%s" % (port, app.token)

    def cleanup(*_):
        try:
            app.shutdown()
        except Exception:
            pass

    atexit.register(cleanup)
    for sig in ("SIGINT", "SIGTERM", "SIGBREAK"):
        if hasattr(signal, sig):
            signal.signal(getattr(signal, sig), lambda *a: (cleanup(), os._exit(0)))
    if sysproxy.IS_WINDOWS:
        # closing the console window must also undo the system proxy
        import ctypes
        handler_t = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_uint)

        def on_ctrl(evt):
            cleanup()
            return 0
        main._keep = handler_t(on_ctrl)
        ctypes.windll.kernel32.SetConsoleCtrlHandler(main._keep, True)

    print("Config Finder  |  ساخته‌شده توسط حمید بوکانیان")
    print("برنامه در مرورگر باز میشه. اگه باز نشد این آدرس رو توی مرورگر بزن:")
    print(url)
    print("برای خروج این پنجره رو ببند یا Ctrl+C بزن (پروکسی سیستم خودکار برمی‌گرده).")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        cleanup()


if __name__ == "__main__":
    main()
