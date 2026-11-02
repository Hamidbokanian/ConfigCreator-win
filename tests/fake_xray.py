"""Stands in for xray.exe in tests: `fake_xray.py run -c config.json`.
Opens the config's HTTP inbound and answers like a proxy that works, unless told otherwise:
  FAKE_BAD=<ports>   -> answers 502 for configs whose outbound port is listed
  FAKE_HANG=<ports>  -> never answers
"""
import http.server
import json
import os
import sys
import time

assert sys.argv[1:3] == ["run", "-c"], sys.argv
cfg = json.load(open(sys.argv[3], encoding="utf-8"))
http_in = [i for i in cfg["inbounds"] if i["protocol"] == "http"][0]
st = cfg["outbounds"][0]["settings"]
out_port = (st.get("vnext") or st.get("servers"))[0]["port"]
bad = set(filter(None, os.environ.get("FAKE_BAD", "").split(",")))
hang = set(filter(None, os.environ.get("FAKE_HANG", "").split(",")))


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if str(out_port) in hang:
            time.sleep(60)
        time.sleep(0.02 + (out_port % 10) * 0.02)
        self.send_response(502 if str(out_port) in bad else 204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


http.server.ThreadingHTTPServer(("127.0.0.1", http_in["port"]), H).serve_forever()
