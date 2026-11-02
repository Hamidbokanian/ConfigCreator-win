"""Builds Xray-core JSON configs from share links.

Every function returns None when the link uses something we cannot express (unsupported
transport, Reality without key, allowInsecure, plugins ...). The server address is passed in
already resolved so the core never needs DNS for it; SNI / Host headers keep the original names.
"""
from .parser import ss_credentials, uri_parts, parse_query, vmess_fields

FINGERPRINTS = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
                "random", "randomized", "randomizednoalpn", "unsafe"}
DOH = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]


def _ne(v, default):
    return v if v else default


def _is_true(v):
    return v is not None and v.lower() in ("1", "true")


def _norm_net(n):
    n = (n or "tcp").lower()
    return {"raw": "tcp", "splithttp": "xhttp"}.get(n, n)


def _security(s, default):
    s = (s or default).lower()
    return s if s in ("tls", "reality") else "none"


def _fingerprint(fp):
    f = (fp or "chrome").lower()
    return f if f in FINGERPRINTS else "chrome"


def _stream(net, sec, p, c):
    host_header = _ne(p.get("host"), c.host)
    path = _ne(p.get("path"), "/")
    st = {"network": net}
    if net == "tcp":
        if (p.get("headertype") or "").lower() == "http":
            st["tcpSettings"] = {"header": {"type": "http", "request": {
                "path": [path], "headers": {"Host": [host_header]}}}}
    elif net == "ws":
        st["wsSettings"] = {"path": path, "headers": {"Host": host_header}}
    elif net == "grpc":
        st["grpcSettings"] = {"serviceName": _ne(p.get("servicename"), ""),
                              "multiMode": (p.get("mode") or "").lower() == "multi"}
    elif net == "httpupgrade":
        st["httpupgradeSettings"] = {"path": path, "host": host_header}
    elif net == "xhttp":
        st["xhttpSettings"] = {"path": path, "host": host_header, "mode": _ne(p.get("mode"), "auto")}
    else:
        return None  # kcp, quic, h2 ... not supported by this tester

    server_name = _ne(p.get("sni"), _ne(p.get("peer"), _ne(p.get("host"), c.host)))
    fp = _fingerprint(p.get("fp"))
    if sec == "tls":
        if _is_true(p.get("allowinsecure")) or _is_true(p.get("insecure")):
            return None  # removed in recent cores
        tls = {"serverName": server_name, "fingerprint": fp}
        alpn = p.get("alpn")
        if alpn:
            tls["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
        st["security"] = "tls"
        st["tlsSettings"] = tls
    elif sec == "reality":
        pbk = p.get("pbk")
        if not pbk:
            return None
        rs = {"serverName": server_name, "fingerprint": fp, "publicKey": pbk,
              "shortId": _ne(p.get("sid"), "")}
        if p.get("spx"):
            rs["spiderX"] = p["spx"]
        st["security"] = "reality"
        st["realitySettings"] = rs
    else:
        st["security"] = "none"
    return st


def outbound(c, address):
    """The proxy outbound (tag 'proxy') for one config, or None."""
    if c is None or not address:
        return None
    try:
        if c.protocol == "vless":
            ui = uri_parts(c.raw, "vless")
            if not ui or not ui[0]:
                return None
            p = parse_query(ui[1])
            net, sec = _norm_net(p.get("type")), _security(p.get("security"), "none")
            st = _stream(net, sec, p, c)
            if st is None:
                return None
            user = {"id": ui[0], "encryption": _ne(p.get("encryption"), "none")}
            if p.get("flow") and net == "tcp" and sec != "none":
                user["flow"] = p["flow"]
            return {"tag": "proxy", "protocol": "vless", "settings": {"vnext": [
                {"address": address, "port": c.port, "users": [user]}]}, "streamSettings": st}

        if c.protocol == "trojan":
            ui = uri_parts(c.raw, "trojan")
            if not ui or not ui[0]:
                return None
            p = parse_query(ui[1])
            st = _stream(_norm_net(p.get("type")), _security(p.get("security"), "tls"), p, c)
            if st is None:
                return None
            return {"tag": "proxy", "protocol": "trojan", "settings": {"servers": [
                {"address": address, "port": c.port, "password": ui[0]}]}, "streamSettings": st}

        if c.protocol == "vmess":
            f = vmess_fields(c.raw)
            if not f or not f.get("id"):
                return None
            try:
                aid = int(f.get("aid") or 0)
            except ValueError:
                aid = 0
            p = {}
            net = _norm_net(f.get("net"))
            for k_src, k_dst in (("host", "host"), ("path", "path"), ("sni", "sni"),
                                 ("alpn", "alpn"), ("fp", "fp")):
                if f.get(k_src):
                    p[k_dst] = f[k_src]
            if net == "grpc":
                if f.get("path"):
                    p["servicename"] = f["path"]
                if f.get("type"):
                    p["mode"] = f["type"]
            elif f.get("type"):
                p["headertype"] = f["type"]
            sec = "tls" if f.get("tls", "").lower() == "tls" else "none"
            st = _stream(net, sec, p, c)
            if st is None:
                return None
            return {"tag": "proxy", "protocol": "vmess", "settings": {"vnext": [
                {"address": address, "port": c.port, "users": [
                    {"id": f["id"], "alterId": aid, "security": _ne(f.get("scy"), "auto")}]}]},
                "streamSettings": st}

        if c.protocol == "ss":
            if c.ss_plugin:
                return None
            cred = ss_credentials(c.raw)
            if not cred or not cred[1]:
                return None
            return {"tag": "proxy", "protocol": "shadowsocks", "settings": {"servers": [
                {"address": address, "port": c.port, "method": cred[0], "password": cred[1]}]},
                "streamSettings": {"network": "tcp"}}
    except Exception:
        return None
    return None


# ------------------------------------------------------------------ full configs

def _http_in(tag, port):
    return {"tag": tag, "listen": "127.0.0.1", "port": port, "protocol": "http", "settings": {}}


def _bypass_rules(bypass_ir):
    # Iranian sites often refuse foreign IPs: send *.ir straight out
    return [{"type": "field", "domain": ["regexp:\\.ir$"], "outboundTag": "direct"}] if bypass_ir else []


def test_config(c, address, http_port):
    """One local HTTP inbound -> the proxy. Used for the real-delay test."""
    ob = outbound(c, address)
    if ob is None:
        return None
    return {"log": {"loglevel": "warning"}, "inbounds": [_http_in("http-in", http_port)],
            "outbounds": [ob]}


def proxy_mode_config(c, address, socks_port, http_port, bypass_ir=True):
    """Local SOCKS + HTTP inbounds, used together with the Windows system proxy."""
    ob = outbound(c, address)
    if ob is None:
        return None
    sniff = {"enabled": True, "destOverride": ["http", "tls"]}
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "socks-in", "listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
             "settings": {"udp": True, "auth": "noauth"}, "sniffing": sniff},
            dict(_http_in("http-in", http_port), sniffing=sniff),
        ],
        "outbounds": [ob, {"tag": "direct", "protocol": "freedom"},
                      {"tag": "block", "protocol": "blackhole"}],
        "routing": {"domainStrategy": "AsIs", "rules": _bypass_rules(bypass_ir)},
    }


def tun_config(c, address, check_port, bypass_ir=True, mtu=1500):
    """Whole-system VPN through a Wintun interface (needs administrator + wintun.dll).

    A private HTTP inbound is added only so the app can verify the tunnel really carries traffic.
    """
    ob = outbound(c, address)
    if ob is None:
        return None
    rules = [{"type": "field", "inboundTag": ["tun-in"], "port": "53", "outboundTag": "dns-out"}]
    rules += _bypass_rules(bypass_ir)
    return {
        "log": {"loglevel": "warning"},
        "dns": {"servers": DOH, "queryStrategy": "UseIPv4"},
        "inbounds": [
            {"tag": "tun-in", "protocol": "tun", "settings": {
                "name": "ConfigFinder", "mtu": mtu, "gateway": ["172.31.255.1/30"],
                "dns": ["1.1.1.1", "8.8.8.8"], "userLevel": 0,
                "autoSystemRoutingTable": ["0.0.0.0/0"], "autoOutboundsInterface": "auto"},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}},
            _http_in("check-in", check_port),
        ],
        "outbounds": [ob, {"tag": "direct", "protocol": "freedom"},
                      {"tag": "dns-out", "protocol": "dns"}],
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }
