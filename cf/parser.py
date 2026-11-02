"""Share-link parser for vmess / vless / trojan / ss (pure standard library)."""
import base64
import json
import re
from dataclasses import dataclass
from urllib.parse import unquote_plus


@dataclass
class ProxyConfig:
    protocol: str          # vmess, vless, trojan, ss
    host: str
    port: int
    raw: str               # the original link, exactly as found
    name: str = ""
    security: str = "none"  # none, tls, reality
    sni: str = ""
    ss_method: str = ""
    ss_plugin: bool = False
    tested_source: bool = False
    ping_ms: int = -1       # TCP connect time from this PC
    real_ms: int = -1       # real delay through the proxy core

    def __post_init__(self):
        if not self.sni:
            self.sni = self.host
        self.ss_method = (self.ss_method or "").lower()
        self.name = self.name or ""

    def dedupe_key(self):
        return self.raw.split("#", 1)[0]


def decode_base64(s):
    """Standard / URL-safe base64, with or without padding. None if invalid."""
    if s is None:
        return None
    t = re.sub(r"\s+", "", s).replace("-", "+").replace("_", "/")
    pad = len(t) % 4
    if pad == 1:
        return None
    if pad:
        t += "=" * (4 - pad)
    try:
        return base64.b64decode(t, validate=True).decode("utf-8", errors="replace")
    except Exception:
        return None


def parse_blob(text):
    """A plain list of links (one per line) or a base64 encoded list."""
    out = []
    if not text:
        return out
    t = text.strip()
    if not t:
        return out
    if "://" not in t:
        dec = decode_base64(t)
        if dec and "://" in dec:
            t = dec
    for line in re.split(r"[\r\n]+", t):
        c = parse_line(line.strip())
        if c is not None:
            out.append(c)
    return out


def parse_line(line):
    if not line:
        return None
    s = line.strip()
    i = s.find("://")
    if i <= 0:
        return None
    scheme = s[:i].lower()
    try:
        if scheme == "vmess":
            return _parse_vmess(s)
        if scheme in ("vless", "trojan"):
            return _parse_uri_style(scheme, s)
        if scheme == "ss":
            return _parse_ss(s)
    except Exception:
        return None
    return None


# ---------------------------------------------------------------- vmess

def vmess_fields(raw):
    """The decoded vmess JSON as a dict of strings, or None."""
    body = raw[len("vmess://"):].split("#", 1)[0]
    txt = decode_base64(body)
    if txt is None:
        return None
    try:
        d = json.loads(txt)
        if isinstance(d, dict):
            return {str(k): ("" if v is None else str(v)) for k, v in d.items()}
    except Exception:
        pass
    # tolerant fallback for slightly broken JSON
    out = {}
    for m in re.finditer(r'"([^"]+)"\s*:\s*(?:"([^"]*)"|([^,}\s]+))', txt):
        out[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
    return out or None


def _parse_vmess(s):
    name = ""
    body = s[len("vmess://"):]
    if "#" in body:
        name = unquote_plus(body.split("#", 1)[1])
    f = vmess_fields(s)
    if not f:
        return None
    host = f.get("add", "").strip()
    port = parse_port(f.get("port"))
    if not host or port < 0:
        return None
    sec = "tls" if f.get("tls", "").lower() == "tls" else "none"
    sni = f.get("sni") or f.get("host") or ""
    if not name:
        name = f.get("ps", "")
    return ProxyConfig("vmess", host, port, s, name, sec, sni.strip())


# ---------------------------------------------------------------- vless / trojan

def uri_parts(raw, scheme):
    """(userinfo, query) of scheme://userinfo@host:port?query#name, or None."""
    rest = raw[len(scheme) + 3:].split("#", 1)[0]
    query = ""
    if "?" in rest:
        rest, query = rest.split("?", 1)
    at = rest.rfind("@")
    if at < 0:
        return None
    return unquote_plus(rest[:at]), query


def _parse_uri_style(scheme, s):
    rest = s[len(scheme) + 3:]
    name = ""
    if "#" in rest:
        rest, frag = rest.split("#", 1)
        name = unquote_plus(frag)
    query = ""
    if "?" in rest:
        rest, query = rest.split("?", 1)
    at = rest.rfind("@")
    if at < 0:
        return None
    host_port = rest[at + 1:].split("/", 1)[0]
    hp = split_host_port(host_port)
    if hp is None:
        return None
    p = parse_query(query)
    sec = p.get("security") or ("tls" if scheme == "trojan" else "none")
    sec = sec.lower()
    if sec not in ("tls", "reality"):
        sec = "none"
    sni = p.get("sni") or p.get("peer") or ""
    return ProxyConfig(scheme, hp[0], hp[1], s, name, sec, sni)


# ---------------------------------------------------------------- shadowsocks

def ss_credentials(raw):
    """(method, password) or None."""
    rest = raw[len("ss://"):].split("#", 1)[0].split("?", 1)[0]
    at = rest.rfind("@")
    if at >= 0:
        userinfo = unquote_plus(rest[:at])
        cred = userinfo if ":" in userinfo else decode_base64(userinfo)
    else:
        dec = decode_base64(rest)
        if dec is None or "@" not in dec:
            return None
        cred = dec[:dec.rfind("@")]
    if not cred or ":" not in cred or cred.index(":") == 0:
        return None
    i = cred.index(":")
    return cred[:i], cred[i + 1:]


def _parse_ss(s):
    rest = s[len("ss://"):]
    name = ""
    if "#" in rest:
        rest, frag = rest.split("#", 1)
        name = unquote_plus(frag)
    plugin = False
    if "?" in rest:
        rest, q = rest.split("?", 1)
        plugin = "plugin=" in q
    at = rest.rfind("@")
    if at >= 0:
        host_port = rest[at + 1:]
    else:
        dec = decode_base64(rest)
        if dec is None or "@" not in dec:
            return None
        host_port = dec[dec.rfind("@") + 1:]
    cred = ss_credentials(s)
    if cred is None:
        return None
    hp = split_host_port(host_port.split("/", 1)[0])
    if hp is None:
        return None
    return ProxyConfig("ss", hp[0], hp[1], s, name, "none", "", cred[0], plugin)


# ---------------------------------------------------------------- helpers

def split_host_port(hp):
    """(host, port) or None. Handles [ipv6]:port."""
    hp = hp.strip()
    if hp.startswith("["):
        end = hp.find("]")
        if end < 0 or end + 1 >= len(hp) or hp[end + 1] != ":":
            return None
        host, port_s = hp[1:end], hp[end + 2:]
    else:
        c = hp.rfind(":")
        if c <= 0:
            return None
        host, port_s = hp[:c], hp[c + 1:]
    port = parse_port(port_s)
    if not host or port < 0:
        return None
    return host, port


def parse_port(p):
    try:
        v = int(str(p).strip())
    except (TypeError, ValueError):
        return -1
    return v if 1 <= v <= 65535 else -1


def parse_query(q):
    m = {}
    if not q:
        return m
    for part in q.split("&"):
        i = part.find("=")
        if i <= 0:
            continue
        m[part[:i].lower()] = unquote_plus(part[i + 1:])
    return m
