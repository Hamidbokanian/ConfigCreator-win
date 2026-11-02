import base64
import json
import os
import unittest

from cf import builder
from cf.parser import parse_blob, parse_line


def b64(s):
    return base64.b64encode(s.encode()).decode()


GOOD = {
    "vless tcp tls": "vless://11111111-2222-3333-4444-555555555555@example.com:443?encryption=none&security=tls&sni=sni.example.com&type=tcp&fp=chrome&alpn=h2,http/1.1#a",
    "vless reality vision": "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?encryption=none&security=reality&sni=www.microsoft.com&fp=firefox&pbk=PUBKEY123&sid=ab12&flow=xtls-rprx-vision&type=tcp#r",
    "vless ws tls": "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=tls&sni=cdn.example.com&type=ws&host=cdn.example.com&path=%2Fmy%20path%3Fed%3D2048#w",
    "vless grpc tls": "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=tls&sni=g.example.com&type=grpc&serviceName=svc&mode=multi#g",
    "vless httpupgrade": "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:80?security=none&type=httpupgrade&host=h.example.com&path=%2Fu#h",
    "trojan ws tls": "trojan://pa%24%24word@104.18.12.149:443?security=tls&sni=www.calmlunch.com&type=ws&host=www.calmlunch.com&path=%2Fassignment#t",
    "trojan default tls": "trojan://pw@example.com:443#t2",
    "vmess ws tls": "vmess://" + b64('{"v":"2","ps":"x","add":"example.org","port":"443","id":"11111111-2222-3333-4444-555555555555","aid":"0","net":"ws","type":"none","host":"ws.example.org","path":"/ray","tls":"tls","sni":"ws.example.org"}'),
    "vmess grpc": "vmess://" + b64('{"add":"1.1.1.1","port":443,"id":"11111111-2222-3333-4444-555555555555","net":"grpc","path":"svcname","type":"multi","tls":"tls"}'),
    "ss aead": "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpleGFtcGxl@outline-server.example.com:8388/?outline=1",
    "ss legacy": "ss://" + b64('aes-256-gcm:p"ass@9.9.9.9:443') + "#legacy",
}


class ParserTests(unittest.TestCase):
    def test_vless_from_public_list(self):
        v = parse_line("vless://394f6981-a782-4779-9a85-e6cf22935d93@95.173.199.113:8443?encryption=none&security=tls&sni=ams1.fromblancwithlove.com&type=tcp&headerType=none#Czech-Republic")
        self.assertEqual((v.protocol, v.host, v.port, v.security, v.sni, v.name),
                         ("vless", "95.173.199.113", 8443, "tls", "ams1.fromblancwithlove.com", "Czech-Republic"))

    def test_trojan_defaults(self):
        t = parse_line("trojan://pw@example.com:443#x")
        self.assertEqual((t.security, t.sni), ("tls", "example.com"))

    def test_reality_and_ipv6(self):
        r = parse_line("vless://uuid@1.2.3.4:443?security=reality&sni=www.microsoft.com&pbk=abc#R")
        self.assertEqual(r.security, "reality")
        v6 = parse_line("vless://uuid@[2001:db8::1]:8443?security=none#v6")
        self.assertEqual((v6.host, v6.port), ("2001:db8::1", 8443))

    def test_vmess(self):
        vm = parse_line(GOOD["vmess ws tls"])
        self.assertEqual((vm.host, vm.port, vm.security, vm.sni, vm.name), ("example.org", 443, "tls", "ws.example.org", "x"))
        vm2 = parse_line("vmess://" + b64('{"add":"1.1.1.1","port":443,"tls":""}'))
        self.assertEqual((vm2.port, vm2.security), (443, "none"))

    def test_shadowsocks(self):
        s1 = parse_line(GOOD["ss aead"])
        self.assertEqual((s1.host, s1.port, s1.ss_method), ("outline-server.example.com", 8388, "chacha20-ietf-poly1305"))
        s2 = parse_line(GOOD["ss legacy"])
        self.assertEqual((s2.host, s2.port, s2.ss_method, s2.name), ("9.9.9.9", 443, "aes-256-gcm", "legacy"))
        s3 = parse_line("ss://" + b64("aes-256-gcm:pw") + "@8.8.8.8:443/?plugin=v2ray-plugin%3Btls#p")
        self.assertTrue(s3.ss_plugin)

    def test_garbage(self):
        for bad in ("hello", "vless://nohost", "vless://u@host:99999?security=tls",
                    "vmess://!!!notbase64!!!", "hysteria2://x@1.1.1.1:443", "", None):
            self.assertIsNone(parse_line(bad), bad)

    def test_blobs(self):
        plain = GOOD["vless tcp tls"] + "\r\n" + GOOD["trojan default tls"] + "\n\njunk\n" + GOOD["ss aead"]
        self.assertEqual(len(parse_blob(plain)), 3)
        self.assertEqual(len(parse_blob(b64(plain))), 3)
        self.assertEqual(parse_blob(""), [])
        self.assertEqual(parse_blob(None), [])


class BuilderTests(unittest.TestCase):
    def test_all_good_links_build(self):
        for name, link in GOOD.items():
            self.assertIsNotNone(builder.outbound(parse_line(link), "203.0.113.7"), name)

    def test_unsupported_are_rejected(self):
        bad = {
            "allowInsecure": "vless://u@1.2.3.4:443?security=tls&allowInsecure=1&type=tcp#x",
            "kcp": "vless://u@1.2.3.4:443?security=none&type=kcp#x",
            "reality without key": "vless://u@1.2.3.4:443?security=reality&sni=a.com&type=tcp#x",
            "ss plugin": "ss://" + b64("aes-256-gcm:pw") + "@8.8.8.8:443/?plugin=v2ray-plugin%3Btls#p",
            "vmess without id": "vmess://" + b64('{"add":"1.1.1.1","port":443}'),
        }
        for name, link in bad.items():
            self.assertIsNone(builder.outbound(parse_line(link), "1.2.3.4"), name)
        self.assertIsNone(builder.outbound(None, "1.1.1.1"))
        self.assertIsNone(builder.outbound(parse_line(GOOD["trojan default tls"]), ""))

    @unittest.skipUnless(os.path.exists("/tmp/xray_cfgs.tsv"), "Java reference output not available")
    def test_matches_the_android_builder(self):
        """The Android (Java) builder was validated separately; both must produce the same outbound."""
        ref = {}
        for line in open("/tmp/xray_cfgs.tsv", encoding="utf-8"):
            name, js = line.rstrip("\n").split("\t", 1)
            ref[name] = json.loads(js)["outbounds"][0]
        self.assertEqual(set(ref), set(GOOD))
        for name, link in GOOD.items():
            self.assertEqual(builder.outbound(parse_line(link), "203.0.113.7"), ref[name], name)

    def test_full_configs(self):
        c = parse_line(GOOD["vless reality vision"])
        t = builder.test_config(c, "1.2.3.4", 5555)
        self.assertEqual(t["inbounds"][0]["port"], 5555)
        p = builder.proxy_mode_config(c, "1.2.3.4", 10808, 10809)
        self.assertEqual([i["protocol"] for i in p["inbounds"]], ["socks", "http"])
        self.assertEqual(p["routing"]["rules"][0]["domain"], ["regexp:\\.ir$"])
        self.assertEqual(builder.proxy_mode_config(c, "1.2.3.4", 1, 2, bypass_ir=False)["routing"]["rules"], [])
        v = builder.tun_config(c, "1.2.3.4", 5556)
        tun = v["inbounds"][0]
        self.assertEqual(tun["protocol"], "tun")
        self.assertEqual(tun["settings"]["autoSystemRoutingTable"], ["0.0.0.0/0"])
        self.assertEqual(v["outbounds"][0]["tag"], "proxy")
        json.dumps(v)  # serialisable
        self.assertIsNone(builder.tun_config(parse_line("vless://u@1.2.3.4:443?type=kcp"), "1.2.3.4", 1))


if __name__ == "__main__":
    unittest.main()
