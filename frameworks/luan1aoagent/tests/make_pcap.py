#!/usr/bin/env python3
"""Write tests/luan1aoagent-sample.pcap: synthetic LuaN1aoAgent traffic and near misses for the Zeek test.

    pip install scapy && python3 tests/make_pcap.py
"""
from pathlib import Path
from scapy.all import IP, TCP, Ether, Raw, wrpcap

pkts = []
t = [1795400000.0]
E = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
ER = Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")


def stamp(p):
    t[0] += 0.01
    p.time = t[0]
    return p


def http(cli, srv, sport, dport, request, response):
    c, s = 1000, 5000
    pkts.append(stamp(E / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="S", seq=c)))
    pkts.append(stamp(ER / IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="SA", seq=s, ack=c + 1)))
    c += 1; s += 1
    pkts.append(stamp(E / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="A", seq=c, ack=s)))
    pkts.append(stamp(E / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="PA", seq=c, ack=s) / Raw(request)))
    c += len(request)
    pkts.append(stamp(ER / IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="PA", seq=s, ack=c) / Raw(response)))
    s += len(response)
    pkts.append(stamp(E / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="FA", seq=c, ack=s)))
    pkts.append(stamp(ER / IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="FA", seq=s, ack=c + 1)))
    pkts.append(stamp(E / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="A", seq=c + 1, ack=s + 1)))


def req(method, path, ua, body=""):
    b = body.encode()
    extra = f"Content-Type: application/json\r\nContent-Length: {len(b)}\r\n" if body else ""
    return f"{method} {path} HTTP/1.1\r\nHost: target.example.test\r\nUser-Agent: {ua}\r\n{extra}Accept: */*\r\n\r\n".encode() + b


def resp(body, status="200 OK", ctype="application/json", extra=""):
    b = body.encode()
    return f"HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {len(b)}\r\n{extra}\r\n".encode() + b


WEB, WB = "10.0.0.5", "10.0.0.8"
BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"
IMITATION = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"

# Requests from its research and fetch tools reaching a web server (src/tools/research-tools.ts:10-11)
http("203.0.113.20", WEB, 43001, 80, req("GET", "/", "LuaN1aoAgent/0.1 security-research"), resp("<html></html>", ctype="text/html"))
http("203.0.113.21", WEB, 43002, 80, req("GET", "/docs", IMITATION), resp("<html></html>", ctype="text/html"))

# The workbench on 8787: the page (web/index.html:7) and the CSRF cookie it sets (src/web-security.ts:92)
http("10.0.0.30", WB, 43010, 8787, req("GET", "/", BROWSER),
     resp('<!doctype html><html lang="zh-CN"><head><title>\u9e3e\u9e1f\u6e17\u900f\u667a\u80fd\u4f53 \u00b7 Agent Workbench</title></head></html>', ctype="text/html"))
http("10.0.0.31", WB, 43011, 8787, req("GET", "/api/session", BROWSER),
     resp('{"user":null}', extra="Set-Cookie: luanniao_csrf=AbC123; Path=/; SameSite=Lax; Max-Age=604800\r\n"))

# Near misses: a real Chrome 124 on macOS, a user agent that names the tool later, another CSRF cookie
http("198.51.100.50", WEB, 43020, 80,
     req("GET", "/", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
     resp("<html></html>", ctype="text/html"))
http("198.51.100.51", WEB, 43021, 80, req("GET", "/", "Mozilla/5.0 (compatible; LuaN1aoAgent-checker)"), resp("<html></html>", ctype="text/html"))
http("198.51.100.52", WB, 43022, 8787, req("GET", "/api/session", BROWSER), resp("{}", extra="Set-Cookie: csrftoken=AbC123; Path=/\r\n"))

out = Path(__file__).with_name("luan1aoagent-sample.pcap")
wrpcap(str(out), pkts)
print(f"wrote {out} ({len(pkts)} packets)")
