#!/usr/bin/env python3
"""Write tests/autocve-sample.pcap: synthetic AutoCVE console and API answers and near misses for the Zeek test.

    pip install scapy && python3 tests/make_pcap.py
"""
from pathlib import Path
from scapy.all import IP, TCP, Ether, Raw, wrpcap

pkts = []
t = [1795300000.0]
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


SRV = "10.0.0.8"
BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"

# The API on 8000 answering GET / (backend/app/main.py:122-130) and the console on 3000 (frontend/index.html:8)
http("10.0.0.30", SRV, 42001, 8000, req("GET", "/", "python-requests/2.32.3"),
     resp('{"message":"Welcome to AutoCVE API","docs":"/docs","demo_account":{"email":"demo@example.com","password":"demo123"}}'))
http("10.0.0.31", SRV, 42002, 3000, req("GET", "/", BROWSER),
     resp('<!doctype html><html><head><title>AutoCVE</title><script type="module" src="/assets/index.js"></script></head></html>', ctype="text/html"))

# Near misses: a page that quotes the welcome, a page titled with more than AutoCVE
http("198.51.100.50", "10.0.0.5", 42010, 80, req("GET", "/blog/autocve", BROWSER),
     resp("<p>The API answers Welcome to AutoCVE API on port 8000.</p>", ctype="text/html"))
http("198.51.100.51", "10.0.0.5", 42011, 80, req("GET", "/", BROWSER),
     resp("<html><head><title>AutoCVE alternatives compared</title></head></html>", ctype="text/html"))

out = Path(__file__).with_name("autocve-sample.pcap")
wrpcap(str(out), pkts)
print(f"wrote {out} ({len(pkts)} packets)")
