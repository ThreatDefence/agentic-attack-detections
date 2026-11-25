#!/usr/bin/env python3
"""Write behaviors-sample.pcap: synthetic traffic for every check in agentic-behaviors, plus near misses and benign
traffic that must stay quiet. 10.0.0.5 is the one address the tests put in server_nets.

    pip install scapy && python3 make_pcap.py
"""
import struct
from pathlib import Path
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether, raw, wrpcap
from scapy.asn1.asn1 import ASN1_BIT_STRING, ASN1_STRING
from scapy.layers.kerberos import (Kerberos, KRB_AS_REQ, KRB_TGS_REQ, KRB_AP_REQ, KRB_Ticket, KRB_KDC_REQ_BODY, KRB_ERROR,
                                   PADATA, EncryptedData, PrincipalName, ASN1_GENERAL_STRING, ASN1_GENERALIZED_TIME,
                                   ASN1_INTEGER)
from scapy.layers.netbios import NBTSession
from scapy.layers.smb2 import SMB2_Header, SMB2_Negotiate_Protocol_Request, SMB2_Negotiate_Protocol_Response

pkts = []
t = [1795000000.0]
E = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
ER = Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")


def stamp(p):
    t[0] += 0.01
    p.time = t[0]
    return p


def pause(seconds):
    t[0] += seconds


def session(cli, srv, sport, dport, request=b"", response=b"", more=()):
    """One TCP connection. `more` adds (request, response) pairs on the same connection."""
    c, s = 1000, 5000
    pkts.append(stamp(E / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="S", seq=c)))
    pkts.append(stamp(ER / IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="SA", seq=s, ack=c + 1)))
    pkts.append(stamp(E / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="A", seq=c + 1, ack=s + 1)))
    c2, s2 = c + 1, s + 1
    for rq, rs in ((request, response),) + tuple(more):
        if rq:
            pkts.append(stamp(E / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="PA", seq=c2, ack=s2) / rq))
            c2 += len(rq)
        if rs:
            pkts.append(stamp(ER / IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="PA", seq=s2, ack=c2) / rs))
            s2 += len(rs)
    pkts.append(stamp(E / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="FA", seq=c2, ack=s2)))
    pkts.append(stamp(ER / IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="FA", seq=s2, ack=c2 + 1)))
    pkts.append(stamp(E / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="A", seq=c2 + 1, ack=s2 + 1)))


def syn_scan(cli, srv, sport, dport):
    """Half-open scan of an open port: SYN, SYN-ACK, RST."""
    pkts.append(stamp(E / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="S", seq=1000)))
    pkts.append(stamp(ER / IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="SA", seq=5000, ack=1001)))
    pkts.append(stamp(E / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="R", seq=1001)))


def req(path, ua, host="app.example.test", extra=""):
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n{extra}Accept: */*\r\n\r\n".encode()


def resp(body="x", status="404 Not Found", ctype="text/html"):
    return f"HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n\r\n{body}".encode()


def client_hello(sni):
    name = sni.encode()
    sni_ext = struct.pack(">HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    body = b"\x03\x03" + bytes(range(32)) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + struct.pack(">H", len(sni_ext)) + sni_ext
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def dns(src, name, qid):
    pkts.append(stamp(E / IP(src=src, dst="10.0.0.53") / UDP(sport=nxt(), dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=name))))


GS, INT, GT = ASN1_GENERAL_STRING, ASN1_INTEGER, ASN1_GENERALIZED_TIME
REALM, KDC = "CORP.TEST", "10.0.0.2"
KRBTGT = PrincipalName(nameString=[GS("krbtgt"), GS(REALM)], nameType=INT(2))


def kdc_body(nonce, cname=None, sname=KRBTGT):
    # kdc-options must be the full 32 bits, or Zeek's Kerberos analyzer rejects the request.
    return KRB_KDC_REQ_BODY(kdcOptions=ASN1_BIT_STRING("01000000100000010000000000010000"), realm=GS(REALM), cname=cname,
                            sname=sname, till=GT("20370913024805Z"), rtime=GT("20370913024805Z"), nonce=INT(nonce),
                            etype=[INT(18)])


def as_exchange(cli, user, nonce, error):
    """A bare AS-REQ as kerbrute sends it, and the KDC's error: 6 unknown name, 25 the name exists."""
    sp = nxt()
    name = PrincipalName(nameString=[GS(user)], nameType=INT(1))
    asreq = Kerberos(root=KRB_AS_REQ(reqBody=kdc_body(nonce, name)))
    err = Kerberos(root=KRB_ERROR(errorCode=INT(error), stime=GT("20261121000000Z"), susec=INT(0), realm=GS(REALM),
                                  cname=name, crealm=GS(REALM), sname=KRBTGT))
    pkts.append(stamp(E / IP(src=cli, dst=KDC) / UDP(sport=sp, dport=88) / asreq))
    pkts.append(stamp(ER / IP(src=KDC, dst=cli) / UDP(sport=88, dport=sp) / err))


def tgs_request(cli, service, nonce):
    """A TGS-REQ for a service ticket, carrying a ticket-granting ticket in PA-TGS-REQ."""
    tgt = KRB_Ticket(realm=GS(REALM), sname=KRBTGT, encPart=EncryptedData(etype=INT(18), kvno=INT(2), cipher=ASN1_STRING(b"\x11" * 64)))
    ap = KRB_AP_REQ(apOptions=ASN1_BIT_STRING("0" * 32), ticket=tgt, authenticator=EncryptedData(etype=INT(18), cipher=ASN1_STRING(b"\x22" * 48)))
    sname = PrincipalName(nameString=[GS(x) for x in service.split("/")], nameType=INT(2))
    tgs = Kerberos(root=KRB_TGS_REQ(padata=[PADATA(padataType=INT(1), padataValue=ap)], reqBody=kdc_body(nonce, sname=sname)))
    pkts.append(stamp(E / IP(src=cli, dst=KDC) / UDP(sport=nxt(), dport=88) / tgs))


SMB_NEG = raw(NBTSession() / SMB2_Header(Command=0, MID=0, CreditRequest=1) / SMB2_Negotiate_Protocol_Request(Dialects=[0x0202, 0x0210, 0x0300]))
SMB_NEG_RESP = raw(NBTSession() / SMB2_Header(Command=0, MID=0, Flags=1, CreditRequest=1) / SMB2_Negotiate_Protocol_Response(DialectRevision=0x0300))

WEB, SRV, LAPTOP = "10.0.0.5", "10.0.0.5", "10.0.0.77"
BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"
PAGE = '<!DOCTYPE html><html><head><title>Shop</title></head><body><div id="app"></div></body></html>'
port = [40000]


def nxt():
    port[0] += 1
    return port[0]


# 1. Model APIs from a server (Model_API_From_Server): DeepSeek, and Qwen on a DashScope subdomain
session(SRV, "198.51.100.80", nxt(), 443, client_hello("api.deepseek.com"))
session(SRV, "198.51.100.81", nxt(), 443, client_hello("coding.dashscope.aliyuncs.com"))
# Near miss: a laptop outside server_nets calls the same model API (nothing expected)
session(LAPTOP, "198.51.100.80", nxt(), 443, client_hello("api.deepseek.com"))

# 2. Qwen Code page reader, then attack traffic from the same address a second later (AI_Agent_Attacking_Site)
session("203.0.113.20", WEB, nxt(), 80, req("/products", "QwenCode/0.6.1 (linux; x64)"), resp("ok", "200 OK"))
pause(1)
session("203.0.113.20", WEB, nxt(), 80, req("/download?f=../../etc/passwd", "curl/8.5.0"), resp())
# A Claude Code reader alone, with no attack traffic (nothing expected)
session("203.0.113.21", WEB, nxt(), 80, req("/docs", "Claude-User (claude-code/2.1.98; +https://support.anthropic.com/)"), resp("ok", "200 OK"))

# 3. Rotating proxies: 60 addresses, two refused login requests each (Rotating_Proxy_Probing)
for i in range(60):
    for _ in range(2):
        session(f"198.18.0.{i + 1}", WEB, nxt(), 80, req("/wp-login.php", "Mozilla/5.0", "shop.example.test"), resp())
# The ratio is met late: one address sends 520 refused requests, then 60 addresses send one each. At 50 addresses
# the average is over 11 per address; it falls to 10 at the 58th, and the notice has to fire then.
ten = (req("/admin", "Mozilla/5.0", "late.example.test") * 10, resp() * 10)
session("198.19.0.1", WEB, nxt(), 80, more=[ten] * 52)
for i in range(60):
    session(f"198.19.1.{i + 1}", WEB, nxt(), 80, req("/admin", "Mozilla/5.0", "late.example.test"), resp())
# Near miss: a login page in normal use. 60 addresses sign in and get 200; 6 of them mistype once (nothing expected)
for i in range(60):
    session(f"198.18.2.{i + 1}", WEB, nxt(), 80, req("/login", BROWSER, "portal.example.test"), resp(PAGE, "200 OK"))
    if i < 6:
        session(f"198.18.2.{i + 1}", WEB, nxt(), 80, req("/login", BROWSER, "portal.example.test"), resp("denied", "401 Unauthorized"))

# 4. Backup sweep with one file served, WSUS admin API and WSUS port (Backup_File_Served, Backup_Path_Sweep, WSUS_*)
for p in ["/.git/HEAD", "/.env.bak", "/backup.zip", "/db_backup.sql", "/dump.sql"]:
    session("203.0.113.30", WEB, nxt(), 80, req(p, "python-requests/2.31.0"), resp())
session("203.0.113.30", WEB, nxt(), 80, req("/.env", "python-requests/2.31.0"),
        resp("APP_ENV=production\nDB_PASSWORD=x\n", "200 OK", "application/octet-stream"))
session("203.0.113.31", "10.0.0.6", nxt(), 8530, req("/ApiRemoting30/WebService.asmx", "Mozilla/5.0", "wsus.example.test"), resp())
# Near miss: a site that answers 200 with its home page to any path (nothing expected)
for p in ["/.env", "/backup.zip"]:
    session("203.0.113.32", WEB, nxt(), 80, req(p, "python-requests/2.31.0", "spa.example.test"), resp(PAGE, "200 OK"))

# 5. Kerberos enumeration as kerbrute does it (Kerberos_Enumeration): 30 AS-REQs, 12 for unknown names (error 6) and
# 18 for names that exist (error 25, preauthentication required). Only the AS-REQs name all 30 accounts, so the
# notice needs Zeek to parse them.
for i in range(30):
    as_exchange("10.0.0.66", f"user{i:02d}", i + 1, 6 if i < 12 else 25)
# Benign: a workstation signs in and asks for a file server ticket (nothing expected)
as_exchange("10.0.0.70", "alice", 101, 25)
tgs_request("10.0.0.70", "cifs/fs01.corp.test", 102)

# 6. SMB fan-out to 12 hosts, each with an SMB2 negotiate exchange (SMB_WinRM_Fan_Out)
for i in range(12):
    session("10.0.0.66", f"10.0.1.{i + 10}", nxt(), 445, SMB_NEG, SMB_NEG_RESP)
# Near misses: a SYN scan and a connect scan of port 445 on 12 hosts each (nothing expected)
for i in range(12):
    syn_scan("10.0.0.67", f"10.0.1.{i + 10}", nxt(), 445)
    session("10.0.0.68", f"10.0.1.{i + 10}", nxt(), 445)

# 7. Callback to the prober on a PentAGI worker port (Callback_To_Prober): three payload requests, then the server
# connects back two seconds later
for p in ["/item?id=1+union+select+1,2,3", "/search?q=<script>alert(1)</script>", "/view?page=../../../etc/passwd"]:
    session("203.0.113.40", WEB, nxt(), 80, req(p, "Mozilla/5.0"), resp())
pause(2)
session(WEB, "203.0.113.40", nxt(), 28001, b"id\n")
# Near miss: an ordinary visitor, then the server connects to it (nothing expected)
for _ in range(3):
    session("203.0.113.41", WEB, nxt(), 80, req("/", "Mozilla/5.0"), resp("ok", "200 OK"))
pause(2)
session(WEB, "203.0.113.41", nxt(), 4444, b"id\n")
# Near miss: a CDN edge relays someone's payload requests, and the server fetches from the same edge (nothing expected)
for p in ["/item?id=1+union+select+1,2,3", "/search?q=<script>alert(1)</script>", "/view?page=../../../etc/passwd", "/?x={{7*7}}"]:
    session("198.51.100.50", WEB, nxt(), 80, req(p, "Mozilla/5.0", extra="X-Forwarded-For: 192.0.2.44\r\nVia: 1.1 edge-syd\r\n"), resp())
pause(2)
session(WEB, "198.51.100.50", nxt(), 443, client_hello("assets.cdn.example.net"))

# 8. Out-of-band lookups (Out_Of_Band_Lookup). Burp's own polling name comes first and must stay quiet. The server
# then looks up a payload name with a polling. label in front, which must not be skipped, and two more interactsh
# names: one notice, not three. A laptop outside server_nets raises nothing.
dns(WEB, "polling.oastify.com", 1)
dns(WEB, "polling.b8j1wp6z0a2c.oast.fun", 6)
dns(WEB, "c9k2xq7a1b3d.oast.fun", 2)
dns(WEB, "d0m3zr8b2c4e.oast.fun", 3)
dns(LAPTOP, "e1n4as9c3d5f.oast.fun", 4)
dns(WEB, "www.example.org", 5)

# A console behind Basic auth with a realm named after the framework, and a near miss with another realm
session("203.0.113.60", WEB, nxt(), 8001, req("/", BROWSER),
        b'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="Cairn Console"\r\nContent-Length: 0\r\n\r\n')
session("203.0.113.61", WEB, nxt(), 443, req("/", BROWSER),
        b'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="Cairns Holiday Rentals"\r\nContent-Length: 0\r\n\r\n')

# Benign: an ordinary visitor and an ordinary outbound call (nothing expected)
session("198.51.100.99", WEB, nxt(), 80, req("/", BROWSER), resp("ok", "200 OK"))
session(WEB, "198.51.100.100", nxt(), 443, client_hello("www.example.com"))

out = Path(__file__).with_name("behaviors-sample.pcap")
wrpcap(str(out), pkts)
print(f"wrote {out} ({len(pkts)} packets)")
