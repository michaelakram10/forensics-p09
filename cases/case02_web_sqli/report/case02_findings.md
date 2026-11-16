# Case 02 — Web SQL Injection (DVWA) — Findings

## Summary
A manual SQL injection attack was conducted against DVWA's SQL Injection
module (`/vulnerabilities/sqli/`) running at Security Level: Low, over a
~92-second window. The attacker progressed through a standard
reconnaissance-to-exfiltration sequence, extracting the full `users`
table including password hashes.

## Attack sequence
1. **17:18:35 — Baseline**: `id=1` — legitimate single-user lookup, used
   as a reference for normal application behavior.
2. **17:19:08 — Injectability probe**: `id=1' OR '1'='1` — returned all
   5 users instead of 1, confirming the input is not sanitized.
3. **17:19:27 / 17:19:38 — Column enumeration**: `ORDER BY 2` succeeded;
   `ORDER BY 3` returned a MySQL error (`Unknown column '3' in 'order
   clause'`), confirming the underlying query selects exactly 2 columns.
4. **17:20:07 — UNION-based extraction**: `UNION SELECT user, password
   FROM users` dumped all 6 user records, including MD5 password
   hashes.

## Key observation: status-code blindness
Every request in this sequence — including the one that triggered a
visible SQL error — returned HTTP 200. A monitoring approach that
inspects only response status codes would miss this entire attack;
detection requires inspecting request content (query strings), which
Zeek's `http.log` captured in full.

## Secondary finding: password reuse
Extracted hashes showed `admin` and `smithy` share the identical MD5
hash `5f4dcc3b5aa765d61d8327deb882cf99` (a widely known hash of the
string "password"), indicating weak/reused credentials across accounts.

## Evidence
- Raw capture: `raw/case02_web_sqli.pcap` (SHA256 in `custody/case02.sha256`)
- Zeek logs: `zeek/tsv/{conn,http,files}.log`
- Timeline: `timeline/case02_timeline.csv`
- Visualization: `viz/case02_timeline.png`
