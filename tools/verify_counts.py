#!/usr/bin/env python3
"""Verify Zeek JSONL evidence against the P09 lab ground truth."""

import argparse
import json
import sys
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parent.parent

CASES = {
    "case01": "case01_ssh_bruteforce",
    "case02": "case02_web_sqli",
    "case03": "case03_dns_tunnel",
    "case04": "case04_c2_beacon",
}

EXPECTED_CSV_SHA256 = (
    "9b44747e8edc117647021d0730dbde052"
    "c09374d15c0280308d3cd32763ca4c6"
)

def load_log(case_dir, name):
    path = case_dir / "zeek" / "json" / f"{name}.log"

    if not path.is_file():
        raise FileNotFoundError(path)

    records = []
    with path.open(encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"{path}:{line_no}: invalid JSON: {exc}"
                ) from exc

    return records


def verify_case(case_id, folder):
    case_dir = ROOT / "cases" / folder
    cache = {}
    results = []

    def log(name):
        if name not in cache:
            cache[name] = load_log(case_dir, name)
        return cache[name]

    def check(description, log_name, expected, predicate):
        try:
            records = log(log_name)
            actual = sum(1 for r in records if predicate(r))
            status = "PASS" if actual == expected else "FAIL"
            detail = f"{actual} (expected {expected})"
        except FileNotFoundError as exc:
            status, detail = "INCONCLUSIVE", f"Missing: {exc}"
        except (ValueError, OSError) as exc:
            status, detail = "FAIL", str(exc)

        results.append((status, description, detail))

    def count(description, log_name, expected):
        check(description, log_name, expected, lambda r: True)

    def field_count(description, log_name, field, value, expected):
        check(
            description, log_name, expected,
            lambda r: r.get(field) == value
        )

    def port_count(description, log_name, port, expected):
        check(
            description, log_name, expected,
            lambda r: r.get("id.resp_p") == port
        )

    if case_id == "case01":
        count("Total Zeek connections", "conn", 50)
        port_count("Connections to SSH port 22", "conn", 22, 38)
        count("SSH protocol records", "ssh", 37)

        field_count(
            "SSH connections using libssh banner",
            "ssh", "client", "SSH-2.0-libssh_0.10.6", 36
        )
        field_count(
            "SSH connections using OpenSSH banner",
            "ssh", "client",
            "SSH-2.0-OpenSSH_9.9p1 Debian-3", 1
        )

    elif case_id == "case02":
        count("Total TCP connections", "conn", 3)
        count("Total HTTP requests", "http", 17)
        count("File-analysis records", "files", 17)

        check(
            "SQL injection endpoint requests",
            "http", 11,
            lambda r: "/vulnerabilities/sqli/" in r.get("uri", "")
        )

        check(
            "Successful customers.csv download",
            "http", 1,
            lambda r: (
                r.get("uri") == "/dump/customers.csv"
                and r.get("method") == "GET"
                and r.get("status_code") == 200
                and r.get("response_body_len") == 28370
            )
        )

        check(
            "Expected customers.csv SHA256 in files.log",
            "files", 1,
            lambda r: r.get("sha256") == EXPECTED_CSV_SHA256
        )

    elif case_id == "case03":
        count("Total DNS connections", "conn", 242)
        count("Total DNS transactions", "dns", 242)

        field_count("Baseline A queries", "dns",
                    "qtype_name", "A", 40)

        field_count("Tunnel TXT queries", "dns",
                    "qtype_name", "TXT", 202)

        check(
            "Queries under tunnel parent domain",
            "dns", 202,
            lambda r: r.get("query", "").endswith(
                ".t.exfil-lab.test"
            )
        )

    elif case_id == "case04":
        count("Total TCP connections", "conn", 52)
        port_count("Connections to C2 port 8443", "conn", 8443, 46)
        port_count("Benign HTTPS connections to port 443",
                   "conn", 443, 6)

        field_count("Primary C2 connection records",
                    "conn", "id.resp_h", "203.0.113.50", 22)

        field_count("Backup C2 connection records",
                    "conn", "id.resp_h", "203.0.113.51", 24)

        count("TLS analysis records", "ssl", 50)

        field_count("Primary C2 established TLS sessions",
                    "ssl", "id.resp_h", "203.0.113.50", 20)

        field_count("Backup C2 established TLS sessions",
                    "ssl", "id.resp_h", "203.0.113.51", 24)

        field_count("Benign TLS sessions",
                    "ssl", "id.resp_h", "198.51.100.20", 6)

    return results


def write_report(case_id, folder, results):
    report_dir = ROOT / "cases" / folder / "report"
    report_dir.mkdir(parents=True, exist_ok=True)

    passed = sum(s == "PASS" for s, _, _ in results)
    failed = sum(s == "FAIL" for s, _, _ in results)
    inconclusive = sum(s == "INCONCLUSIVE" for s, _, _ in results)

    lines = [
        f"# Verification Report - {folder}",
        "",
        f"- Case ID: `{case_id}`",
        "- Evidence source: `zeek/json/`",
        "- Timezone: UTC",
        "",
        "## Results",
        "",
        "| Status | Verification | Observed result |",
        "|---|---|---|",
    ]

    for status, description, detail in results:
        lines.append(f"| {status} | {description} | {detail} |")

    lines.extend([
        "",
        "## Summary",
        "",
        f"- PASS: {passed}",
        f"- FAIL: {failed}",
        f"- INCONCLUSIVE: {inconclusive}",
        "",
        "## Interpretation",
        "",
        "This report validates observable Zeek log records against "
        "the configured expected values.",
        "",
        "A matching count does not independently prove the underlying "
        "activity or establish packet-level integrity.",
        "",
    ])

    output = report_dir / "verify_counts.md"
    output.write_text("\n".join(lines), encoding="utf-8")

    return passed, failed, inconclusive, output


def main():
    parser = argparse.ArgumentParser(
        description="Verify all P09 forensic cases."
    )
    parser.add_argument(
        "case",
        nargs="?",
        choices=CASES.keys(),
        help="Verify one case, e.g. case01"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Verify all four cases"
    )

    args = parser.parse_args()

    if not args.all and not args.case:
        parser.error("Specify a case ID or --all")

    selected = CASES.items() if args.all else [
        (args.case, CASES[args.case])
    ]

    totals = Counter()

    for case_id, folder in selected:
        print(f"\n{'=' * 65}")
        print(f"VERIFYING {folder}")
        print("=" * 65)

        results = verify_case(case_id, folder)

        for status, description, detail in results:
            print(f"[{status:12}] {description}: {detail}")
            totals[status] += 1

        passed, failed, inconclusive, output = write_report(
            case_id, folder, results
        )

        print(f"\nReport: {output.relative_to(ROOT)}")
        print(
            f"Summary: {passed} PASS, {failed} FAIL, "
            f"{inconclusive} INCONCLUSIVE"
        )

    print(f"\n{'=' * 65}")
    print("OVERALL VERIFICATION")
    print("=" * 65)
    print(f"PASS:         {totals['PASS']}")
    print(f"FAIL:         {totals['FAIL']}")
    print(f"INCONCLUSIVE: {totals['INCONCLUSIVE']}")

    if totals["FAIL"]:
        return 1
    if totals["INCONCLUSIVE"]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
