# Verification Report - case02_web_sqli

- Case ID: `case02`
- Evidence source: `zeek/json/`
- Timezone: UTC

## Results

| Status | Verification | Observed result |
|---|---|---|
| PASS | Total TCP connections | 3 (expected 3) |
| PASS | Total HTTP requests | 17 (expected 17) |
| PASS | File-analysis records | 17 (expected 17) |
| FAIL | SQL injection endpoint requests | 13 (expected 11) |
| PASS | Successful customers.csv download | 1 (expected 1) |
| PASS | Expected customers.csv SHA256 in files.log | 1 (expected 1) |

## Summary

- PASS: 5
- FAIL: 1
- INCONCLUSIVE: 0

## Interpretation

This report validates observable Zeek log records against the configured expected values.

A matching count does not independently prove the underlying activity or establish packet-level integrity.
