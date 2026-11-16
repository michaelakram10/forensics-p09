# Verification Report - case04_c2_beacon

- Case ID: `case04`
- Evidence source: `zeek/json/`
- Timezone: UTC

## Results

| Status | Verification | Observed result |
|---|---|---|
| PASS | Total TCP connections | 52 (expected 52) |
| PASS | Connections to C2 port 8443 | 46 (expected 46) |
| PASS | Benign HTTPS connections to port 443 | 6 (expected 6) |
| PASS | Primary C2 connection records | 22 (expected 22) |
| PASS | Backup C2 connection records | 24 (expected 24) |
| PASS | TLS analysis records | 50 (expected 50) |
| PASS | Primary C2 established TLS sessions | 20 (expected 20) |
| PASS | Backup C2 established TLS sessions | 24 (expected 24) |
| PASS | Benign TLS sessions | 6 (expected 6) |

## Summary

- PASS: 9
- FAIL: 0
- INCONCLUSIVE: 0

## Interpretation

This report validates observable Zeek log records against the configured expected values.

A matching count does not independently prove the underlying activity or establish packet-level integrity.
