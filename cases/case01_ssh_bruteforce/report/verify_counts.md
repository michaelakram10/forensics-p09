# Verification Report - case01_ssh_bruteforce

- Case ID: `case01`
- Evidence source: `zeek/json/`
- Timezone: UTC

## Results

| Status | Verification | Observed result |
|---|---|---|
| PASS | Total Zeek connections | 50 (expected 50) |
| PASS | Connections to SSH port 22 | 38 (expected 38) |
| PASS | SSH protocol records | 37 (expected 37) |
| PASS | SSH connections using libssh banner | 36 (expected 36) |
| PASS | SSH connections using OpenSSH banner | 1 (expected 1) |

## Summary

- PASS: 5
- FAIL: 0
- INCONCLUSIVE: 0

## Interpretation

This report validates observable Zeek log records against the configured expected values.

A matching count does not independently prove the underlying activity or establish packet-level integrity.
