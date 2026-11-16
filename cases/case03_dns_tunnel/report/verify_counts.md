# Verification Report - case03_dns_tunnel

- Case ID: `case03`
- Evidence source: `zeek/json/`
- Timezone: UTC

## Results

| Status | Verification | Observed result |
|---|---|---|
| PASS | Total DNS connections | 242 (expected 242) |
| PASS | Total DNS transactions | 242 (expected 242) |
| PASS | Baseline A queries | 40 (expected 40) |
| PASS | Tunnel TXT queries | 202 (expected 202) |
| PASS | Queries under tunnel parent domain | 202 (expected 202) |

## Summary

- PASS: 5
- FAIL: 0
- INCONCLUSIVE: 0

## Interpretation

This report validates observable Zeek log records against the configured expected values.

A matching count does not independently prove the underlying activity or establish packet-level integrity.
