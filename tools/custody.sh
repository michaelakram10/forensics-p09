#!/usr/bin/env bash
# usage: tools/custody.sh <case> "<action>"
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG="$ROOT/custody/custody_log.csv"
[ -f "$LOG" ] || echo "utc_time,user,host,case,action,pcap_sha256" > "$LOG"
case_id="$1"; action="$2"
pcap="$(ls "$ROOT"/cases/${case_id}*/raw/*.pcap 2>/dev/null | head -n 1 || true)"
sum="n/a"; [ -n "$pcap" ] && sum="$(sha256sum "$pcap" | cut -d' ' -f1)"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ),$USER,$(hostname),$case_id,\"$action\",$sum" >> "$LOG"
tail -n 1 "$LOG"
