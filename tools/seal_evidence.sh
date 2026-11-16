#!/usr/bin/env bash
# Hash every pcap in cases/*/raw, write <file>.sha256, make both read-only.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
for d in "$ROOT"/cases/*/raw; do
  ( cd "$d"
    for f in *.pcap; do
      [ -e "$f" ] || continue
      chmod u+w "$f" 2>/dev/null || true
      sha256sum "$f" > "$f.sha256"
      chmod 444 "$f" "$f.sha256"
      echo "SEALED $d/$f  $(cut -d' ' -f1 "$f.sha256")"
    done )
done
