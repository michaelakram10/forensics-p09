#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
for n in 01 02 03 04; do python3 "gen_case$n.py"; done
../tools/seal_evidence.sh
for c in case01 case02 case03 case04; do ../tools/custody.sh "$c" "generated and sealed by Presenter"; done
