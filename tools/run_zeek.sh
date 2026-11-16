#!/bin/bash
# Usage: run_zeek.sh <case_dir>
set -euo pipefail
CASE_DIR="$1"
PCAP=$(ls "$CASE_DIR"/raw/*.pcap | head -1)
(cd "$CASE_DIR/zeek/tsv" && zeek -C -r "../../raw/$(basename $PCAP)")
(cd "$CASE_DIR/zeek/json" && zeek -C -r "../../raw/$(basename $PCAP)" LogAscii::use_json=T)
