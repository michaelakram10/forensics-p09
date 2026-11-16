#!/bin/bash
# Usage: preserve_and_hash.sh <case_dir> <pcap_path>
set -euo pipefail
CASE_DIR="$1"
PCAP="$2"
cp "$PCAP" "$CASE_DIR/raw/"
FNAME=$(basename "$PCAP")
sha256sum "$CASE_DIR/raw/$FNAME" | tee "$P09/custody/$(basename $CASE_DIR).sha256"
capinfos "$CASE_DIR/raw/$FNAME"
