#!/usr/bin/env bash
# usage: tools/run_zeek.sh case01_ssh_bruteforce case01
set -euo pipefail
export TZ=UTC
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CASE_DIR="$ROOT/cases/$1"
PCAP="$CASE_DIR/raw/$2.pcap"

( cd "$CASE_DIR/raw" && sha256sum -c "$2.pcap.sha256" )      # refuse to run on a modified pcap

rm -rf "$CASE_DIR"/zeek/tsv/* "$CASE_DIR"/zeek/json/*

# 1) TSV logs (for zeek-cut) + hashing + file extraction. -C ignores checksum errors.
( cd "$CASE_DIR/zeek/tsv"  && zeek -C -r "$PCAP" local \
      frameworks/files/hash-all-files frameworks/files/extract-all-files )

# 2) JSON logs (for jq / pandas / plotting)
( cd "$CASE_DIR/zeek/json" && zeek -C -r "$PCAP" LogAscii::use_json=T local )

zeek --version > "$CASE_DIR/zeek/zeek_version.txt"
echo "--- TSV logs ---";  ls -1 "$CASE_DIR/zeek/tsv"
echo "--- JSON logs ---"; ls -1 "$CASE_DIR/zeek/json"
