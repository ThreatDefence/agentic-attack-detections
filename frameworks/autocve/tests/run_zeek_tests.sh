#!/usr/bin/env bash
# Run the AutoCVE Zeek package against tests/autocve-sample.pcap: every notice must fire and the near misses must stay quiet.
# Rebuild the capture with: python3 tests/make_pcap.py
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
(cd "$work" && zeek -C -r "$OLDPWD/tests/autocve-sample.pcap" "$OLDPWD/zeek/autocve" >/dev/null 2>stderr.txt)
log="$work/notice.log"
fail=0
expect() { if ! { grep "AutoCVE::$1" "$log" 2>/dev/null || true; } | grep -qF -- "$2"; then echo "MISSING: $1 with $2"; fail=1; fi; }
quiet() { if grep -qF -- "$2" "$log" 2>/dev/null; then echo "UNEXPECTED: $1"; fail=1; fi; }

if [ -s "$work/stderr.txt" ]; then echo "UNEXPECTED: zeek wrote to stderr"; cat "$work/stderr.txt"; fail=1; fi
for n in API_Exposed Console_Page; do
    if grep -q "AutoCVE::$n" "$log" 2>/dev/null; then echo "notice: $n"; else echo "MISSING: $n"; fail=1; fi
done
expect API_Exposed "10.0.0.8:8000"
expect Console_Page "10.0.0.8:3000"
quiet "a page that quotes the API welcome" 198.51.100.50
quiet "a page titled with more than AutoCVE" 198.51.100.51

if [ "$fail" -eq 0 ]; then echo "PASS"; else echo "FAIL"; exit 1; fi
