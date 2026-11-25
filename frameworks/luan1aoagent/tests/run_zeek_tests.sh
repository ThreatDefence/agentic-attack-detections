#!/usr/bin/env bash
# Run the LuaN1aoAgent Zeek package against tests/luan1aoagent-sample.pcap: every notice must fire and the near misses must stay quiet.
# Rebuild the capture with: python3 tests/make_pcap.py
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
(cd "$work" && zeek -C -r "$OLDPWD/tests/luan1aoagent-sample.pcap" "$OLDPWD/zeek/luan1aoagent" >/dev/null 2>stderr.txt)
log="$work/notice.log"
fail=0
expect() { if ! { grep "LuaN1aoAgent::$1" "$log" 2>/dev/null || true; } | grep -qF -- "$2"; then echo "MISSING: $1 with $2"; fail=1; fi; }
quiet() { if grep -qF -- "$2" "$log" 2>/dev/null; then echo "UNEXPECTED: $1"; fail=1; fi; }

if [ -s "$work/stderr.txt" ]; then echo "UNEXPECTED: zeek wrote to stderr"; cat "$work/stderr.txt"; fail=1; fi
for n in User_Agent Browser_Imitation Console_Page; do
    if grep -q "LuaN1aoAgent::$n" "$log" 2>/dev/null; then echo "notice: $n"; else echo "MISSING: $n"; fail=1; fi
done
expect User_Agent "LuaN1aoAgent/0.1 security-research"
expect Browser_Imitation "Chrome/124.0 Safari/537.36"
expect Console_Page "workbench page served"
expect Console_Page "workbench cookie set"
quiet "a real Chrome 124 on macOS" 198.51.100.50
quiet "a user agent that names the tool later" 198.51.100.51
quiet "another CSRF cookie" 198.51.100.52

if [ "$fail" -eq 0 ]; then echo "PASS"; else echo "FAIL"; exit 1; fi
