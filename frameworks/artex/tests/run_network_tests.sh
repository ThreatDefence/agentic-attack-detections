#!/usr/bin/env bash
# Run the Zeek script and the Suricata rules against tests/artex-sample.pcap and check the expected hits.
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
pcap=tests/artex-sample.pcap
python3 ../../tools/build_feeds.py >/dev/null

echo "== Suricata"
cat suricata/artex.rules suricata/artex-ip.rules > "$work/all.rules"
suricata -k none -r "$pcap" -S "$work/all.rules" -l "$work" >/dev/null 2>&1
got_sids=$(grep -o '\[1:[0-9]*:' "$work/fast.log" | cut -d: -f2 | sort -u | tr '\n' ' ')
echo "alerts: $got_sids"
fail=0
for sid in 3800001 3800008 3800020 3800022 3800023 3800025 3800040 3800060 3800062 3800063 3800065 3800066 3800067 3800042 3800084 3800085 3800086; do
  if ! grep -q "\[1:$sid:" "$work/fast.log"; then echo "MISSING suricata sid $sid"; fail=1; fi
done
if grep -q "198.51.100.7" "$work/fast.log"; then echo "FALSE POSITIVE on benign browser request"; fail=1; fi
if grep -q "198.51.100.8" "$work/fast.log"; then echo "FALSE POSITIVE on a realm that only starts with Artex"; fail=1; fi

echo "== Zeek"
(cd "$work" && zeek -C -r "$OLDPWD/$pcap" "$OLDPWD/zeek/artex" >/dev/null)
notices=$(cut -f11 "$work/notice.log" 2>/dev/null | grep '^ARTEX' | sort -u | tr '\n' ' ' || true)
echo "notices: $notices"
for n in ARTEX::User_Agent ARTEX::Probe_Marker ARTEX::Probe_Path ARTEX::JWT_Alg_None ARTEX::Console_Page ARTEX::Console_Auth; do
  if ! grep -q "$n" "$work/notice.log"; then echo "MISSING zeek notice $n"; fail=1; fi
done
# User agent names match in any case, and alg:none tokens with typ after alg and with the NONE spelling are caught.
notice_has() { { grep "$1" "$work/notice.log" 2>/dev/null || true; } | grep -qF -- "$2"; }
for ua in "artex-pentest/1.0" "ScopeWeaver/1.0" "ARTEX-PENTEST/1.0"; do
  if ! notice_has ARTEX::User_Agent "$ua"; then echo "MISSING zeek user agent notice for $ua"; fail=1; fi
done
for jwt in "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30." "eyJhbGciOiJOT05FIn0.e30."; do
  if ! notice_has ARTEX::JWT_Alg_None "$jwt"; then echo "MISSING zeek alg:none notice for $jwt"; fail=1; fi
done
# Renamed consoles: the Japanese title ending (from 10.0.0.21) and the Pojun description (10.0.0.22); the realm (10.0.0.23)
# and the proxy header (10.0.0.24) in front of consoles.
for who in 10.0.0.21 10.0.0.22; do
  if ! notice_has ARTEX::Console_Page "$who"; then echo "MISSING zeek console page notice for the request from $who"; fail=1; fi
done
for who in 10.0.0.23 10.0.0.24; do
  if ! notice_has ARTEX::Console_Auth "$who"; then echo "MISSING zeek console auth notice for the request from $who"; fail=1; fi
done
if grep -q "198.51.100.7" "$work/notice.log"; then echo "FALSE POSITIVE zeek notice on benign browser request"; fail=1; fi
if grep -q "198.51.100.8" "$work/notice.log"; then echo "FALSE POSITIVE zeek notice on a realm that only starts with Artex"; fail=1; fi

echo "== Zeek intel"
# The Intel framework reads files asynchronously, so a short pcap can finish before the file loads.
# This check waits for the file, then looks up indicators of each type.
cat > "$work/intel.zeek" <<ZEEK
@load frameworks/intel/seen
redef Intel::read_files += { "$PWD/zeek/intel/artex.intel" };
redef exit_only_after_terminate = T;
event td_stop() { terminate(); }
event zeek_init() { schedule 20sec { td_stop() }; }
event Input::end_of_data(name: string, source: string)
    {
    Intel::seen([\$indicator="nginxmysql.com", \$indicator_type=Intel::DOMAIN, \$where=DNS::IN_REQUEST]);
    Intel::seen([\$host=199.19.95.66, \$where=Conn::IN_RESP]);
    Intel::seen([\$indicator="artex-pentest/1.0", \$indicator_type=Intel::SOFTWARE, \$where=HTTP::IN_USER_AGENT_HEADER]);
    Intel::seen([\$indicator="ftp.vietnam852.com", \$indicator_type=Intel::DOMAIN, \$where=DNS::IN_REQUEST]);
    Intel::seen([\$indicator="www.example.com", \$indicator_type=Intel::DOMAIN, \$where=DNS::IN_REQUEST]);
    schedule 1sec { td_stop() };
    }
ZEEK
(cd "$work" && zeek "$work/intel.zeek" >/dev/null 2>&1 || true)
for v in nginxmysql.com 199.19.95.66 artex-pentest/1.0 ftp.vietnam852.com; do
  if grep -q "$v" "$work/intel.log" 2>/dev/null; then echo "intel hit: $v"; else echo "MISSING zeek intel hit $v"; fail=1; fi
done
if grep -q "www.example.com" "$work/intel.log" 2>/dev/null; then echo "FALSE POSITIVE intel hit www.example.com"; fail=1; fi

rm -rf "$work"
if [ "$fail" -eq 0 ]; then echo "PASS"; else echo "FAIL"; exit 1; fi
