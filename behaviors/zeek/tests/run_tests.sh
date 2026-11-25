#!/usr/bin/env bash
# Run the agentic-behaviors Zeek package against behaviors-sample.pcap and check that every notice fires and that
# the near misses and benign traffic stay quiet.
# The pcap uses documentation ranges (198.18/15, 198.51.100/24, 203.0.113/24) as outside addresses, so private
# ranges are not treated as local here; 10.0.0.0/8 is the site and 10.0.0.5 is the one server.
set -euo pipefail
cd "$(dirname "$0")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
site='redef Site::private_address_space_is_local = F; redef Site::local_nets += { 10.0.0.0/8 };'
(cd "$work" && zeek -C -r "$OLDPWD/behaviors-sample.pcap" "$OLDPWD/../agentic-behaviors" -e \
    "$site redef AgenticBehaviors::server_nets += { 10.0.0.5/32 };" >/dev/null 2>stderr.txt)
log="$work/notice.log"
fail=0
# count <notice> [text]: notice.log lines of that type, optionally only those that also hold the text.
count() { { grep "AgenticBehaviors::$1" "$log" 2>/dev/null || true; } | { grep -F -- "${2:-}" || true; } | wc -l | tr -d ' '; }
# quiet <what> <notice> [text]: fail when such a line exists.
quiet() { if [ "$(count "$2" "${3:-}")" != 0 ]; then echo "UNEXPECTED: $1"; fail=1; fi; }

if [ -s "$work/stderr.txt" ]; then echo "UNEXPECTED: zeek wrote to stderr"; cat "$work/stderr.txt"; fail=1; fi
for n in Model_API_From_Server AI_Agent_Attacking_Site Rotating_Proxy_Probing Backup_File_Served Backup_Path_Sweep \
         WSUS_Admin_From_Internet WSUS_Port_From_Internet Kerberos_Enumeration SMB_WinRM_Fan_Out Callback_To_Prober Out_Of_Band_Lookup Agent_Console_Realm; do
    if grep -q "AgenticBehaviors::$n" "$log" 2>/dev/null; then echo "notice: $n"; else echo "MISSING: $n"; fail=1; fi
done
# The benign visitor and the www.example.com call must not raise anything.
if grep -E "198\.51\.100\.(99|100)|203\.0\.113\.21|example\.org" "$log" >/dev/null 2>&1; then echo "UNEXPECTED: benign traffic raised a notice"; fail=1; fi
# Both model API hosts must be seen, including the DashScope subdomain.
grep -q "coding.dashscope.aliyuncs.com" "$log" || { echo "MISSING: DashScope subdomain"; fail=1; }

# Kerberos: Zeek must parse the requests themselves. 31 AS-REQs (30 from the enumerating address) and one TGS-REQ.
krb() { { grep -v '^#' "$work/kerberos.log" 2>/dev/null || true; } | awk -F'\t' -v src="$1" -v type="$2" '$3 == src && $7 == type' | wc -l | tr -d ' '; }
[ "$(krb 10.0.0.66 AS)" = 30 ] || { echo "MISSING: 30 parsed AS-REQs from 10.0.0.66 in kerberos.log, got $(krb 10.0.0.66 AS)"; fail=1; }
[ "$(krb 10.0.0.70 TGS)" = 1 ] || { echo "MISSING: parsed TGS-REQ from 10.0.0.70 in kerberos.log"; fail=1; }
# Only 12 of the 30 names come back in errors, so 25 accounts can only be counted from the AS-REQs.
[ "$(count Kerberos_Enumeration '10.0.0.66 asked the KDC about 25 accounts, 12 failed')" = 1 ] || { echo "MISSING: Kerberos enumeration counted from AS-REQs"; fail=1; }
quiet "a workstation signing in raised a notice" "" "10.0.0.70"

# Rotating proxies: the host whose ratio is met late in the window must be caught; the login page in normal use must not.
[ "$(count Rotating_Proxy_Probing shop.example.test)" = 1 ] || { echo "MISSING: rotating proxies on shop.example.test"; fail=1; }
[ "$(count Rotating_Proxy_Probing late.example.test)" = 1 ] || { echo "MISSING: rotating proxies on late.example.test (ratio met late)"; fail=1; }
quiet "a login page in normal use raised Rotating_Proxy_Probing" Rotating_Proxy_Probing portal.example.test

# Near misses.
quiet "a realm that only starts with Cairn raised Agent_Console_Realm" Agent_Console_Realm "Cairns Holiday"
quiet "a laptop outside server_nets raised a notice" "" "10.0.0.77"
quiet "a catch-all 200 page raised Backup_File_Served" Backup_File_Served "203.0.113.32"
quiet "a SYN scan raised SMB_WinRM_Fan_Out" SMB_WinRM_Fan_Out "10.0.0.67"
quiet "a connect scan raised SMB_WinRM_Fan_Out" SMB_WinRM_Fan_Out "10.0.0.68"
quiet "an ordinary visitor raised Callback_To_Prober" Callback_To_Prober "203.0.113.41"
quiet "a CDN edge raised Callback_To_Prober" Callback_To_Prober "198.51.100.50"
quiet "Burp's polling name raised Out_Of_Band_Lookup" Out_Of_Band_Lookup "looked up polling.oastify.com"
# A payload name with a polling. label in front is not Burp's client: it must raise the notice.
[ "$(count Out_Of_Band_Lookup 'looked up polling.b8j1wp6z0a2c.oast.fun')" = 1 ] || { echo "MISSING: Out_Of_Band_Lookup for a payload name that starts with polling."; fail=1; }
# Three interactsh names from one server inside the hour: one notice.
[ "$(count Out_Of_Band_Lookup)" = 1 ] || { echo "UNEXPECTED: $(count Out_Of_Band_Lookup) Out_Of_Band_Lookup notices, want 1"; fail=1; }

# With server_nets left empty the server checks stay off and Zeek says so once.
mkdir "$work/unset"
(cd "$work/unset" && zeek -C -r "$OLDPWD/behaviors-sample.pcap" "$OLDPWD/../agentic-behaviors" -e "$site" >/dev/null 2>stderr.txt)
log="$work/unset/notice.log"
for n in Model_API_From_Server Callback_To_Prober Out_Of_Band_Lookup; do
    quiet "$n fired with server_nets empty" "$n"
done
[ "$(count Rotating_Proxy_Probing)" = 2 ] || { echo "MISSING: checks that need no server_nets, with server_nets empty"; fail=1; }
[ "$(grep -c 'server_nets is empty' "$work/unset/stderr.txt")" = 1 ] || { echo "MISSING: one warning that server_nets is empty"; fail=1; }

[ $fail -eq 0 ] && echo PASS || { echo FAIL; exit 1; }
