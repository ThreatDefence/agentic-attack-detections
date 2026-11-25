# What LuaN1aoAgent leaves behind

LuaN1aoAgent ([SanMuzZzZz/LuaN1aoAgent](https://github.com/SanMuzZzZz/LuaN1aoAgent), reviewed at `19403774`, November 18, 2026; repository created December 4, 2025; AGPL-3.0; 1,500 stars on November 25, 2026). Autonomous penetration testing agent with graph-based planning (鸾鸟, LuaN1ao), a web workbench and a network sandbox reached through chisel. File references are to the repository at `19403774` unless another commit is named.

**Fragility** says what it takes to remove a signal: *code* means editing LuaN1aoAgent, *config* means a setting or environment variable, *operator* means a choice made at run time.

## How it runs

| Part | What it does | Source |
|---|---|---|
| Workbench | `npm run web -- --port 8787`; the first user to register becomes the administrator | `README.md:405-408` |
| Sandbox tunnel | A chisel server in reverse mode on port 19090 | `src/connectivity/network-sandbox-manager.ts:265,1011` |

## The console

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Page title | `<title>鸾鸟渗透智能体 · Agent Workbench</title>` | `web/index.html:7` | Code |
| CSRF cookie | `Set-Cookie: luanniao_csrf=<token>; Path=/; SameSite=Lax; Max-Age=604800` | `src/web-security.ts:5,92` | Code |
| Port | 8787 | `README.md:405` | Config |

## Signals on the target side

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Research tool user agent | `LuaN1aoAgent/0.1 security-research` from the search and fetch tools | `src/tools/research-tools.ts:10,134,308` | Code |
| Browser imitation | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/124.0 Safari/537.36`: no `(KHTML, like Gecko)` and a two-part version, so no real browser sends it | `src/tools/research-tools.ts:11,378,417` | Code |

## Signals on a host that runs LuaN1aoAgent

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Tunnel | `chisel server --reverse --keyfile /run/luanniao/chisel.key --host 0.0.0.0 --port 19090` | `src/connectivity/network-sandbox-manager.ts:1011` | Code |

## Exposure searches

Each search in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) with `framework` set to `luan1aoagent`, and the signal above it comes from:

| `matched_on` | Search | Signal |
|---|---|---|
| page title | `http.title:"鸾鸟渗透智能体"`, kept only when the title holds it | Page title |

1 host on port 8787, seen in the seven days to November 25, 2026.

## Rules

The Suricata rules in [`suricata/luan1aoagent.rules`](suricata/luan1aoagent.rules) and the Zeek package in [`zeek/luan1aoagent/`](zeek/luan1aoagent) match the signals above. Each Suricata rule has a case and a near miss in [`tests/suricata/run_tests.py`](../../tests/suricata/run_tests.py); the Zeek package runs against [`tests/luan1aoagent-sample.pcap`](tests/luan1aoagent-sample.pcap).
