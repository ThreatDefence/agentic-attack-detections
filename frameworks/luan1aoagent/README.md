# LuaN1aoAgent Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

**LuaN1aoAgent** ([SanMuzZzZz/LuaN1aoAgent](https://github.com/SanMuzZzZz/LuaN1aoAgent), reviewed at `19403774`, November 18, 2026). Autonomous penetration testing agent with graph-based planning (鸾鸟, LuaN1ao), a web workbench and a network sandbox reached through chisel.

This folder was added from the exposure snapshot of November 25, 2026, which found LuaN1aoAgent consoles on the internet. It covers how to recognise an exposed console and what the tool sends, with a file reference for every signal. It has no hunts or Sigma rules yet. No vendor or CERT report of LuaN1aoAgent in a real intrusion was found on November 25, 2026.

| | |
|---|---|
| Platforms | Suricata, Zeek, exposure searches |
| Docs | [What LuaN1aoAgent leaves behind](source-code-signals.md) |
| Status | Experimental. Baseline every rule on your own data before alerting |

## What LuaN1aoAgent leaves behind

The short version. The full list is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Source |
|---|---|---|
| Page title | `<title>鸾鸟渗透智能体 · Agent Workbench</title>` | `web/index.html:7` |
| CSRF cookie | `Set-Cookie: luanniao_csrf=<token>; Path=/; SameSite=Lax; Max-Age=604800` | `src/web-security.ts:5,92` |
| Port | 8787 | `README.md:405` |
| Research tool user agent | `LuaN1aoAgent/0.1 security-research` from the search and fetch tools | `src/tools/research-tools.ts:10,134,308` |
| Browser imitation | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/124.0 Safari/537.36`: no `(KHTML, like Gecko)` and a two-part version, so no real browser sends it | `src/tools/research-tools.ts:11,378,417` |

## Exposed consoles

1 host on port 8787, seen in the seven days to November 25, 2026. The addresses are in [`exposure/consoles.csv`](../../exposure/consoles.csv) with `framework` set to `luan1aoagent`, and the searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv).

## What is in this folder

| Folder | Contents |
|---|---|
| [`suricata/`](suricata) | Rules for its console and, where it sends any, its requests |
| [`zeek/`](zeek) | A Zeek package for the same signals, and the Intel framework file generated from the CSV |
| [`tests/`](tests) | A sample capture with near misses and `run_zeek_tests.sh` |

Indicators go in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `luan1aoagent`.

## Limits

- The research tool user agent is also sent to search engines and documentation sites, not only to targets.
- A match means LuaN1aoAgent, not an attacker: these tools are run by researchers and security teams too. Check who runs it and whether the test was agreed.
