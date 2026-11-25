# REDCELL Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

**REDCELL** ([martian56/redcell](https://github.com/martian56/redcell), reviewed at `f6dae370`, November 18, 2026). AI red team platform whose LangGraph agents run a penetration test end to end inside a Kali container and write the report, with a pivot module built on chisel.

This folder was added from the exposure snapshot of November 25, 2026, which found REDCELL consoles on the internet. It covers how to recognise an exposed console and what the tool sends, with a file reference for every signal. It has no hunts or Sigma rules yet. No vendor or CERT report of REDCELL in a real intrusion was found on November 25, 2026.

| | |
|---|---|
| Platforms | Exposure searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) |
| Docs | [What REDCELL leaves behind](source-code-signals.md) |
| Status | Experimental. Baseline every rule on your own data before alerting |

## What REDCELL leaves behind

The short version. The full list is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Source |
|---|---|---|
| Page title | `<title>REDCELL</title>` | `apps/web/index.html:23` |
| Theme key | `localStorage.getItem('rc-theme')` in the page | `apps/web/index.html:13` |
| App title | `<meta name="apple-mobile-web-app-title" content="REDCELL" />` | `apps/web/index.html:10` |
| Pivot | After a foothold, a chisel client on the target dials back to the operator | `packages/core/redcell_core/engine/pivot.py:8,131` |

## Exposed consoles

1 host on port 80, not seen in the seven days to November 25, 2026. The addresses are in [`exposure/consoles.csv`](../../exposure/consoles.csv) with `framework` set to `redcell`, and the searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv).

## What is in this folder

| Folder | Contents |
|---|---|
| [`zeek/intel/`](zeek/intel) | Intel framework file generated from the CSV (empty until indicators are added) |
| [`suricata/`](suricata) | Address rules generated from the CSV (empty until indicators are added) |

Indicators go in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `redcell`.

## Limits

- A match means REDCELL, not an attacker: these tools are run by researchers and security teams too. Check who runs it and whether the test was agreed.
