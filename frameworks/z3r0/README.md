# Z3r0 Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

**Z3r0** ([yv1ing/Z3r0](https://github.com/yv1ing/Z3r0), reviewed at `659be635`, September 4, 2026). Red team workbench with specialist agents, sandboxed tools, an evidence record and an egress proxy pool.

This folder was added from the exposure snapshot of November 25, 2026, which found Z3r0 consoles on the internet. It covers how to recognise an exposed console and what the tool sends, with a file reference for every signal. It has no hunts or Sigma rules yet. No vendor or CERT report of Z3r0 in a real intrusion was found on November 25, 2026.

| | |
|---|---|
| Platforms | Exposure searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) |
| Docs | [What Z3r0 leaves behind](source-code-signals.md) |
| Status | Experimental. Baseline every rule on your own data before alerting |

## What Z3r0 leaves behind

The short version. The full list is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Source |
|---|---|---|
| Page title | `<title>Z3r0 Console</title>`, and the same text on the sign-in page | `web/app/index.html:6`, `web/src/features/auth/LoginPage.tsx:55` |
| Port | 8000 | `config.py:36` |

## Exposed consoles

4 hosts, 1 seen in the seven days to November 25, 2026, on port 8000 and 18089. The addresses are in [`exposure/consoles.csv`](../../exposure/consoles.csv) with `framework` set to `z3r0`, and the searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv).

## What is in this folder

| Folder | Contents |
|---|---|
| [`zeek/intel/`](zeek/intel) | Intel framework file generated from the CSV (empty until indicators are added) |
| [`suricata/`](suricata) | Address rules generated from the CSV (empty until indicators are added) |

Indicators go in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `z3r0`.

## Limits

- A match means Z3r0, not an attacker: these tools are run by researchers and security teams too. Check who runs it and whether the test was agreed.
