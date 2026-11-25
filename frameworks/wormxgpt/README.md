# WormXGPT Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

**WormXGPT** ([gaur-avvv/wormxgpt](https://github.com/gaur-avvv/wormxgpt), reviewed at `d4abdb4c`, October 19, 2026). Hacker-themed AI tooling suite: a React web terminal and a local MCP bridge that call security tools from a model prompted to drop its limits. It borrows the WormGPT name; it is not the criminal service of that name.

This folder was added from the exposure snapshot of November 25, 2026, which found WormXGPT consoles on the internet. It covers how to recognise an exposed console and what the tool sends, with a file reference for every signal. It has no hunts or Sigma rules yet. No vendor or CERT report of WormXGPT in a real intrusion was found on November 25, 2026.

| | |
|---|---|
| Platforms | Exposure searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) |
| Docs | [What WormXGPT leaves behind](source-code-signals.md) |
| Status | Experimental. Baseline every rule on your own data before alerting |

## What WormXGPT leaves behind

The short version. The full list is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Source |
|---|---|---|
| Page title | `<title>WormGPT Red Terminal</title>` | `index.html:21` |
| Port | 3000 | `vite.config.ts:31` |
| User agents | `WormGPT-Agent`, `WormGPT-Security-Agent/1.0`, `WormGPT-SecurityAudit` | `services/tools.ts:909,2180,3690` |

## Exposed consoles

1 host on port 3000, not seen in the seven days to November 25, 2026. The addresses are in [`exposure/consoles.csv`](../../exposure/consoles.csv) with `framework` set to `wormxgpt`, and the searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv).

## What is in this folder

| Folder | Contents |
|---|---|
| [`zeek/intel/`](zeek/intel) | Intel framework file generated from the CSV (empty until indicators are added) |
| [`suricata/`](suricata) | Address rules generated from the CSV (empty until indicators are added) |

Indicators go in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `wormxgpt`.

## Limits

- Pages that sell or imitate the criminal WormGPT service are not this tool and are not in the list.
- A match means WormXGPT, not an attacker: these tools are run by researchers and security teams too. Check who runs it and whether the test was agreed.
