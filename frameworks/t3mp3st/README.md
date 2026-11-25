# T3MP3ST Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

**T3MP3ST** ([elder-plinius/T3MP3ST](https://github.com/elder-plinius/T3MP3ST), reviewed at `29824d56`, September 7, 2026). Multi-agent red teaming harness with recon, OSINT and exploitation tools and a command and control dashboard.

This folder was added from the exposure snapshot of November 25, 2026, which found T3MP3ST consoles on the internet. It covers how to recognise an exposed console and what the tool sends, with a file reference for every signal. It has no hunts or Sigma rules yet. No vendor or CERT report of T3MP3ST in a real intrusion was found on November 25, 2026.

| | |
|---|---|
| Platforms | Exposure searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) |
| Docs | [What T3MP3ST leaves behind](source-code-signals.md) |
| Status | Experimental. Baseline every rule on your own data before alerting |

## What T3MP3ST leaves behind

The short version. The full list is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Source |
|---|---|---|
| Dashboard title | `<title>T3MP3ST - Command & Control Dashboard</title>` | `docs/index.html:7` |
| Settings key | `localStorage.getItem('t3mp3st_api_url')` | `docs/index.html:6136-6139` |
| Port | 3333 | `Dockerfile:36` |
| User agents | `T3MP3ST/1.0`, `Mozilla/5.0 (compatible; T3MP3ST-JS/1.0)`, `Mozilla/5.0 (compatible; T3MP3ST-OSINT/1.0)` | `src/arsenal/index.ts:3155`, `src/arsenal/js-analyze.ts:49`, `src/arsenal/social-osint.ts:34` |

## Exposed consoles

1 host on port 3333, seen in the seven days to November 25, 2026. The addresses are in [`exposure/consoles.csv`](../../exposure/consoles.csv) with `framework` set to `t3mp3st`, and the searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv).

## What is in this folder

| Folder | Contents |
|---|---|
| [`zeek/intel/`](zeek/intel) | Intel framework file generated from the CSV (empty until indicators are added) |
| [`suricata/`](suricata) | Address rules generated from the CSV (empty until indicators are added) |

Indicators go in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `t3mp3st`.

## Limits

- A match means T3MP3ST, not an attacker: these tools are run by researchers and security teams too. Check who runs it and whether the test was agreed.
