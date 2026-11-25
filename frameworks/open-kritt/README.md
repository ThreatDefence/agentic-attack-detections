# open-kritt Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

**open-kritt** ([Kritt-ai/open-kritt](https://github.com/Kritt-ai/open-kritt), reviewed at `ab240adc`, October 28, 2026). Self-hosted vulnerability research tool whose agents find and validate flaws in source code, with an executor view that shows the sandboxed runs.

This folder was added from the exposure snapshot of November 25, 2026, which found open-kritt consoles on the internet. It covers how to recognise an exposed console and what the tool sends, with a file reference for every signal. It has no hunts or Sigma rules yet. No vendor or CERT report of open-kritt in a real intrusion was found on November 25, 2026.

| | |
|---|---|
| Platforms | Exposure searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) |
| Docs | [What open-kritt leaves behind](source-code-signals.md) |
| Status | Experimental. Baseline every rule on your own data before alerting |

## What open-kritt leaves behind

The short version. The full list is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Source |
|---|---|---|
| Page title | `<title>open·kritt</title>` | `frontend/index.html:12` |
| Favicons | `/favicon.svg` (Shodan hash `1455498108`) and `/favicon.ico` (`2014761914`), computed from the files | `frontend/public/favicon.svg`, `frontend/public/favicon.ico` |
| Executor view | `<title>open-kritt executor</title>` on port 8090 | `executor-view/server.py:3983` |

## Exposed consoles

1 host on port 80, seen in the seven days to November 25, 2026. The addresses are in [`exposure/consoles.csv`](../../exposure/consoles.csv) with `framework` set to `open-kritt`, and the searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv).

## What is in this folder

| Folder | Contents |
|---|---|
| [`zeek/intel/`](zeek/intel) | Intel framework file generated from the CSV (empty until indicators are added) |
| [`suricata/`](suricata) | Address rules generated from the CSV (empty until indicators are added) |

Indicators go in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `open-kritt`.

## Limits

- open-kritt reviews code; an exposed console says someone runs it, not that anyone is being attacked.
- A match means open-kritt, not an attacker: these tools are run by researchers and security teams too. Check who runs it and whether the test was agreed.
