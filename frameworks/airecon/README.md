# AIRecon Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

**AIRecon** ([pikpikcu/airecon](https://github.com/pikpikcu/airecon), reviewed at `e5bb22b5`, November 12, 2026). Autonomous reconnaissance agent that drives a Kali Docker sandbox from a local Ollama model, with a terminal interface and its own SearXNG search instance.

This folder was added from the exposure snapshot of November 25, 2026, which found AIRecon consoles on the internet. It covers how to recognise an exposed console and what the tool sends, with a file reference for every signal. It has no hunts or Sigma rules yet. No vendor or CERT report of AIRecon in a real intrusion was found on November 25, 2026.

| | |
|---|---|
| Platforms | Exposure searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) |
| Docs | [What AIRecon leaves behind](source-code-signals.md) |
| Status | Experimental. Baseline every rule on your own data before alerting |

## What AIRecon leaves behind

The short version. The full list is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Source |
|---|---|---|
| Search page title | `AIRecon Search`, the SearXNG instance name | `airecon/containers/settings.yml:8` |
| Browser user agent | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36`. Real Chrome 131 on Linux sends it too, so it is context only | `airecon/proxy/agent/constants.py:166` |

## Exposed consoles

2 hosts on port 8080, 1 seen in the seven days to November 25, 2026. What is exposed is the search instance, not a control console. The addresses are in [`exposure/consoles.csv`](../../exposure/consoles.csv) with `framework` set to `airecon`, and the searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv).

## What is in this folder

| Folder | Contents |
|---|---|
| [`zeek/intel/`](zeek/intel) | Intel framework file generated from the CSV (empty until indicators are added) |
| [`suricata/`](suricata) | Address rules generated from the CSV (empty until indicators are added) |

Indicators go in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `airecon`.

## Limits

- The exposed service is a search page. It says AIRecon runs there; it does not give control of the agent.
- A match means AIRecon, not an attacker: these tools are run by researchers and security teams too. Check who runs it and whether the test was agreed.
