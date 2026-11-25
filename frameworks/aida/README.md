# AIDA Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

**AIDA** ([Vasco0x4/AIDA](https://github.com/Vasco0x4/AIDA), reviewed at `7f428c0b`, September 15, 2026). Platform that turns any model into a penetration tester: the operator sets the scope, the agent runs tools in its own container (`aida-pentest`) or in Exegol, and the analyst reviews the findings.

This folder was added from the exposure snapshot of November 25, 2026, which found AIDA consoles on the internet. It covers how to recognise an exposed console and what the tool sends, with a file reference for every signal. It has no hunts or Sigma rules yet. No vendor or CERT report of AIDA in a real intrusion was found on November 25, 2026.

| | |
|---|---|
| Platforms | Exposure searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) |
| Docs | [What AIDA leaves behind](source-code-signals.md) |
| Status | Experimental. Baseline every rule on your own data before alerting |

## What AIDA leaves behind

The short version. The full list is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Source |
|---|---|---|
| Page title | `<title>AIDA - AI-Driven Security Assessment</title>` | `frontend/index.html:8` |
| Port | 31337 | `docker-compose.hub.yml:112` |

## Exposed consoles

5 hosts, 4 of them seen in the seven days to November 25, 2026, on ports 31337, 443 and 8443. The addresses are in [`exposure/consoles.csv`](../../exposure/consoles.csv) with `framework` set to `aida`, and the searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv).

## What is in this folder

| Folder | Contents |
|---|---|
| [`zeek/intel/`](zeek/intel) | Intel framework file generated from the CSV (empty until indicators are added) |
| [`suricata/`](suricata) | Address rules generated from the CSV (empty until indicators are added) |

Indicators go in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `aida`.

## Limits

- The stock compose file binds the console to loopback. An exposed console was opened on purpose.
- A match means AIDA, not an attacker: these tools are run by researchers and security teams too. Check who runs it and whether the test was agreed.
