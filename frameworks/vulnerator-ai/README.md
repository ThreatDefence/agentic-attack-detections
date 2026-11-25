# Vulnerator AI Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

**Vulnerator AI** ([irraz/vulnerator-ai](https://github.com/irraz/vulnerator-ai), reviewed at `11ea08d4`, November 24, 2026). OODA-loop penetration testing agent: a Hermes Agent brain drives Kali and Playwright tools over MCP, with Caido as the interception proxy and ATT&CK as its planning language.

This folder was added from the exposure snapshot of November 25, 2026, which found Vulnerator AI consoles on the internet. It covers how to recognise an exposed console and what the tool sends, with a file reference for every signal. It has no hunts or Sigma rules yet. No vendor or CERT report of Vulnerator AI in a real intrusion was found on November 25, 2026.

| | |
|---|---|
| Platforms | Exposure searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) |
| Docs | [What Vulnerator AI leaves behind](source-code-signals.md) |
| Status | Experimental. Baseline every rule on your own data before alerting |

## What Vulnerator AI leaves behind

The short version. The full list is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Source |
|---|---|---|
| Page title | `<title>Vulnerator Console</title>` | `docker/web/static/index.html:8` |
| Basic auth realm | `WWW-Authenticate: Basic realm="Vulnerator-AI", charset="UTF-8"` | `docker/web/web_app.py:275` |
| Port | 9100 | `README.md:114`, `CHANGELOG.md:19` |
| Tools | Default signatures of the Kali tools and a Playwright browser, relayed through Caido | `docker-compose.yml`, `README.md:109` |

## Exposed consoles

21 hosts, all on port 9100, none seen in the seven days to November 25, 2026. The realm search found no host. The addresses are in [`exposure/consoles.csv`](../../exposure/consoles.csv) with `framework` set to `vulnerator-ai`, and the searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv).

## What is in this folder

| Folder | Contents |
|---|---|
| [`zeek/intel/`](zeek/intel) | Intel framework file generated from the CSV (empty until indicators are added) |
| [`suricata/`](suricata) | Address rules generated from the CSV (empty until indicators are added) |

Indicators go in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `vulnerator-ai`.

## Limits

- Hermes Agent is the brain, so a host running Vulnerator AI also matches the [Hermes Agent](../hermes) signals.
- A match means Vulnerator AI, not an attacker: these tools are run by researchers and security teams too. Check who runs it and whether the test was agreed.
