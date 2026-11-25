# AutoCVE Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

**AutoCVE** ([larlarua/AutoCVE](https://github.com/larlarua/AutoCVE), reviewed at `b26025f2`, September 3, 2026). Agent-driven CVE discovery platform: agents audit a project's source code, verify what they find and write a report.

This folder was added from the exposure snapshot of November 25, 2026, which found AutoCVE consoles on the internet. It covers how to recognise an exposed console and what the tool sends, with a file reference for every signal. It has no hunts or Sigma rules yet. No vendor or CERT report of AutoCVE in a real intrusion was found on November 25, 2026.

| | |
|---|---|
| Platforms | Suricata, Zeek, exposure searches |
| Docs | [What AutoCVE leaves behind](source-code-signals.md) |
| Status | Experimental. Baseline every rule on your own data before alerting |

## What AutoCVE leaves behind

The short version. The full list is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Source |
|---|---|---|
| Console title | `<title>AutoCVE</title>` | `frontend/index.html:8` |
| API welcome | `Welcome to AutoCVE API` next to `demo_account` in the JSON answer to `GET /` on port 8000 | `backend/app/main.py:125-129` |
| Ports | 3000 for the console, 8000 for the API | `docker-compose.yml:94,237` |

## Exposed consoles

256 hosts, 147 of them seen in the seven days to November 25, 2026. Almost all serve the console on port 3000 (244 services); 19 answer on the API port, mostly 8000. AutoCVE is the largest of the frameworks added on that date. The addresses are in [`exposure/consoles.csv`](../../exposure/consoles.csv) with `framework` set to `autocve`, and the searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv).

## What is in this folder

| Folder | Contents |
|---|---|
| [`suricata/`](suricata) | Rules for its console and, where it sends any, its requests |
| [`zeek/`](zeek) | A Zeek package for the same signals, and the Intel framework file generated from the CSV |
| [`tests/`](tests) | A sample capture with near misses and `run_zeek_tests.sh` |

Indicators go in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `autocve`.

## Limits

- AutoCVE audits code. An exposed console says someone runs it, not that anyone is being attacked.
- The demo account in the API answer is the stock one. Where it was not removed, anyone who reaches the console can sign in.
- A match means AutoCVE, not an attacker: these tools are run by researchers and security teams too. Check who runs it and whether the test was agreed.
