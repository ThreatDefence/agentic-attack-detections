# BugTraceAI Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

**BugTraceAI** ([BugTraceAI/BugTraceAI](https://github.com/BugTraceAI/BugTraceAI), reviewed at `016697fb`, October 19, 2026). Self-hosted web penetration testing suite: an agentic scanner (BugTraceAI-CLI) with an API, a web interface (BugTraceAI-WEB), an API testing service and MCP servers. Signals are from the sub-repositories BugTraceAI-CLI at `b96ccccf`, BugTraceAI-WEB at `1b406437` and BugTraceAI-API at `83876ee4`.

This folder was added from the exposure snapshot of November 25, 2026, which found BugTraceAI consoles on the internet. It covers how to recognise an exposed console and what the tool sends, with a file reference for every signal. It has no hunts or Sigma rules yet. No vendor or CERT report of BugTraceAI in a real intrusion was found on November 25, 2026.

| | |
|---|---|
| Platforms | Exposure searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) |
| Docs | [What BugTraceAI leaves behind](source-code-signals.md) |
| Status | Experimental. Baseline every rule on your own data before alerting |

## What BugTraceAI leaves behind

The short version. The full list is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Source |
|---|---|---|
| Web page title | `<title>BugTraceAI</title>` | BugTraceAI-WEB `index.html:9` |
| API answer | `"name": "BugTraceAI API"` in the JSON answer to `GET /`. The separate API testing service is titled `BugTraceAI API Testing REST Interface` and is left out of the search | BugTraceAI-CLI `bugtrace/api/main.py:110,205`, BugTraceAI-API `api_server.py:37` |
| Ports | 8000 (scanner API), 6869 (web) | BugTraceAI-CLI `Dockerfile:102`, BugTraceAI-WEB `.env.example:3` |
| Reflection probe | `bugtraceomni7x9z` in parameters | BugTraceAI-CLI `bugtrace/core/config.py:541` |
| Command injection marker | `echo BTAIRCE7331` | BugTraceAI-CLI `bugtrace/agents/rce/agent.py:203` |
| User agents | `BugTraceAI/1.0 XSS-Fuzzer`, `BugTraceAI-AuthProbe/1.2`, `Mozilla/5.0 (compatible; BugTraceAI-WebBrowsing/1.0)`, and by default a 2021 Chrome 91 string | BugTraceAI-CLI `tools/go-xss-fuzzer/fuzzer/fuzzer.go:135`, BugTraceAI-API `tools/auth_probe.py:204`, BugTraceAI-WEB `backend/src/services/webFetchService.ts:60`, BugTraceAI-CLI `bugtrace/core/config.py:743` |
| XSS payload | `HACKED BY BUGTRACEAI` in the bundled payload list | BugTraceAI-CLI `tools/go-xss-fuzzer/payloads/xss_payloads.txt:3` |

## Exposed consoles

3 hosts with 4 services, all seen in the seven days to November 25, 2026: the web interface on 6869 and the scanner API on 8000. BugStore, the project's deliberately vulnerable practice shop, is titled with BugTraceAI too and is left out. The addresses are in [`exposure/consoles.csv`](../../exposure/consoles.csv) with `framework` set to `bugtraceai`, and the searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv).

## What is in this folder

| Folder | Contents |
|---|---|
| [`zeek/intel/`](zeek/intel) | Intel framework file generated from the CSV (empty until indicators are added) |
| [`suricata/`](suricata) | Address rules generated from the CSV (empty until indicators are added) |

Indicators go in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `bugtraceai`.

## Limits

- BugStore pages carry the BugTraceAI name but are a practice target, not a console.
- A match means BugTraceAI, not an attacker: these tools are run by researchers and security teams too. Check who runs it and whether the test was agreed.
