# Chufeng Agent Core Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

**Chufeng Agent Core** (no public source code found). Self-hosted agent workspace titled 楚锋 Agent Core. Its sign-in page calls it a local security workspace for CTF, digital forensics and authorised penetration testing tasks. No public source code or report was found on November 25, 2026, so the fingerprints below come from what the servers answered in Shodan's scan data, not from code.

This folder was added from the exposure snapshot of November 25, 2026, which found Chufeng Agent Core consoles on the internet. It covers how to recognise an exposed console and what the tool sends, with a source for every signal. It has no hunts or Sigma rules yet. No vendor or CERT report of Chufeng Agent Core in a real intrusion was found on November 25, 2026.

| | |
|---|---|
| Platforms | Exposure searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) |
| Docs | [What Chufeng Agent Core leaves behind](source-code-signals.md) |
| Status | Experimental. Baseline every rule on your own data before alerting |

## What Chufeng Agent Core leaves behind

The short version. The full list is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Source |
|---|---|---|
| Sign-in page title | `<title>登录 · 楚锋 Agent Core</title>` and `<meta name="description" content="登录 楚锋 Agent Core">` | Shodan banner |
| Icon | `/assets/favicon.svg?v=2.0.0` | Shodan banner |
| Headers | `server: uvicorn`, a strict `content-security-policy`, `x-frame-options: DENY`, `cache-control: no-store` | Shodan banner |

## Exposed consoles

4 hosts on Tencent Cloud, on ports 8765 and 8080, 2 of them seen in the seven days to November 25, 2026. The addresses are in [`exposure/consoles.csv`](../../exposure/consoles.csv) with `framework` set to `chufeng`, and the searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv).

## What is in this folder

| Folder | Contents |
|---|---|
| [`zeek/intel/`](zeek/intel) | Intel framework file generated from the CSV (empty until indicators are added) |
| [`suricata/`](suricata) | Address rules generated from the CSV (empty until indicators are added) |

Indicators go in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `chufeng`.

## Limits

- There is no source to review, so it is not known what the agents do. The folder records the console so it can be followed.
- A match means Chufeng Agent Core, not an attacker: these tools are run by researchers and security teams too. Check who runs it and whether the test was agreed.
