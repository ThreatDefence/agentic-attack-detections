# Decepticon Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

**Decepticon** ([BitterSecurity/Decepticon](https://github.com/BitterSecurity/Decepticon), reviewed at `6b15092d`, November 20, 2026). Autonomous red team agent built on LangGraph, with a Kali sandbox and on-demand Sliver C2, BloodHound and reverse-engineering workloads. Its open web console was removed on November 11, 2026 (`02864fbd`, "remove OSS web dashboard in favor of the SaaS UI"); consoles still online run older builds.

This folder was added from the exposure snapshot of November 25, 2026, which found Decepticon consoles on the internet. It covers how to recognise an exposed console and what the tool sends, with a file reference for every signal. It has no hunts or Sigma rules yet. No vendor or CERT report of Decepticon in a real intrusion was found on November 25, 2026.

| | |
|---|---|
| Platforms | Exposure searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) |
| Docs | [What Decepticon leaves behind](source-code-signals.md) |
| Status | Experimental. Baseline every rule on your own data before alerting |

## What Decepticon leaves behind

The short version. The full list is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Source |
|---|---|---|
| Page title (removed build) | `Decepticon — Autonomous Red Team Platform` | `clients/web/src/app/layout.tsx:21` at `d26ddaa1` |
| Icon (removed build) | `clients/web/src/app/icon.png`, Shodan favicon hash `-1814445533` (computed from the file) | `clients/web/src/app/icon.png` at `d26ddaa1` |
| Passive discovery user agent | `decepticon-roe/1` | `packages/decepticon/decepticon/passive_discovery.py:40` |
| Sandbox HTTP user agent | `decepticon-http-sandbox/1` | `packages/decepticon/decepticon/backends/http_transport.py:139` |

## Exposed consoles

3 hosts on port 3000, 1 seen in the seven days to November 25, 2026. A title search for "Autonomous Red Team Platform" also found 7 pages titled "Jed | The Autonomous Red Team Platform" on port 443: another product, so that search was dropped. The addresses are in [`exposure/consoles.csv`](../../exposure/consoles.csv) with `framework` set to `decepticon`, and the searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv).

## What is in this folder

| Folder | Contents |
|---|---|
| [`zeek/intel/`](zeek/intel) | Intel framework file generated from the CSV (empty until indicators are added) |
| [`suricata/`](suricata) | Address rules generated from the CSV (empty until indicators are added) |

Indicators go in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `decepticon`.

## Limits

- The web console is gone from the current code, so the exposed count will fall as operators update.
- A match means Decepticon, not an attacker: these tools are run by researchers and security teams too. Check who runs it and whether the test was agreed.
