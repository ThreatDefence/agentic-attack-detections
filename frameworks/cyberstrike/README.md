# CyberStrike Detection Rules and IOCs

Part of [Agentic Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

**CyberStrike** ([CyberStrikeus/CyberStrike](https://github.com/CyberStrikeus/CyberStrike), reviewed at `f5ee67f9`, November 22, 2026). Open-core offensive security harness written in TypeScript: agents run web and network tests with a browser extension (HackBrowser), an injection prober and a callback server. Not related to CyberStrikeAI, which has its own [folder](../cyberstrikeai).

This folder was added from the exposure snapshot of November 25, 2026, which found CyberStrike consoles on the internet. It covers how to recognise an exposed console and what the tool sends, with a file reference for every signal. It has no hunts or Sigma rules yet. No vendor or CERT report of CyberStrike in a real intrusion was found on November 25, 2026.

| | |
|---|---|
| Platforms | Exposure searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) |
| Docs | [What CyberStrike leaves behind](source-code-signals.md) |
| Status | Experimental. Baseline every rule on your own data before alerting |

## What CyberStrike leaves behind

The short version. The full list is in [source-code-signals.md](source-code-signals.md).

| Signal | What it looks like | Source |
|---|---|---|
| Page title | `<title>CyberStrike</title>` | `packages/app/index.html:6` |
| Theme script | `<script id="cs-theme-preload-script" src="/cs-theme-preload.js">`, kept by renamed builds (HiveHack and HB-Red-team in the snapshot) | `packages/app/index.html:31`, `packages/app/public/cs-theme-preload.js:15` |
| API header | CORS allows the request header `x-cyberstrike-directory`, which selects the working directory | `packages/cyberstrike/src/server/server.ts:110,238` |
| Port | 4096 | `packages/cyberstrike/src/server/server.ts:716` |
| Unknown method probe | HTTP method `CSPROBE`, sent to see whether any verb reaches a handler | `packages/cyberstrike/src/tool/inject-probe/probe/verb.ts:28` |
| Host header probe | `ma<nonce>.poison.test` as the injected host value | `packages/cyberstrike/src/tool/inject-probe/probe/host-header.ts:47` |

## Exposed consoles

8 hosts, 5 of them seen in the seven days to November 25, 2026, mostly on port 4096. Two had renamed the console (HiveHack, HB-Red-team) and were found by the theme script. The addresses are in [`exposure/consoles.csv`](../../exposure/consoles.csv) with `framework` set to `cyberstrike`, and the searches in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv).

## What is in this folder

| Folder | Contents |
|---|---|
| [`zeek/intel/`](zeek/intel) | Intel framework file generated from the CSV (empty until indicators are added) |
| [`suricata/`](suricata) | Address rules generated from the CSV (empty until indicators are added) |

Indicators go in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `cyberstrike`.

## Limits

- `CyberStrike` alone is a common word in page titles, which is why the title search is held to the default ports.
- Not to be confused with CyberStrikeAI: different code, different authors.
- A match means CyberStrike, not an attacker: these tools are run by researchers and security teams too. Check who runs it and whether the test was agreed.
