# What CyberStrike leaves behind

CyberStrike ([CyberStrikeus/CyberStrike](https://github.com/CyberStrikeus/CyberStrike), reviewed at `f5ee67f9`, November 22, 2026; repository created February 14, 2026; AGPL-3.0; 3,719 stars on November 25, 2026). Open-core offensive security harness written in TypeScript: agents run web and network tests with a browser extension (HackBrowser), an injection prober and a callback server. Not related to CyberStrikeAI, which has its own [folder](../cyberstrikeai). File references are to the repository at `f5ee67f9` unless another commit is named.

**Fragility** says what it takes to remove a signal: *code* means editing CyberStrike, *config* means a setting or environment variable, *operator* means a choice made at run time.

## How it runs

| Part | What it does | Source |
|---|---|---|
| Server | `cyberstrike serve` or `cyberstrike web` listens on port 4096 by default and serves the web app and the API | `packages/cyberstrike/src/server/server.ts:59,716` |
| Browser | A Chrome extension, CyberStrike HackBrowser, drives crawling and login; each session gets a profile directory `hb2-profile-<session>-<credential>` | `CHANGELOG.md:13,59`, `packages/cyberstrike/test/server/web-spawn-import.test.ts:28-30` |
| Callbacks | An optional out-of-band server; the domain comes from `CYBERSTRIKE_OOB_DOMAIN` | `docs/oob-server.md:35,51` |

## The console

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Page title | `<title>CyberStrike</title>` | `packages/app/index.html:6` | Code |
| Theme script | `<script id="cs-theme-preload-script" src="/cs-theme-preload.js">`, kept by renamed builds (HiveHack and HB-Red-team in the snapshot) | `packages/app/index.html:31`, `packages/app/public/cs-theme-preload.js:15` | Code |
| API header | CORS allows the request header `x-cyberstrike-directory`, which selects the working directory | `packages/cyberstrike/src/server/server.ts:110,238` | Code |
| Port | 4096 | `packages/cyberstrike/src/server/server.ts:716` | Config |

## Signals on the target side

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Unknown method probe | HTTP method `CSPROBE`, sent to see whether any verb reaches a handler | `packages/cyberstrike/src/tool/inject-probe/probe/verb.ts:28` | Code |
| Host header probe | `ma<nonce>.poison.test` as the injected host value | `packages/cyberstrike/src/tool/inject-probe/probe/host-header.ts:47` | Code |

## Signals on a host that runs CyberStrike

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Windows hook scripts | `%TEMP%\cs_<number>.bat` written and run through `cmd.exe /c` | `packages/cyberstrike/src/tool/winhook/shared.ts:154,163` | Code |
| Model traffic | `HTTP-Referer: https://cyberstrike.io/` on requests to model gateways, and `User-Agent: cyberstrike/<version>` on Copilot and Codex sign-in calls | `packages/cyberstrike/src/provider/provider.ts:377,476`, `packages/cyberstrike/src/plugin/copilot.ts:208`, `packages/cyberstrike/src/plugin/codex.ts:590` | Code |
| Brain service | `wss://brain.cyberstrike.io/v1/ws` when the hosted brain is used | `packages/cyberstrike/src/cli/cmd/brain.ts:6` | Config |

## Exposure searches

Each search in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) with `framework` set to `cyberstrike`, and the signal above it comes from:

| `matched_on` | Search | Signal |
|---|---|---|
| theme preload script | `http.html:"cs-theme-preload"` | Theme script |
| page title on default ports | `http.title:"CyberStrike" -http.title:"CyberStrikeAI" port:4096,4097,4098`, kept only when the title holds CyberStrike | Page title and port |

8 hosts, 5 of them seen in the seven days to November 25, 2026, mostly on port 4096. Two had renamed the console (HiveHack, HB-Red-team) and were found by the theme script.
