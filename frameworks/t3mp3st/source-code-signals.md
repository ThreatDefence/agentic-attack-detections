# What T3MP3ST leaves behind

T3MP3ST ([elder-plinius/T3MP3ST](https://github.com/elder-plinius/T3MP3ST), reviewed at `29824d56`, September 7, 2026; repository created July 2, 2026; AGPL-3.0; 7,133 stars on November 25, 2026). Multi-agent red teaming harness with recon, OSINT and exploitation tools and a command and control dashboard. File references are to the repository at `29824d56` unless another commit is named.

**Fragility** says what it takes to remove a signal: *code* means editing T3MP3ST, *config* means a setting or environment variable, *operator* means a choice made at run time.

## How it runs

| Part | What it does | Source |
|---|---|---|
| Server | Express server on port 3333, the dashboard under `/ui` | `Dockerfile:36`, `docker-compose.yml:11`, `src/server.ts:8150,8217` |

## The console

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Dashboard title | `<title>T3MP3ST - Command & Control Dashboard</title>` | `docs/index.html:7` | Code |
| Settings key | `localStorage.getItem('t3mp3st_api_url')` | `docs/index.html:6136-6139` | Code |
| Port | 3333 | `Dockerfile:36` | Config |

## Signals on the target side

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| User agents | `T3MP3ST/1.0`, `Mozilla/5.0 (compatible; T3MP3ST-JS/1.0)`, `Mozilla/5.0 (compatible; T3MP3ST-OSINT/1.0)` | `src/arsenal/index.ts:3155`, `src/arsenal/js-analyze.ts:49`, `src/arsenal/social-osint.ts:34` | Code |

## Exposure searches

Each search in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) with `framework` set to `t3mp3st`, and the signal above it comes from:

| `matched_on` | Search | Signal |
|---|---|---|
| page title | `http.title:"T3MP3ST"`, kept only when the title holds it | Dashboard title |

1 host on port 3333, seen in the seven days to November 25, 2026.

## Behind Basic authentication

Operators put nginx Basic auth in front of the T3MP3ST console and name the realm after the tool. In Shodan on November 25, 2026, 1 service answered `401` with a realm that starts with `T3MP3ST`, on port 80. The realm is set by the web server in front of the console, so a match is probable, not certain. The exposure search `basic auth realm (probable)` finds them, and Suricata 3801043 and the Zeek behavior `AgenticBehaviors::Agent_Console_Realm` match the realm on your own network.
