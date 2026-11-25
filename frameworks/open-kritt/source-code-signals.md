# What open-kritt leaves behind

open-kritt ([Kritt-ai/open-kritt](https://github.com/Kritt-ai/open-kritt), reviewed at `ab240adc`, October 28, 2026; repository created July 20, 2026; AGPL-3.0; 2,441 stars on November 25, 2026). Self-hosted vulnerability research tool whose agents find and validate flaws in source code, with an executor view that shows the sandboxed runs. File references are to the repository at `ab240adc` unless another commit is named.

**Fragility** says what it takes to remove a signal: *code* means editing open-kritt, *config* means a setting or environment variable, *operator* means a choice made at run time.

## How it runs

| Part | What it does | Source |
|---|---|---|
| Stack | Frontend on 5173, backend on 3002, executor view on 8090 (container `open-kritt-executor-view`) | `README.md:79`, `.env.example:17`, `docker-compose.yml:56,188` |

## The console

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Page title | `<title>open·kritt</title>` | `frontend/index.html:12` | Code |
| Favicons | `/favicon.svg` (Shodan hash `1455498108`) and `/favicon.ico` (`2014761914`), computed from the files | `frontend/public/favicon.svg`, `frontend/public/favicon.ico` | Code |
| Executor view | `<title>open-kritt executor</title>` on port 8090 | `executor-view/server.py:3983` | Code |

## Signals on a host that runs open-kritt

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Internal user agent | `open-kritt-executor-view` between its own components, not towards a target | `docker-compose.yml:188`, `executor-view/server.py:58` | Code |

## Exposure searches

Each search in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) with `framework` set to `open-kritt`, and the signal above it comes from:

| `matched_on` | Search | Signal |
|---|---|---|
| favicon | `http.favicon.hash:1455498108,2014761914` | Favicons |

1 host on port 80, seen in the seven days to November 25, 2026.

## Behind Basic authentication

Operators put nginx Basic auth in front of the open-kritt console and name the realm after the tool. In Shodan on November 25, 2026, 3 services answered `401` with a realm that starts with `kritt`, on ports 80, 443 and 8080. The realm is set by the web server in front of the console, so a match is probable, not certain. The exposure search `basic auth realm (probable)` finds them, and Suricata 3801043 and the Zeek behavior `AgenticBehaviors::Agent_Console_Realm` match the realm on your own network.
