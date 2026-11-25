# What REDCELL leaves behind

REDCELL ([martian56/redcell](https://github.com/martian56/redcell), reviewed at `f6dae370`, November 18, 2026; repository created August 2, 2026; MIT; 418 stars on November 25, 2026). AI red team platform whose LangGraph agents run a penetration test end to end inside a Kali container and write the report, with a pivot module built on chisel. File references are to the repository at `f6dae370` unless another commit is named.

**Fragility** says what it takes to remove a signal: *code* means editing REDCELL, *config* means a setting or environment variable, *operator* means a choice made at run time.

## How it runs

| Part | What it does | Source |
|---|---|---|
| Stack | Images `ghcr.io/martian56/redcell-api` and `ghcr.io/martian56/redcell-kali`; the admin password comes from `REDCELL_ADMIN_PASSWORD` | `docker-compose.yml:18-19,71`, `README.md:106` |
| First run | `GET /api/v1/auth/first-run` tells the interface whether the stock admin password is still in use, with a hint | `apps/api/app/routers/auth.py:21`, `docs/PRE-AUTH-SURFACE.md:16` |

## The console

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Page title | `<title>REDCELL</title>` | `apps/web/index.html:23` | Code |
| Theme key | `localStorage.getItem('rc-theme')` in the page | `apps/web/index.html:13` | Code |
| App title | `<meta name="apple-mobile-web-app-title" content="REDCELL" />` | `apps/web/index.html:10` | Code |

## Signals on the target side

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Pivot | After a foothold, a chisel client on the target dials back to the operator | `packages/core/redcell_core/engine/pivot.py:8,131` | Code |

## Signals on a host that runs REDCELL

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Tunnel tooling | ngrok is installed in the worker image | `docker/worker/Dockerfile:7-8` | Code |

## Exposure searches

Each search in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) with `framework` set to `redcell`, and the signal above it comes from:

| `matched_on` | Search | Signal |
|---|---|---|
| app title and theme key | `http.title:"REDCELL" http.html:"rc-theme"`, kept only when the title holds REDCELL | Page title and theme key |

1 host on port 80, not seen in the seven days to November 25, 2026.
