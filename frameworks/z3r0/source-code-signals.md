# What Z3r0 leaves behind

Z3r0 ([yv1ing/Z3r0](https://github.com/yv1ing/Z3r0), reviewed at `659be635`, September 4, 2026; repository created April 27, 2026; MIT; 1,022 stars on November 25, 2026). Red team workbench with specialist agents, sandboxed tools, an evidence record and an egress proxy pool. File references are to the repository at `659be635` unless another commit is named.

**Fragility** says what it takes to remove a signal: *code* means editing Z3r0, *config* means a setting or environment variable, *operator* means a choice made at run time.

## How it runs

| Part | What it does | Source |
|---|---|---|
| Server | Listens on port 8000 by default | `config.py:36` |
| Workspace | `.z3r0/` with `config.json` | `config.py:11` |

## The console

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Page title | `<title>Z3r0 Console</title>`, and the same text on the sign-in page | `web/app/index.html:6`, `web/src/features/auth/LoginPage.tsx:55` | Code |
| Port | 8000 | `config.py:36` | Config |

## Signals on a host that runs Z3r0

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Proxy check | `User-Agent: Z3r0-Proxy-Test/1.0` to `https://www.gstatic.com/generate_204` when it tests an egress proxy. The proxy sees it, the target does not | `service/egress_proxy/proxies.py:23,257` | Code |

## Exposure searches

Each search in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) with `framework` set to `z3r0`, and the signal above it comes from:

| `matched_on` | Search | Signal |
|---|---|---|
| page title | `http.title:"Z3r0 Console"`, kept only when the title holds it | Page title |

4 hosts, 1 seen in the seven days to November 25, 2026, on port 8000 and 18089.
