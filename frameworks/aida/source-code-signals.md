# What AIDA leaves behind

AIDA ([Vasco0x4/AIDA](https://github.com/Vasco0x4/AIDA), reviewed at `7f428c0b`, September 15, 2026; repository created January 31, 2026; AGPL-3.0; 521 stars on November 25, 2026). Platform that turns any model into a penetration tester: the operator sets the scope, the agent runs tools in its own container (`aida-pentest`) or in Exegol, and the analyst reviews the findings. File references are to the repository at `7f428c0b` unless another commit is named.

**Fragility** says what it takes to remove a signal: *code* means editing AIDA, *config* means a setting or environment variable, *operator* means a choice made at run time.

## How it runs

| Part | What it does | Source |
|---|---|---|
| Stack | Containers `aida_backend`, `aida_frontend`, `aida_postgres`, a Docker socket proxy and `aida-pentest`; images `vasco0x4/aida-backend`, `vasco0x4/aida-frontend`, `vasco0x4/aida-pentest` | `docker-compose.yml:35`, `docker-compose.hub.yml:76,86,108,124-125` |
| Ports | The console on 31337, bound to 127.0.0.1 unless `FRONTEND_BIND` is changed; the API on 8000 | `docker-compose.hub.yml:8,112`, `docker-compose.yml:49-51` |

## The console

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Page title | `<title>AIDA - AI-Driven Security Assessment</title>` | `frontend/index.html:8` | Code |
| Port | 31337 | `docker-compose.hub.yml:112` | Config |

## Signals on a host that runs AIDA

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Workspace | `.aida/` beside the install, holding `mode-config` | `restart.sh:57-59` | Code |

## Exposure searches

Each search in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) with `framework` set to `aida`, and the signal above it comes from:

| `matched_on` | Search | Signal |
|---|---|---|
| page title | `http.title:"AIDA - AI-Driven Security Assessment"`, kept only when the title holds it | Page title |

5 hosts, 4 of them seen in the seven days to November 25, 2026, on ports 31337, 443 and 8443.
