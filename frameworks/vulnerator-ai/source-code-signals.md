# What Vulnerator AI leaves behind

Vulnerator AI ([irraz/vulnerator-ai](https://github.com/irraz/vulnerator-ai), reviewed at `11ea08d4`, November 24, 2026; repository created October 15, 2026; MIT; 295 stars on November 25, 2026). OODA-loop penetration testing agent: a Hermes Agent brain drives Kali and Playwright tools over MCP, with Caido as the interception proxy and ATT&CK as its planning language. File references are to the repository at `11ea08d4` unless another commit is named.

**Fragility** says what it takes to remove a signal: *code* means editing Vulnerator AI, *config* means a setting or environment variable, *operator* means a choice made at run time.

## How it runs

| Part | What it does | Source |
|---|---|---|
| Stack | Docker Compose: `vulnerator-ai-kali` (tools), the Hermes agent (`nousresearch/hermes-agent`), Caido (`caido/caido`) and, in the `web` profile, the operator console `vulnerator-web` on port 9100 | `docker-compose.yml:32,577`, `.env.example:91,225`, `README.md:109,114` |
| Console auth | Basic auth with the realm `Vulnerator-AI` | `docker/web/web_app.py:275` |

## The console

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Page title | `<title>Vulnerator Console</title>` | `docker/web/static/index.html:8` | Code |
| Basic auth realm | `WWW-Authenticate: Basic realm="Vulnerator-AI", charset="UTF-8"` | `docker/web/web_app.py:275` | Code |
| Port | 9100 | `README.md:114`, `CHANGELOG.md:19` | Config |

## Signals on the target side

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Tools | Default signatures of the Kali tools and a Playwright browser, relayed through Caido | `docker-compose.yml`, `README.md:109` | Code |

## Signals on a host that runs Vulnerator AI

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Containers | Images `vulnerator-ai-kali`, `nousresearch/hermes-agent` and `caido/caido`; Hermes API on port 8642 | `docker-compose.yml:32,577`, `CHANGELOG.md:138` | Config |

## Exposure searches

Each search in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) with `framework` set to `vulnerator-ai`, and the signal above it comes from:

| `matched_on` | Search | Signal |
|---|---|---|
| page title | `http.title:"Vulnerator Console"` | Page title |

21 hosts, all on port 9100, none seen in the seven days to November 25, 2026. The realm search found no host.
