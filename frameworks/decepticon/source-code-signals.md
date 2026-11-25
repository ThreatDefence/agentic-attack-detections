# What Decepticon leaves behind

Decepticon ([BitterSecurity/Decepticon](https://github.com/BitterSecurity/Decepticon), reviewed at `6b15092d`, November 20, 2026; repository created June 6, 2025; Apache-2.0; 6,687 stars on November 25, 2026). Autonomous red team agent built on LangGraph, with a Kali sandbox and on-demand Sliver C2, BloodHound and reverse-engineering workloads. Its open web console was removed on November 11, 2026 (`02864fbd`, "remove OSS web dashboard in favor of the SaaS UI"); consoles still online run older builds. File references are to the repository at `6b15092d` unless another commit is named.

**Fragility** says what it takes to remove a signal: *code* means editing Decepticon, *config* means a setting or environment variable, *operator* means a choice made at run time.

## How it runs

| Part | What it does | Source |
|---|---|---|
| Operator interface | A terminal CLI in the current code. Builds before `02864fbd` also had a Next.js web console on port 3000 | `README.md:85`, `clients/web/` at `d26ddaa1` |
| Sandbox | A Kali sandbox reached over HTTP, plus services started on demand | `packages/decepticon/decepticon/backends/http_transport.py` |

## The console

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Page title (removed build) | `Decepticon — Autonomous Red Team Platform` | `clients/web/src/app/layout.tsx:21` at `d26ddaa1` | Code |
| Icon (removed build) | `clients/web/src/app/icon.png`, Shodan favicon hash `-1814445533` (computed from the file) | `clients/web/src/app/icon.png` at `d26ddaa1` | Code |

## Signals on the target side

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Passive discovery user agent | `decepticon-roe/1` | `packages/decepticon/decepticon/passive_discovery.py:40` | Code |
| Sandbox HTTP user agent | `decepticon-http-sandbox/1` | `packages/decepticon/decepticon/backends/http_transport.py:139` | Code |

## Signals on a host that runs Decepticon

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Model gateway user agent | `Decepticon/1.0` on LiteLLM requests | `config/litellm.yaml:622` | Config |

## Exposure searches

Each search in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) with `framework` set to `decepticon`, and the signal above it comes from:

| `matched_on` | Search | Signal |
|---|---|---|
| logo | `http.favicon.hash:-1814445533` | Icon |

3 hosts on port 3000, 1 seen in the seven days to November 25, 2026. A title search for "Autonomous Red Team Platform" also found 7 pages titled "Jed | The Autonomous Red Team Platform" on port 443: another product, so that search was dropped.

## Behind Basic authentication

Operators put nginx Basic auth in front of the Decepticon console and name the realm after the tool. In Shodan on November 25, 2026, 4 services answered `401` with a realm that starts with `Decepticon`, on ports 3000, 80 and 443. The realm is set by the web server in front of the console, so a match is probable, not certain. The exposure search `basic auth realm (probable)` finds them, and Suricata 3801043 and the Zeek behavior `AgenticBehaviors::Agent_Console_Realm` match the realm on your own network.
