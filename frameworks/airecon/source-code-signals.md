# What AIRecon leaves behind

AIRecon ([pikpikcu/airecon](https://github.com/pikpikcu/airecon), reviewed at `e5bb22b5`, November 12, 2026; repository created March 5, 2026; MIT; 1,102 stars on November 25, 2026). Autonomous reconnaissance agent that drives a Kali Docker sandbox from a local Ollama model, with a terminal interface and its own SearXNG search instance. File references are to the repository at `e5bb22b5` unless another commit is named.

**Fragility** says what it takes to remove a signal: *code* means editing AIRecon, *config* means a setting or environment variable, *operator* means a choice made at run time.

## How it runs

| Part | What it does | Source |
|---|---|---|
| Search | A SearXNG instance named `AIRecon Search` on port 8080 | `airecon/containers/settings.yml:8,16` |
| Proxy and browser | Proxy on 32445, Chrome DevTools on 9222, Caido on 48080 | `airecon/proxy/config.py:131,307,311` |
| State | `~/.airecon/` (memory and learning databases) | `README.md:81-82` |

## The console

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Search page title | `AIRecon Search`, the SearXNG instance name | `airecon/containers/settings.yml:8` | Config (default) |

## Signals on the target side

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Browser user agent | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36`. Real Chrome 131 on Linux sends it too, so it is context only | `airecon/proxy/agent/constants.py:166` | Code |

## Exposure searches

Each search in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) with `framework` set to `airecon`, and the signal above it comes from:

| `matched_on` | Search | Signal |
|---|---|---|
| search title | `http.title:"AIRecon Search"`, kept only when the title holds it | Search page title |

2 hosts on port 8080, 1 seen in the seven days to November 25, 2026. What is exposed is the search instance, not a control console.
