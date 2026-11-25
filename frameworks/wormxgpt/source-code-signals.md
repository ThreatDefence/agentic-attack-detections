# What WormXGPT leaves behind

WormXGPT ([gaur-avvv/wormxgpt](https://github.com/gaur-avvv/wormxgpt), reviewed at `d4abdb4c`, October 19, 2026; repository created January 28, 2026; Apache-2.0; 86 stars on November 25, 2026). Hacker-themed AI tooling suite: a React web terminal and a local MCP bridge that call security tools from a model prompted to drop its limits. It borrows the WormGPT name; it is not the criminal service of that name. File references are to the repository at `d4abdb4c` unless another commit is named.

**Fragility** says what it takes to remove a signal: *code* means editing WormXGPT, *config* means a setting or environment variable, *operator* means a choice made at run time.

## How it runs

| Part | What it does | Source |
|---|---|---|
| Web terminal | Vite on port 3000 | `package.json:10`, `vite.config.ts:31` |
| MCP bridge | `wormxgpt serve` on port 3002 | `mcp-server.ts:802`, `README.md:101` |

## The console

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Page title | `<title>WormGPT Red Terminal</title>` | `index.html:21` | Code |
| Port | 3000 | `vite.config.ts:31` | Config |

## Signals on the target side

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| User agents | `WormGPT-Agent`, `WormGPT-Security-Agent/1.0`, `WormGPT-SecurityAudit` | `services/tools.ts:909,2180,3690` | Code |

## Signals on a host that runs WormXGPT

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Model requests | `X-Title: WormGPT Terminal` to OpenRouter | `services/openrouter.ts:40` | Code |

## Exposure searches

Each search in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) with `framework` set to `wormxgpt`, and the signal above it comes from:

| `matched_on` | Search | Signal |
|---|---|---|
| page title | `http.title:"WormGPT Red Terminal"`, kept only when the title holds it | Page title |

1 host on port 3000, not seen in the seven days to November 25, 2026.
