# What BugTraceAI leaves behind

BugTraceAI ([BugTraceAI/BugTraceAI](https://github.com/BugTraceAI/BugTraceAI), reviewed at `016697fb`, October 19, 2026; repository created February 11, 2026; Apache-2.0; 377 stars on November 25, 2026). Self-hosted web penetration testing suite: an agentic scanner (BugTraceAI-CLI) with an API, a web interface (BugTraceAI-WEB), an API testing service and MCP servers. Signals are from the sub-repositories BugTraceAI-CLI at `b96ccccf`, BugTraceAI-WEB at `1b406437` and BugTraceAI-API at `83876ee4`. File references are to the repository at `016697fb` unless another commit is named.

**Fragility** says what it takes to remove a signal: *code* means editing BugTraceAI, *config* means a setting or environment variable, *operator* means a choice made at run time.

## How it runs

| Part | What it does | Source |
|---|---|---|
| Scanner API | `serve --host 0.0.0.0 --port 8000` in the CLI image; `GET /` answers `{"name": "BugTraceAI API", ...}` | BugTraceAI-CLI `Dockerfile:102-105`, `bugtrace/api/main.py:110,205` |
| Web interface | Port 6869 by default | BugTraceAI-WEB `.env.example:3`, `README.md:65` |

## The console

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Web page title | `<title>BugTraceAI</title>` | BugTraceAI-WEB `index.html:9` | Code |
| API answer | `"name": "BugTraceAI API"` in the JSON answer to `GET /`. The separate API testing service is titled `BugTraceAI API Testing REST Interface` and is left out of the search | BugTraceAI-CLI `bugtrace/api/main.py:110,205`, BugTraceAI-API `api_server.py:37` | Code |
| Ports | 8000 (scanner API), 6869 (web) | BugTraceAI-CLI `Dockerfile:102`, BugTraceAI-WEB `.env.example:3` | Config |

## Signals on the target side

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Reflection probe | `bugtraceomni7x9z` in parameters | BugTraceAI-CLI `bugtrace/core/config.py:541` | Code |
| Command injection marker | `echo BTAIRCE7331` | BugTraceAI-CLI `bugtrace/agents/rce/agent.py:203` | Code |
| User agents | `BugTraceAI/1.0 XSS-Fuzzer`, `BugTraceAI-AuthProbe/1.2`, `Mozilla/5.0 (compatible; BugTraceAI-WebBrowsing/1.0)`, and by default a 2021 Chrome 91 string | BugTraceAI-CLI `tools/go-xss-fuzzer/fuzzer/fuzzer.go:135`, BugTraceAI-API `tools/auth_probe.py:204`, BugTraceAI-WEB `backend/src/services/webFetchService.ts:60`, BugTraceAI-CLI `bugtrace/core/config.py:743` | Code, config for the Chrome string |
| XSS payload | `HACKED BY BUGTRACEAI` in the bundled payload list | BugTraceAI-CLI `tools/go-xss-fuzzer/payloads/xss_payloads.txt:3` | Code |

## Exposure searches

Each search in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) with `framework` set to `bugtraceai`, and the signal above it comes from:

| `matched_on` | Search | Signal |
|---|---|---|
| API answer | `http.html:"BugTraceAI API" -http.html:"Testing REST Interface"` | API answer |
| page title | `http.title:"BugTraceAI" -http.title:"BugStore"`, kept only when the title holds BugTraceAI | Web page title |

3 hosts with 4 services, all seen in the seven days to November 25, 2026: the web interface on 6869 and the scanner API on 8000. BugStore, the project's deliberately vulnerable practice shop, is titled with BugTraceAI too and is left out.
