# What AutoCVE leaves behind

AutoCVE ([larlarua/AutoCVE](https://github.com/larlarua/AutoCVE), reviewed at `b26025f2`, September 3, 2026; repository created June 15, 2026; AGPL-3.0; 1,241 stars on November 25, 2026). Agent-driven CVE discovery platform: agents audit a project's source code, verify what they find and write a report. File references are to the repository at `b26025f2` unless another commit is named.

**Fragility** says what it takes to remove a signal: *code* means editing AutoCVE, *config* means a setting or environment variable, *operator* means a choice made at run time.

## How it runs

| Part | What it does | Source |
|---|---|---|
| Stack | Docker Compose: the web console on port 3000 (nginx serving the built frontend, `3000:80`) and the FastAPI backend on port 8000, with PostgreSQL and Redis | `docker-compose.yml:94,237`, `docker-compose.prod.yml` |
| API root | `GET /` on the API answers `{"message": "Welcome to AutoCVE API", "docs": "/docs", "demo_account": {"email": "demo@example.com", "password": "demo123"}}` without a login. The demo account is printed in the answer | `backend/app/main.py:122-130` |
| Work | The agents read source code. Nothing is sent to the audited project itself, so AutoCVE is not seen on the target side | `backend/app/`, `skill_library/` |

## The console

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Console title | `<title>AutoCVE</title>` | `frontend/index.html:8` | Code |
| API welcome | `Welcome to AutoCVE API` next to `demo_account` in the JSON answer to `GET /` on port 8000 | `backend/app/main.py:125-129` | Code |
| Ports | 3000 for the console, 8000 for the API | `docker-compose.yml:94,237` | Config |

## Signals on a host that runs AutoCVE

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Report titles | `AutoCVE 审计报告 - <task>` and `AutoCVE 最终漏洞报告` in exported HTML reports | `frontend/src/pages/AgentAudit/components/ReportExportDialog.tsx:286`, `backend/app/services/task_report_service.py:260` | Code |

## Exposure searches

Each search in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) with `framework` set to `autocve`, and the signal above it comes from:

| `matched_on` | Search | Signal |
|---|---|---|
| page title | `http.title:"AutoCVE"`, kept only when the title holds AutoCVE | Console title |
| API welcome | `http.html:"Welcome to AutoCVE API"` | API welcome |

256 hosts, 147 of them seen in the seven days to November 25, 2026. Almost all serve the console on port 3000 (244 services); 19 answer on the API port, mostly 8000. AutoCVE is the largest of the frameworks added on that date.

## Rules

The Suricata rules in [`suricata/autocve.rules`](suricata/autocve.rules) and the Zeek package in [`zeek/autocve/`](zeek/autocve) match the signals above. Each Suricata rule has a case and a near miss in [`tests/suricata/run_tests.py`](../../tests/suricata/run_tests.py); the Zeek package runs against [`tests/autocve-sample.pcap`](tests/autocve-sample.pcap).
