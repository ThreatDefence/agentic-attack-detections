# What Chufeng Agent Core leaves behind

Chufeng Agent Core (no public source code found). Self-hosted agent workspace titled 楚锋 Agent Core. Its sign-in page calls it a local security workspace for CTF, digital forensics and authorised penetration testing tasks. No public source code or report was found on November 25, 2026, so the fingerprints below come from what the servers answered in Shodan's scan data, not from code. References are to the Shodan banners of November 24, 2026.

**Fragility** is *unknown*: without the code it is not known which of these the operator can change.

## How it runs

| Part | What it does | Source |
|---|---|---|
| Server | uvicorn on ports 8765 and 8080; `/` redirects with 303 to `/login` | Shodan banners, November 24, 2026 |

## The console

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Sign-in page title | `<title>登录 · 楚锋 Agent Core</title>` and `<meta name="description" content="登录 楚锋 Agent Core">` | Shodan banner | Unknown |
| Icon | `/assets/favicon.svg?v=2.0.0` | Shodan banner | Unknown |
| Headers | `server: uvicorn`, a strict `content-security-policy`, `x-frame-options: DENY`, `cache-control: no-store` | Shodan banner | Unknown |

## Exposure searches

Each search in [`exposure/shodan-queries.csv`](../../exposure/shodan-queries.csv) with `framework` set to `chufeng`, and the signal above it comes from:

| `matched_on` | Search | Signal |
|---|---|---|
| login title | `http.title:"楚锋 Agent Core"`, kept only when the title holds it | Sign-in page title |

4 hosts on Tencent Cloud, on ports 8765 and 8080, 2 of them seen in the seven days to November 25, 2026.
