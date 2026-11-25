#!/usr/bin/env python3
"""Run the Elastic rules in a real Elasticsearch and Kibana and check what they find.

    python3 tests/elastic/run_tests.py --es http://localhost:9200 --kibana http://localhost:5601

Needs Elasticsearch and Kibana with the Security app, the elastic user's password in ELASTIC_PASSWORD. lab/ starts
both in Docker. The test:

1. Writes test events into the data stream logs-aad.test-default with ECS field names: for every Sigma rule, its own
   test events from tests/sigma/fixtures/, a matching event made from each branch of its condition and a near miss for
   each, the same events tests/splunk/run_tests.py sends to Splunk. The Sigma rule decides whether each event should
   match.
2. Runs each rule's Lucene query against those events the way the detection engine does (query_string over logs-*)
   and checks Elasticsearch agrees with the Sigma rule on every event.
3. Imports every rule into Kibana Security in one NDJSON import, enables them, waits for their first run and checks
   each run succeeded and that the rules with a matching test event raised an alert.

The NDJSON comes from tools/build_elastic.py when it exists, otherwise it is built here the same way (pass --ndjson to
import a file of your own). Rules stay enabled afterwards with --keep-enabled, so the lab keeps showing alerts.

Exit status is non-zero on any failure.
"""
import argparse
import base64
import copy
import importlib.util
import json
import os
import re
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import attack  # noqa: E402
import convert  # noqa: E402
from sigma.collection import SigmaCollection  # noqa: E402
from sigma.correlations import SigmaCorrelationRule  # noqa: E402
from sigma.rule import SigmaDetection  # noqa: E402

# The Splunk test already makes events from a Sigma condition; this test sends the same ones.
_spec = importlib.util.spec_from_file_location("splunk_run_tests", ROOT / "tests" / "splunk" / "run_tests.py")
splunk_tests = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(splunk_tests)

DATA_STREAM = "logs-aad.test-default"
INDEX = ["logs-*", "filebeat-*", "winlogbeat-*", "packetbeat-*"]
REPO = "https://github.com/ThreatDefence/agentic-attack-detections"
# Kibana's severity values are low, medium, high and critical; anything else fails the import.
LEVEL = {"informational": ("low", 21), "low": ("low", 21), "medium": ("medium", 47),
         "high": ("high", 73), "critical": ("critical", 99)}
CATEGORY = {"process_creation": ("process", "start"), "file_event": ("file", "creation"), "dns_query": ("network", "protocol"),
            "proxy": ("web", "access"), "webserver": ("web", "access"), "registry_set": ("registry", "change")}
failures = []


def fail(msg):
    failures.append(msg)
    print("FAIL", msg)


class Http:
    def __init__(self, url, password, kibana=False):
        self.url = url.rstrip("/")
        self.headers = {"Authorization": "Basic " + base64.b64encode(f"elastic:{password}".encode()).decode()}
        if kibana:
            self.headers.update({"kbn-xsrf": "true", "elastic-api-version": "2023-10-31"})

    def call(self, method, path, body=None, raw=None, ctype="application/json"):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        headers = dict(self.headers, **({"Content-Type": ctype} if data is not None else {}))
        req = urllib.request.Request(self.url + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"{method} {path}: HTTP {e.code}: {e.read().decode(errors='replace')[:800]}") from None


# ----- rules -------------------------------------------------------------------------------------------------------

def leaf_items(det):
    for x in det.detection_items:
        if isinstance(x, SigmaDetection):
            yield from leaf_items(x)
        else:
            yield x


def sigma_rules():
    """[(rule, lucene query, {sigma field: ECS field})] for every Sigma rule with an Elastic conversion."""
    cls, plist = convert.pipelines()["elastic_lucene"]
    files = sorted(p for d in convert.SIGMA_DIRS for p in d.rglob("*.yml"))
    out = []
    for rule in SigmaCollection.load_ruleset([str(p) for p in files]).rules:
        if isinstance(rule, SigmaCorrelationRule):
            continue
        done = convert_rule(rule)
        if done is None:
            if rule._output:
                print(f"skip (no Elastic conversion): {convert.rel_of(Path(str(rule.source.path)))}")
            continue
        out.append((rule, *done))
    return out


def convert_rule(rule):
    """(lucene query, {sigma field: ECS field}) for one rule, or None. A correlation's base rule converts too."""
    cls, plist = convert.pipelines()["elastic_lucene"]
    if not rule._output:
        rule = copy.deepcopy(rule)
        rule._output = True
    for _, pipe in plist:
        mapped = copy.deepcopy(rule)
        try:
            q = convert.convert_one(cls, pipe, SigmaCollection([mapped]))
        except Exception:  # noqa: BLE001 - the next pipeline may map what this one could not
            continue
        if q:
            break
    else:
        return None
    fields = {}
    for name, det in rule.detection.detections.items():
        for a, b in zip(leaf_items(det), leaf_items(mapped.detection.detections[name])):
            if a.field and b.field and a.field != b.field:
                fields[a.field] = b.field
    return q[0], fields


def correlation_events(rules, run, stamp):
    """For each correlation in the import: enough events from one source to cross its threshold.

    The events are the union of every matching branch of the base rule, so each column the ES|QL query names exists.
    The group-by and counted fields come from the query itself. Returns (docs, {rule_id: title}).
    """
    by_id = {}
    files = sorted(p for d in convert.SIGMA_DIRS for p in d.rglob("*.yml"))
    for r in SigmaCollection.load_ruleset([str(p) for p in files]).rules:
        if isinstance(r, SigmaCorrelationRule):
            by_id[str(r.id)] = r
    docs, expect = [], {}
    for rule in rules:
        corr = by_id.get(rule["rule_id"])
        if corr is None or rule.get("type") != "esql":
            continue
        base = corr.rules[0].rule
        query, fields = convert_rule(base)
        event = {}
        for _, expected, ev in splunk_tests.rule_events(base, ROOT / "tests" / "sigma" / "fixtures"):
            if expected:
                event.update(ev)
        # Numbers stay numbers (Entra ID result codes are numeric in the Azure integration).
        event = {k: int(v) if isinstance(v, str) and v.isdigit() else v for k, v in event.items()}
        group = re.search(r"by timebucket, ([\w.@]+)", rule["query"]).group(1)
        counted = re.search(r"count_distinct\(([\w.@]+)\)", rule["query"])
        for i in range(corr.condition.count + 2):
            doc = ecs_event(event, fields, base.logsource.category, f"{run}-corr-{rule['rule_id']}-{i}", stamp)
            put(doc, group, "198.51.100.7" if group.endswith(".ip") else f"aad-{run}-group")
            if counted:
                put(doc, counted.group(1), f"aad-{run}-value-{i}")
            docs.append(doc)
        expect[rule["rule_id"]] = rule["name"]
    return docs, expect


def link(path):
    return f"{REPO}/blob/main/{path.relative_to(ROOT).as_posix()}"


def build_ndjson(converted):
    """The import file: every Sigma rule and the hand-written ARTEX rules, disabled."""
    build_elastic = ROOT / "tools" / "build_elastic.py"
    if build_elastic.exists():
        spec = importlib.util.spec_from_file_location("build_elastic", build_elastic)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        print("rules: from tools/build_elastic.py")
        return mod.build()
    rules = []
    for rule, query, _ in converted:
        severity, risk = LEVEL.get(rule.level.name.lower() if rule.level else "medium", ("medium", 47))
        rules.append({
            "rule_id": str(rule.id), "name": rule.title, "description": (rule.description or rule.title).strip(),
            "severity": severity, "risk_score": risk, "type": "query", "language": "lucene", "query": query,
            "index": INDEX, "enabled": False, "author": [a.strip() for a in (rule.author or "ThreatDefence").split(",")],
            "references": list(rule.references or []),
            "false_positives": list(rule.falsepositives or []), "from": "now-9m", "interval": "5m", "max_signals": 100,
            "note": link(Path(str(rule.source.path))), "tags": ["Agentic Attack Detections"],
        })
    for path in sorted(ROOT.glob("frameworks/*/elastic/rules/*.toml")):
        rule = tomllib.loads(path.read_text(encoding="utf-8"))["rule"]
        rule.update(enabled=False, note=link(path))
        rule.setdefault("from", "now-9m")
        rule.setdefault("interval", "5m")
        rules.append(rule)
    print("rules: built here (no tools/build_elastic.py on this branch)")
    return "".join(json.dumps(r, sort_keys=True) + "\n" for r in rules).encode()


# ----- events ------------------------------------------------------------------------------------------------------

# Elastic Defend maps these with a lowercase "caseless" sub-field, and the ECS Windows pipeline queries that sub-field.
CASELESS = ["process.executable", "process.parent.executable", "process.name", "process.parent.name",
            "process.command_line", "process.parent.command_line", "file.path", "file.name"]


NUMERIC = {"azure.signinlogs.properties.status.error_code": "long"}


def ensure_template(es):
    """logs-aad.test-*: the built-in logs template plus Elastic Defend's caseless sub-fields."""
    base = es.call("GET", "/_index_template/logs")["index_templates"][0]["index_template"]
    props = {}
    for f in CASELESS:
        node = props
        parts = f.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {"properties": {}})["properties"]
        node[parts[-1]] = {"type": "keyword", "fields": {"caseless": {"type": "keyword", "normalizer": "aad_lowercase"}}}
    # Typed as in Elastic's integrations, so the ES|QL correlations compare like with like.
    for f, kind in NUMERIC.items():
        node = props
        parts = f.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {"properties": {}})["properties"]
        node[parts[-1]] = {"type": kind}
    es.call("PUT", "/_index_template/aad-test", {
        "index_patterns": ["logs-aad.test-*"], "priority": 200, "data_stream": {},
        "composed_of": base["composed_of"], "ignore_missing_component_templates": base.get("ignore_missing_component_templates", []),
        "template": {"settings": {"analysis": {"normalizer": {"aad_lowercase": {"type": "custom", "filter": ["lowercase"]}}}},
                     "mappings": {"properties": props}},
        "_meta": {"description": "agentic-attack-detections lab test events"}})
    try:
        current = es.call("GET", f"/{DATA_STREAM}/_mapping/field/process.executable.caseless")
    except RuntimeError:
        return  # no data stream yet; the first event creates it from the template
    if not any(v.get("mappings") for v in current.values()):
        es.call("POST", f"/{DATA_STREAM}/_rollover")  # a stream made before the template: new events go to a new index


def ecs_event(event, fields, category, case, stamp):
    doc = {"@timestamp": stamp, "event": {"ingested": stamp}, "labels": {"aad_case": case}, "host": {"name": "aad-test-host"}}
    if category in CATEGORY:
        doc["event"].update(category=CATEGORY[category][0], type=CATEGORY[category][1])
    for k, v in event.items():
        put(doc, fields.get(k, k).removesuffix(".caseless"), v)
    return doc


def put(doc, key, value):
    """Set a dotted field, inside an object the event already has (event, host, labels) so no field is written twice."""
    head, _, rest = key.partition(".")
    if rest and isinstance(doc.get(head), dict):
        put(doc[head], rest, value)
    else:
        doc[key] = value


def bulk(es, docs):
    for i in range(0, len(docs), 500):
        lines = "".join(json.dumps({"create": {}}) + "\n" + json.dumps(d) + "\n" for d in docs[i:i + 500])
        res = es.call("POST", f"/{DATA_STREAM}/_bulk?refresh=true", raw=lines.encode(), ctype="application/x-ndjson")
        if res.get("errors"):
            bad = [it["create"]["error"] for it in res["items"] if "error" in it["create"]][:3]
            fail(f"bulk indexing: {bad}")


# ----- main --------------------------------------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--es", default="http://localhost:9200")
    ap.add_argument("--kibana", default="http://localhost:5601")
    ap.add_argument("--ndjson", type=Path, help="import this NDJSON file instead of building one")
    ap.add_argument("--skip-kibana", action="store_true", help="only check the queries in Elasticsearch")
    ap.add_argument("--keep-enabled", action="store_true", help="leave the rules enabled after the test")
    ap.add_argument("--wait", type=int, default=600, help="seconds to wait for the rules' first run")
    args = ap.parse_args()
    password = os.environ["ELASTIC_PASSWORD"]
    es, kb = Http(args.es, password), Http(args.kibana, password, kibana=True)
    run = uuid.uuid4().hex[:8]
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    ensure_template(es)
    converted = sigma_rules()
    docs, plan = [], []
    for rule, query, fields in converted:
        cases = splunk_tests.rule_events(rule, ROOT / "tests" / "sigma" / "fixtures")
        if not any(e for _, e, _ in cases):
            fail(f"{rule.title}: no matching test event could be made")
        for i, (cname, expected, ev) in enumerate(cases):
            case = f"{run}-{rule.id}-{i}"
            docs.append(ecs_event(ev, fields, rule.logsource.category, case, stamp))
            plan.append((rule, query, case, cname, expected))
    bulk(es, docs)
    print(f"{len(docs)} test events indexed into {DATA_STREAM} (run {run})")

    # 1. Each rule's query, as the detection engine runs it, agrees with the Sigma rule on every event.
    checked, wrong = 0, {}
    for rule, query, _ in converted:
        mine = [p for p in plan if p[0] is rule]
        body = {"size": 1000, "_source": ["labels.aad_case"], "query": {"bool": {
            "must": [{"query_string": {"query": query, "analyze_wildcard": True}}],
            "filter": [{"prefix": {"labels.aad_case": f"{run}-{rule.id}-"}}]}}}
        try:
            res = es.call("POST", "/" + ",".join(INDEX) + "/_search?ignore_unavailable=true&allow_no_indices=true", body)
        except RuntimeError as e:
            fail(f"{rule.title}: query fails in Elasticsearch: {e}")
            continue
        found = {h["_source"]["labels"]["aad_case"] for h in res["hits"]["hits"]}
        for _, _, case, cname, expected in mine:
            checked += 1
            if (case in found) != expected:
                wrong.setdefault(rule.title, []).append(cname)
                fail(f"{rule.title}: event {cname!r} should {'match' if expected else 'not match'}, "
                     f"Elasticsearch {'matched' if case in found else 'did not'}")
    print(f"lucene queries: {len(converted)} rules, {checked} events compared with the Sigma rule, "
          f"{len(wrong)} rules disagree")

    if args.skip_kibana:
        return finish()

    # 2. One import, every rule accepted.
    data = args.ndjson.read_bytes() if args.ndjson else build_ndjson(converted)
    boundary = uuid.uuid4().hex
    form = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"rules.ndjson\"\r\n"
            f"Content-Type: application/ndjson\r\n\r\n").encode() + data + f"\r\n--{boundary}--\r\n".encode()
    res = kb.call("POST", "/api/detection_engine/rules/_import?overwrite=true", raw=form,
                  ctype=f"multipart/form-data; boundary={boundary}")
    for err in res.get("errors", []):
        fail(f"import: rule {err.get('rule_id')}: {err.get('error', {}).get('message')}")
    imported = [json.loads(line) for line in data.decode().splitlines() if line.strip()]
    rule_ids = [r["rule_id"] for r in imported]
    print(f"import: {res.get('rules_count')} rules, {res.get('success_count')} imported, {len(res.get('errors', []))} errors")

    # Events for the correlations (ES|QL rules) and the indicator match rule, written before the rules run.
    extra_docs, extra_expect = correlation_events(imported, run, stamp)
    iocs = ROOT / "generated" / "elastic_ndjson" / "agentic-attack-indicators.ndjson"
    tm = [r for r in imported if r.get("type") == "threat_match"]
    if tm and iocs.exists():
        res = es.call("POST", f"/{tm[0]['threat_index'][0]}/_bulk?refresh=true", raw=iocs.read_bytes(),
                      ctype="application/x-ndjson")
        if res.get("errors"):
            fail(f"indicator bulk: {[it['create'].get('error') for it in res['items'] if 'error' in it['create']][:3]}")
        docs_in = [json.loads(line) for line in iocs.read_text(encoding="utf-8").splitlines()[1::2]]
        ip = next(d["threat.indicator.ip"] for d in docs_in if d.get("threat.indicator.type") == "ipv4-addr")
        print(f"indicators: {len(docs_in)} loaded into {tm[0]['threat_index'][0]}, test event to {ip}")
        extra_docs.append({"@timestamp": stamp, "event.ingested": stamp, "event.category": "network",
                           "labels.aad_case": f"{run}-ioc", "source.ip": "10.20.30.40", "destination.ip": ip})
        extra_expect[tm[0]["rule_id"]] = tm[0]["name"]
    bulk(es, extra_docs)
    print(f"{len(extra_docs)} events for {len(extra_expect)} correlation and indicator rules")

    # 3. Enable them, wait for every first run, and check the run and the alerts.
    ids = []
    for rid in rule_ids:
        try:
            ids.append(kb.call("GET", "/api/detection_engine/rules?rule_id=" + urllib.parse.quote(rid))["id"])
        except RuntimeError:
            pass
    since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 5))
    kb.call("POST", "/api/detection_engine/rules/_bulk_action", {"action": "enable", "ids": ids})
    status, deadline = {}, time.time() + args.wait
    while time.time() < deadline:
        status = {}
        for rid in rule_ids:
            try:
                r = kb.call("GET", "/api/detection_engine/rules?rule_id=" + urllib.parse.quote(rid))
            except RuntimeError:
                continue
            last = (r.get("execution_summary") or {}).get("last_execution") or {}
            if last.get("date", "") >= since:
                status[rid] = (r["name"], last.get("status"), last.get("message", ""))
        if len(status) >= len(ids):
            break
        time.sleep(10)
    print(f"rule runs: {len(status)} of {len(ids)} rules ran")
    # Kibana keeps the ATT&CK mapping of every rule as imported: same techniques, none outside the pinned release.
    def techniques(threat):
        return sorted({t["id"] for th in threat or [] for t in th.get("technique", [])} |
                      {s["id"] for th in threat or [] for t in th.get("technique", []) for s in t.get("subtechnique", [])})
    mapped = 0
    for r in imported:
        try:
            stored = kb.call("GET", "/api/detection_engine/rules?rule_id=" + urllib.parse.quote(r["rule_id"]))
        except RuntimeError:
            continue
        want, got = techniques(r.get("threat")), techniques(stored.get("threat"))
        if not got:
            fail(f"{r['name']}: no ATT&CK technique in Kibana")
        elif got != want or attack.problems(got):
            fail(f"{r['name']}: Kibana has techniques {got}, the import has {want} {attack.problems(got)}")
        else:
            mapped += 1
    print(f"att&ck: {mapped} of {len(imported)} rules keep their techniques in Kibana")
    for rid in rule_ids:
        if rid not in status:
            fail(f"rule {rid}: no run within {args.wait}s")
        elif status[rid][1] not in ("succeeded", "partial failure"):
            fail(f"{status[rid][0]}: run {status[rid][1]}: {status[rid][2][:300]}")
    alerts = es.call("POST", "/.alerts-security.alerts-default/_search?ignore_unavailable=true", {
        "size": 0, "query": {"range": {"@timestamp": {"gte": since}}},
        "aggs": {"r": {"terms": {"field": "kibana.alert.rule.rule_id", "size": 1000}}}})
    fired = {b["key"]: b["doc_count"] for b in alerts.get("aggregations", {}).get("r", {}).get("buckets", [])}
    should = {str(r.id): r.title for r, _, _ in converted
              if any(p[4] for p in plan if p[0] is r) and r.title not in wrong}
    should = {rid: title for rid, title in should.items() if rid in rule_ids}  # base rules of correlations are not imported
    should.update(extra_expect)
    for rid, title in sorted(should.items(), key=lambda x: x[1]):
        if rid not in fired:
            fail(f"{title}: no alert, though its test events match in Elasticsearch")
    print(f"alerts: {sum(fired.values())} alerts from {len(fired)} rules")
    if not args.keep_enabled:
        kb.call("POST", "/api/detection_engine/rules/_bulk_action", {"action": "disable", "ids": ids})
    return finish()


def finish():
    print(f"{len(failures)} failures" if failures else "PASS")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
