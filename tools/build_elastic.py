#!/usr/bin/env python3
"""Build the Elastic Security imports: every rule in one NDJSON file, and the indicators for the indicator match rule.

    python3 tools/build_elastic.py            # write generated/elastic_ndjson/
    python3 tools/build_elastic.py --check    # rebuild in memory, fail if the committed files differ

Reads:
    frameworks/*/sigma/, behaviors/sigma/     every Sigma rule, converted to Lucene on ECS field names by the same
                                              pipeline as generated/elastic_lucene/ (tools/convert.py); correlation
                                              rules become threshold rules over their base rule's query
    frameworks/*/elastic/rules/*.toml         the hand-written ARTEX rules, which are Kibana rule objects already
    iocs/indicators.csv                       the indicators the plain lists in feeds/ carry (medium and high
                                              confidence, addresses past their review date left out)

Writes generated/elastic_ndjson/:
    agentic-attack-detections.ndjson          one rule per line for Security > Rules > Import, or one call to
                                              POST /api/detection_engine/rules/_import. Every rule is disabled and
                                              carries its severity, risk score, ATT&CK tactics and techniques,
                                              references and a link to its source file
    indicators-index.json                     the mapping for the index the indicator match rule reads (aad-indicators)
    indicators.ndjson                         the indicators as a _bulk request into that index

The data views are one setting, INDEX below, with ECS defaults. ATT&CK names come from the table below rather than a
download, so the output is the same bytes for the same commit, with or without network.
"""
import argparse
import copy
import json
import re
import sys
import tomllib
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import build_feeds  # noqa: E402
import convert  # noqa: E402
from sigma.collection import SigmaCollection  # noqa: E402
from sigma.correlations import SigmaCorrelationRule  # noqa: E402
from sigma.rule import SigmaRule  # noqa: E402

NAME = "agentic-attack-detections"
OUT = ROOT / "generated" / "elastic_ndjson"
RULES = OUT / f"{NAME}.ndjson"
IND_MAPPING = OUT / "indicators-index.json"
IND_BULK = OUT / "indicators.ndjson"
REPO = "https://github.com/ThreatDefence/agentic-attack-detections"
NS = uuid.UUID("2b6f0d4e-7c1a-5e8b-9f3d-a4c2e1b07d55")  # fixed namespace: stable ids for generated rules

# Where the events are: ECS defaults and the Beats' own indices. Change it here for every rule at once.
INDEX = ["logs-*", "filebeat-*", "winlogbeat-*", "packetbeat-*"]
INDICATOR_INDEX = "aad-indicators"
TAG = "Agentic Attack Detections"

# Sigma level -> Kibana severity and its default risk score. Kibana accepts low, medium, high and critical only.
LEVEL = {"informational": ("low", 21), "low": ("low", 21), "medium": ("medium", 47),
         "high": ("high", 73), "critical": ("critical", 99)}

# Enterprise ATT&CK 20.1: tactic slug as Sigma tags it -> id. 20 split Defense Evasion into Stealth (TA0005) and
# Defense Impairment (TA0112).
TACTICS = {"initial-access": "TA0001", "execution": "TA0002", "persistence": "TA0003", "privilege-escalation": "TA0004",
           "stealth": "TA0005", "credential-access": "TA0006", "discovery": "TA0007", "lateral-movement": "TA0008",
           "collection": "TA0009", "exfiltration": "TA0010", "command-and-control": "TA0011", "impact": "TA0040",
           "resource-development": "TA0042", "reconnaissance": "TA0043", "defense-impairment": "TA0112"}
# Technique -> (name, tactics), Enterprise ATT&CK 20.1. Add a technique here when a rule names a new one; the build
# fails until it is here, so a typo or a retired id does not reach Kibana.
TECHNIQUES = {
    "T1036": ("Masquerading", ["stealth"]),
    "T1036.005": ("Match Legitimate Resource Name or Location", ["stealth"]),
    "T1046": ("Network Service Discovery", ["discovery"]),
    "T1053": ("Scheduled Task/Job", ["execution", "persistence", "privilege-escalation"]),
    "T1053.003": ("Cron", ["execution", "persistence", "privilege-escalation"]),
    "T1053.005": ("Scheduled Task", ["execution", "persistence", "privilege-escalation"]),
    "T1056": ("Input Capture", ["collection", "credential-access"]),
    "T1057": ("Process Discovery", ["discovery"]),
    "T1059": ("Command and Scripting Interpreter", ["execution"]),
    "T1059.001": ("PowerShell", ["execution"]),
    "T1059.003": ("Windows Command Shell", ["execution"]),
    "T1059.004": ("Unix Shell", ["execution"]),
    "T1071": ("Application Layer Protocol", ["command-and-control"]),
    "T1071.001": ("Web Protocols", ["command-and-control"]),
    "T1071.004": ("DNS", ["command-and-control"]),
    "T1078": ("Valid Accounts", ["initial-access", "persistence", "privilege-escalation", "stealth"]),
    "T1078.004": ("Cloud Accounts", ["initial-access", "persistence", "privilege-escalation", "stealth"]),
    "T1082": ("System Information Discovery", ["discovery"]),
    "T1098": ("Account Manipulation", ["persistence", "privilege-escalation"]),
    "T1098.001": ("Additional Cloud Credentials", ["persistence", "privilege-escalation"]),
    "T1098.003": ("Additional Cloud Roles", ["persistence", "privilege-escalation"]),
    "T1102": ("Web Service", ["command-and-control"]),
    "T1105": ("Ingress Tool Transfer", ["command-and-control"]),
    "T1110": ("Brute Force", ["credential-access"]),
    "T1110.003": ("Password Spraying", ["credential-access"]),
    "T1136": ("Create Account", ["persistence"]),
    "T1136.003": ("Cloud Account", ["persistence"]),
    "T1190": ("Exploit Public-Facing Application", ["initial-access"]),
    "T1505": ("Server Software Component", ["persistence"]),
    "T1505.001": ("SQL Stored Procedures", ["persistence"]),
    "T1505.003": ("Web Shell", ["persistence"]),
    "T1518": ("Software Discovery", ["discovery"]),
    "T1518.001": ("Security Software Discovery", ["discovery"]),
    "T1525": ("Implant Internal Image", ["persistence"]),
    "T1543": ("Create or Modify System Process", ["persistence", "privilege-escalation"]),
    "T1543.001": ("Launch Agent", ["persistence", "privilege-escalation"]),
    "T1543.002": ("Systemd Service", ["persistence", "privilege-escalation"]),
    "T1547": ("Boot or Logon Autostart Execution", ["persistence", "privilege-escalation"]),
    "T1547.001": ("Registry Run Keys / Startup Folder", ["persistence", "privilege-escalation"]),
    "T1552": ("Unsecured Credentials", ["credential-access"]),
    "T1567": ("Exfiltration Over Web Service", ["exfiltration"]),
    "T1572": ("Protocol Tunneling", ["command-and-control"]),
    "T1574": ("Hijack Execution Flow", ["execution", "stealth"]),
    "T1574.001": ("DLL", ["execution", "stealth"]),
    "T1580": ("Cloud Infrastructure Discovery", ["discovery"]),
    "T1590": ("Gather Victim Network Information", ["reconnaissance"]),
    "T1590.002": ("DNS", ["reconnaissance"]),
    "T1594": ("Search Victim-Owned Websites", ["reconnaissance"]),
    "T1595": ("Active Scanning", ["reconnaissance"]),
    "T1595.002": ("Vulnerability Scanning", ["reconnaissance"]),
    "T1606": ("Forge Web Credentials", ["credential-access"]),
    "T1606.001": ("Web Cookies", ["credential-access"]),
    "T1611": ("Escape to Host", ["privilege-escalation"]),
}

# Indicator type in iocs/indicators.csv -> (ECS threat.indicator.type, field under threat.indicator). User agents
# have no ECS indicator field, so they go in user_agent.original under threat.indicator.
INDICATOR_TYPES = {"ipv4": ("ipv4-addr", "ip"), "ipv6": ("ipv6-addr", "ip"), "domain": ("domain-name", "url.domain"),
                   "url": ("url", "url.full"), "sha256": ("file", "file.hash.sha256"), "md5": ("file", "file.hash.md5"),
                   "user_agent": ("software", "user_agent.original")}
# Event field -> indicator field. Any one pair matching raises an alert.
THREAT_MAPPING = [("source.ip", "ip"), ("destination.ip", "ip"), ("dns.question.name", "url.domain"),
                  ("url.domain", "url.domain"), ("destination.domain", "url.domain"), ("url.full", "url.full"),
                  ("url.original", "url.full"), ("file.hash.sha256", "file.hash.sha256"),
                  ("file.hash.md5", "file.hash.md5"), ("user_agent.original", "user_agent.original")]

errors = []


def rel(path):
    return Path(path).resolve().relative_to(ROOT).as_posix()


def framework_of(path):
    parts = Path(rel(path)).parts
    return parts[1] if parts[0] == "frameworks" else parts[0]


def link(path):
    return f"{REPO}/blob/main/{rel(path)}"


def title(slug):
    return " ".join(w if w == "and" else w.capitalize() for w in slug.split("-"))


def threat(tags, src):
    """Kibana's threat block from attack.* tags: each technique under the rule's tactics it belongs to."""
    names = [t.name.lower() for t in tags if t.namespace == "attack"]
    tactics = [t for t in names if t in TACTICS]
    techniques = sorted({t.upper() for t in names if re.fullmatch(r"t\d{4}(\.\d{3})?", t)})
    for t in names:
        if t not in TACTICS and not re.fullmatch(r"t\d{4}(\.\d{3})?", t) and not re.fullmatch(r"[gs]\d{4}", t):
            errors.append(f"{src}: attack.{t} is not an ATT&CK 20.1 tactic")
    out = {}
    for t in techniques:
        if t not in TECHNIQUES or t[:5] not in TECHNIQUES:
            errors.append(f"{src}: technique {t} is not in TECHNIQUES in tools/build_elastic.py; add it with its tactics")
            continue
        home = [ta for ta in tactics if ta in TECHNIQUES[t][1]] or TECHNIQUES[t][1][:1]
        for ta in home:
            parent = t[:5]
            entry = out.setdefault(ta, {}).setdefault(parent, {
                "id": parent, "name": TECHNIQUES[parent][0], "reference": f"https://attack.mitre.org/techniques/{parent}/"})
            if "." in t:
                entry.setdefault("subtechnique", []).append({
                    "id": t, "name": TECHNIQUES[t][0], "reference": f"https://attack.mitre.org/techniques/{t.replace('.', '/')}/"})
    for ta in tactics:
        out.setdefault(ta, {})
    return [{"framework": "MITRE ATT&CK",
             "tactic": {"id": TACTICS[ta], "name": title(ta), "reference": f"https://attack.mitre.org/tactics/{TACTICS[ta]}/"},
             "technique": [out[ta][p] for p in sorted(out[ta])]}
            for ta in sorted(out, key=lambda x: TACTICS[x])]


def lucene(rule):
    """The rule's Lucene query on the elastic_lucene pipelines, ECS first; None when neither maps it."""
    cls, plist = convert.pipelines()["elastic_lucene"]
    for _, pipe in plist:
        try:
            out = convert.convert_one(cls, pipe, SigmaCollection([copy.deepcopy(rule)]))
        except Exception:  # noqa: BLE001 - the next pipeline may map what this one could not
            continue
        if out:
            return out[0]
    return None


def mapped_field(field, logsource):
    """The field name the pipeline gives a Sigma field in this log source, for a correlation's group-by."""
    ls = {k: v for k, v in (("category", logsource.category), ("product", logsource.product),
                            ("service", logsource.service)) if v}
    rule = SigmaRule.from_dict({"title": "field", "logsource": ls,
                                "detection": {"s": {field: "aad"}, "condition": "s"}})
    q = lucene(rule)
    return q.split(":", 1)[0].removesuffix(".caseless") if q else field


def base(rule, src):
    """Fields every rule carries."""
    severity, risk = LEVEL[rule.level.name.lower() if rule.level else "medium"]
    author = rule.author or "ThreatDefence"
    out = {
        "rule_id": str(rule.id),
        "name": rule.title,
        "description": (rule.description or rule.title).strip(),
        "severity": severity,
        "risk_score": risk,
        "author": [a.strip() for a in author.split(",") if a.strip()],
        "license": "MIT",
        "references": list(rule.references or []),
        "false_positives": list(rule.falsepositives or []),
        "tags": [TAG, framework_of(src), "Sigma"],
        "note": f"Source: [{rel(src)}]({link(src)})",
        "index": INDEX,
        "enabled": False,
        "from": "now-9m",
        "interval": "5m",
        "max_signals": 100,
    }
    t = threat(rule.tags, rel(src))
    if t:
        out["threat"] = t
    return out


def duration(spec):
    m = re.fullmatch(r"(\d+)([smhd])", str(spec))
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def from_sigma():
    files = sorted(p for d in convert.SIGMA_DIRS for p in d.rglob("*.yml"))
    collection = SigmaCollection.load_ruleset([str(p) for p in files])
    by_id = {str(r.id): r for r in collection.rules}
    for rule in collection.rules:
        src = Path(str(rule.source.path))
        if isinstance(rule, SigmaCorrelationRule):
            yield from correlation(rule, src, by_id)
            continue
        # A base rule of a correlation converts to nothing in the collection (it only feeds the correlation), so
        # load it on its own: it is a detection in its own right, at its own level.
        q = lucene(SigmaRule.from_yaml(src.read_text(encoding="utf-8")))
        if not q:
            errors.append(f"{rel(src)}: no Elastic conversion")
            continue
        yield dict(base(rule, src), type="query", language="lucene", query=q)


def correlation(rule, src, by_id):
    """event_count and value_count correlations as Kibana threshold rules over the base rule's query."""
    corr_type = rule.type.name.lower()
    refs = [str(getattr(r, "reference", r)) for r in rule.rules]
    if corr_type not in ("event_count", "value_count") or len(refs) != 1:
        errors.append(f"{rel(src)}: {corr_type} correlation over {len(refs)} rules has no Elastic threshold form")
        return
    ref = refs[0]
    target = by_id.get(ref) or next((r for r in by_id.values() if getattr(r, "name", None) == ref), None)
    if target is None:
        errors.append(f"{rel(src)}: base rule {ref} not found")
        return
    tsrc = Path(str(target.source.path))
    q = lucene(SigmaRule.from_yaml(tsrc.read_text(encoding="utf-8")))
    if not q:
        errors.append(f"{rel(src)}: base rule {rel(tsrc)} has no Elastic conversion")
        return
    cond = rule.condition
    op = cond.op.name.lower()
    count = {"gte": cond.count, "gt": cond.count + 1}.get(op)
    if count is None:
        errors.append(f"{rel(src)}: condition {op} has no Elastic threshold form")
        return
    group = [mapped_field(f, target.logsource) for f in (rule.group_by or [])]
    threshold = {"field": group}
    if corr_type == "event_count":
        threshold["value"] = count
    else:
        threshold.update(value=1, cardinality=[{"field": mapped_field(str(cond.fieldref), target.logsource), "value": count}])
    window = duration(rule.timespan.spec if hasattr(rule.timespan, "spec") else rule.timespan)
    out = dict(base(rule, src), type="threshold", language="lucene", query=q, threshold=threshold)
    out.update({"from": f"now-{window}s", "interval": f"{min(window, 300)}s",
                "note": out["note"] + f"\n\nBase rule: [{rel(tsrc)}]({link(tsrc)})"})
    yield out


def from_toml():
    """The hand-written rules are Kibana rule objects already: add only what the import needs."""
    for path in sorted(ROOT.glob("frameworks/*/elastic/rules/*.toml")):
        rule = tomllib.loads(path.read_text(encoding="utf-8"))["rule"]
        rule["enabled"] = False
        rule.setdefault("note", f"Source: [{rel(path)}]({link(path)})")
        rule["tags"] = sorted(set(rule.get("tags", [])) | {TAG, framework_of(path)})
        if rule.get("language") != "esql":
            rule.setdefault("index", INDEX)
        rule.setdefault("from", "now-9m")
        rule.setdefault("interval", "5m")
        rule.setdefault("max_signals", 100)
        if rule.get("severity") not in {s for s, _ in LEVEL.values()}:
            errors.append(f"{rel(path)}: severity {rule.get('severity')!r} is not one Kibana accepts")
        yield rule


def indicators():
    """[(row, ECS type, indicator field)] for every indicator the plain lists in feeds/ carry."""
    out = []
    for r in build_feeds.load():
        if r["type"] not in INDICATOR_TYPES or r["confidence"] == "low" or not build_feeds.active_ip(r):
            continue
        if r["type"] == "ipv4" and "/" in r["value"]:
            continue  # a network: an ip field holds one address, and Suricata and the WAF rules cover the range
        out.append((r, *INDICATOR_TYPES[r["type"]]))
    return sorted(out, key=lambda x: (x[0]["type"], x[0]["value"]))


def indicator_rule():
    rows = indicators()
    count = {}
    for r, _, _ in rows:
        count[r["type"]] = count.get(r["type"], 0) + 1
    query = " or ".join(f"{field}:*" for field in dict.fromkeys(f for f, _ in THREAT_MAPPING))
    return {
        "rule_id": str(uuid.uuid5(NS, "indicator-match")),
        "name": "Agentic Attack Framework Indicator Match",
        "description": ("An event names an address, domain, URL, file hash or user agent from the agentic attack "
                        "framework indicators in iocs/indicators.csv (medium and high confidence, as in feeds/). "
                        f"Load them into the {INDICATOR_INDEX} index first: indicators-index.json and "
                        "indicators.ndjson from generated/elastic_ndjson/ or the release."),
        "severity": "high",
        "risk_score": 73,
        "author": ["ThreatDefence"],
        "license": "MIT",
        "references": [f"{REPO}/blob/main/iocs/indicators.csv"],
        "false_positives": ["Low-confidence rows are left out, but check the indicator's context in the alert: "
                            "an address can change hands after its review date"],
        "tags": [TAG, "indicators"],
        "note": (f"Source: [iocs/indicators.csv]({REPO}/blob/main/iocs/indicators.csv), "
                 + ", ".join(f"{n} {t}" for t, n in sorted(count.items())) + " at build time."),
        "type": "threat_match",
        "language": "kuery",
        "query": query,
        "index": INDEX,
        "threat_index": [INDICATOR_INDEX],
        "threat_language": "lucene",
        "threat_query": "*:*",
        "threat_indicator_path": "threat.indicator",
        "threat_mapping": [{"entries": [{"field": f, "type": "mapping", "value": f"threat.indicator.{v}"}]}
                           for f, v in THREAT_MAPPING],
        "enabled": False,
        "from": "now-9m",
        "interval": "5m",
        "max_signals": 100,
    }


def indicator_files():
    mapping = {"mappings": {"dynamic": "false", "properties": {
        "@timestamp": {"type": "date"},
        "event": {"properties": {k: {"type": "keyword"} for k in ("kind", "category", "type")}},
        "labels": {"properties": {"framework": {"type": "keyword"}}},
        "threat": {"properties": {"indicator": {"properties": {
            "type": {"type": "keyword"}, "ip": {"type": "ip"}, "confidence": {"type": "keyword"},
            "provider": {"type": "keyword"}, "reference": {"type": "keyword"}, "description": {"type": "text"},
            "first_seen": {"type": "date"},
            "url": {"properties": {"domain": {"type": "keyword"}, "full": {"type": "keyword"}}},
            "file": {"properties": {"hash": {"properties": {"sha256": {"type": "keyword"}, "md5": {"type": "keyword"}}}}},
            "user_agent": {"properties": {"original": {"type": "keyword"}}},
        }}}}}}}
    lines = []
    for r, ecs_type, field in indicators():
        ind = {"type": ecs_type, "confidence": r["confidence"].title(), "provider": r["source"],
               "description": r["context"]}
        if r.get("source_url"):
            ind["reference"] = r["source_url"]
        if r.get("reported"):
            ind["first_seen"] = r["reported"]
        node = ind
        parts = field.split(".")
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        node[parts[-1]] = r["value"]
        doc = {"@timestamp": r.get("reported") or "1970-01-01", "event": {"kind": "enrichment", "category": "threat",
               "type": "indicator"}, "labels": {"framework": r.get("framework", "")}, "threat": {"indicator": ind}}
        _id = str(uuid.uuid5(NS, f"{r['type']}:{r['value']}"))
        lines.append(json.dumps({"index": {"_index": INDICATOR_INDEX, "_id": _id}}) + "\n"
                     + json.dumps(doc, sort_keys=True, ensure_ascii=False) + "\n")
    return json.dumps(mapping, indent=1, sort_keys=True) + "\n", "".join(lines)


def build_all():
    errors.clear()
    rules = sorted([*from_sigma(), *from_toml(), indicator_rule()], key=lambda r: (r["name"], r["rule_id"]))
    ids = [r["rule_id"] for r in rules]
    for i in sorted({i for i in ids if ids.count(i) > 1}):
        errors.append(f"rule_id {i} is used twice; one Kibana import would overwrite the other")
    if errors:
        raise SystemExit("\n".join(errors))
    mapping, bulk = indicator_files()
    data = "".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in rules)
    return {RULES: data, IND_MAPPING: mapping, IND_BULK: bulk}, rules


def build():
    """The rules NDJSON as bytes (tests/elastic/run_tests.py imports it)."""
    return build_all()[0][RULES].encode("utf-8")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail if the committed files differ from a fresh build")
    args = ap.parse_args()
    files, rules = build_all()
    kinds = {}
    for r in rules:
        kinds[r["type"]] = kinds.get(r["type"], 0) + 1
    summary = f"{len(rules)} rules (" + ", ".join(f"{n} {t}" for t, n in sorted(kinds.items())) + \
              f"), {files[IND_BULK].count(chr(10)) // 2} indicators"
    if args.check:
        stale = [rel(p) for p, text in files.items() if not p.exists() or p.read_text(encoding="utf-8") != text]
        if stale:
            raise SystemExit(f"{', '.join(stale)} stale: run tools/build_elastic.py and commit generated/elastic_ndjson/")
        print(f"elastic import: {summary}, up to date")
        return
    OUT.mkdir(parents=True, exist_ok=True)
    for p, text in files.items():
        p.write_text(text, encoding="utf-8")
    print(f"{rel(OUT)}: {summary}")


if __name__ == "__main__":
    main()
