#!/usr/bin/env python3
"""Build the Elastic NDJSON import: every rule, for one Kibana Security space.

    python3 tools/build_elastic.py                  # write generated/elastic_ndjson/agentic-attack-detections.ndjson
    python3 tools/build_elastic.py --check         # rebuild in memory, fail if the committed file differs

Reads:
    frameworks/*/sigma/, behaviors/sigma/     every Sigma rule, converted to Lucene on ECS field names
    frameworks/artex/elastic/rules/           the hand-written ARTEX rules, read as Kibana rule objects

One NDJSON line per rule, each disabled, carrying its severity, risk score, ATT&CK techniques, references
and the file it came from. The index patterns are one setting: INDEX below, ECS defaults.

Import: Security > Rules > Import, or one call to POST /api/detection_engine/rules/_import with
overwrite=true. Output is deterministic: the same commit gives the same bytes.
"""
import argparse
import copy
import json
import sys
import tomllib
from pathlib import Path

from sigma.backends.elasticsearch.elasticsearch_lucene import LuceneBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from convert import SIGMA_DIRS, convert_one, ecs, rel_of  # noqa: E402

NAME = "agentic-attack-detections"
OUT = ROOT / "generated" / "elastic_ndjson" / f"{NAME}.ndjson"
REPO = "https://github.com/ThreatDefence/agentic-attack-detections"

# The one place the data lands: ECS defaults, plus the beats' own indices.
INDEX = ["logs-*", "filebeat-*", "winlogbeat-*", "packetbeat-*"]

# Kibana's two fields for a Sigma level: the label it sorts by, and its default risk score.
LEVEL = {"informational": ("low", 21), "low": ("low", 21), "medium": ("moderate", 47),
         "high": ("high", 73), "critical": ("critical", 99)}


def link(path):
    return f"{REPO}/blob/main/{path.relative_to(ROOT).as_posix()}"


def from_sigma():
    """Every Sigma rule, on the ECS pipeline convert.py already uses for generated/elastic_lucene/."""
    plist = [("ecs", ecs()), ("raw fields", None)]
    threat = LuceneBackend()
    files = sorted(p for d in SIGMA_DIRS for p in d.rglob("*.yml"))
    for rule in SigmaCollection.load_ruleset([str(p) for p in files]).rules:
        if isinstance(rule, SigmaCorrelationRule):
            continue
        path = Path(str(rule.source.path))
        for _, pipe in plist:
            try:
                out = convert_one(LuceneBackend, pipe, copy.deepcopy(SigmaCollection([rule])))
            except Exception:  # noqa: BLE001 — the next pipeline may map what this one could not
                continue
            if out:
                break
        else:
            print(f"skip (no Elastic mapping): {rel_of(path)} {rule.title}")
            continue
        severity, risk = LEVEL.get(rule.level, ("medium", 47))
        yield {
            "rule_id": str(rule.id),
            "name": rule.title,
            "description": (rule.description or rule.title).strip(),
            "severity": severity,
            "risk_score": risk,
            "type": "query",
            "language": "lucene",
            "query": out[0],
            "index": INDEX,
            "enabled": False,
            "author": ", ".join(rule.author or ["ThreatDefence"]),
            "references": list(rule.references or []),
            "false_positives": list(rule.falsepositives or []),
            "threat": list(threat.finalize_output_threat_model(rule.tags)),
            "from": "now-9m",
            "interval": "5m",
            "max_signals": 100,
            "timestamp_override": "event.ingested",
            "note": link(path),
        }


def from_toml():
    """The hand-written ARTEX rules are already Kibana rule objects, one file each."""
    for path in sorted(ROOT.glob("frameworks/*/elastic/rules/*.toml")):
        rule = tomllib.loads(path.read_text(encoding="utf-8"))["rule"]
        rule.update(enabled=False, note=link(path))
        rule.setdefault("index", INDEX)
        rule.setdefault("from", "now-9m")
        rule.setdefault("interval", "5m")
        rule.setdefault("max_signals", 100)
        yield rule


def build():
    rules = sorted([*from_sigma(), *from_toml()], key=lambda r: r["rule_id"])
    rules = [{k: v for k, v in r.items() if k != "threat" or v} for r in rules]
    ids = [r["rule_id"] for r in rules]
    if len(ids) != len(set(ids)):
        raise SystemExit("two rules share a rule_id; Kibana import would overwrite one with the other")
    return "".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in rules).encode("utf-8")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail if the committed file differs from a fresh build")
    args = ap.parse_args()
    data = build()
    count = data.count(b"\n")
    if args.check:
        if not OUT.exists() or OUT.read_bytes() != data:
            raise SystemExit(f"{OUT.relative_to(ROOT)} is stale: run tools/build_elastic.py and commit it")
        print(f"elastic: {count} rules, committed")
        return
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(data)
    print(f"{OUT.relative_to(ROOT)}: {count} rules")


if __name__ == "__main__":
    main()
