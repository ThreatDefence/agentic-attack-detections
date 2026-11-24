#!/usr/bin/env python3
"""Build the ATT&CK coverage page and the ATT&CK Navigator layers.

    python3 tools/build_attack.py             # write docs/attack-coverage.md and generated/attack/
    python3 tools/build_attack.py --check     # rebuild in memory, fail if the committed files differ
    python3 tools/build_attack.py --strict    # also fail when a rule names no technique

Reads:
    frameworks/*/sigma/, behaviors/sigma/     attack.tNNNN and attack.<tactic> tags
    frameworks/*/sentinel/analytics/*.yaml    relevantTechniques and tactics
    frameworks/*/sentinel/hunting/*.kql       a `// ATT&CK:` line in the file header
    frameworks/*/suricata/*.rules             mitre_technique_id in metadata
    frameworks/*/yara/*.yar                   mitre_att in meta
    frameworks/*/zeek/                        a technique in a notice's comment

Techniques are checked against the list pySigma ships, so a typo or a retired technique fails here
rather than in the Navigator. Output is deterministic: the same commit gives the same bytes.
"""
import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml
from sigma.data.mitre_attack import mitre_attack_tactics, mitre_attack_techniques

ROOT = Path(__file__).resolve().parent.parent
MD = ROOT / "docs" / "attack-coverage.md"
LAYERS = ROOT / "generated" / "attack"
NAME = "agentic-attack-detections"
REPO = "https://github.com/ThreatDefence/agentic-attack-detections"

# The ATT&CK release the technique list below was checked against. Bump it with pySigma.
ATTACK_VERSION = "17"
TECHNIQUE = re.compile(r"T\d{4}(?:\.\d{3})?", re.I)
# Sentinel writes CredentialAccess, Sigma writes credential-access: compare on letters alone.
TACTIC_OF_NAME = {re.sub(r"[^a-z]", "", name): tid for tid, name in mitre_attack_tactics.items()}
def tactic_id(name):
    return TACTIC_OF_NAME.get(re.sub(r"[^a-z]", "", str(name).lower()))


def framework_of(path):
    parts = path.relative_to(ROOT).parts
    return parts[1] if parts[0] == "frameworks" else parts[0]


def entry(framework, kind, name, path, techniques, tactics=()):
    return {
        "framework": framework,
        "kind": kind,
        "rule": name,
        "path": path,
        "techniques": {t.upper() for t in techniques},
        "tactics": {t.upper() for t in tactics},
    }


def from_sigma():
    for path in sorted(ROOT.glob("frameworks/*/sigma/**/*.yml")) + sorted(ROOT.glob("behaviors/sigma/**/*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        tags = [str(t).lower() for t in doc.get("tags") or []]
        techniques = [t.split(".", 1)[1] for t in tags if t.startswith("attack.t")]
        tactics = [t.split(".", 1)[1] for t in tags
                   if t.startswith("attack.") and not t.startswith("attack.t")]
        yield entry(framework_of(path), "sigma", doc.get("title") or path.stem, path, techniques,
                    [tactic_id(t) for t in tactics if tactic_id(t)])


def from_sentinel():
    for path in sorted(ROOT.glob("frameworks/*/sentinel/analytics/*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        tactics = [tactic_id(t) for t in doc.get("tactics") or []]
        yield entry(framework_of(path), "sentinel", doc.get("name") or path.stem, path,
                    doc.get("relevantTechniques") or [], [t for t in tactics if t])


def from_hunting():
    """A `//  ATT&CK: T1059 T1105` line in the header, the format the hunts use from here on."""
    for path in sorted(ROOT.glob("frameworks/*/sentinel/hunting/*.kql")):
        head = "\n".join(path.read_text(encoding="utf-8").splitlines()[:8])
        line = next((l for l in head.splitlines() if "ATT&CK" in l.upper()), "")
        yield entry(framework_of(path), "hunt", path.stem, path, TECHNIQUE.findall(line))


def from_suricata():
    for path in sorted(ROOT.glob("frameworks/*/suricata/*.rules")):
        text = path.read_text(encoding="utf-8")
        for alert in re.findall(r"^alert .*?\(\s*msg:\s*\"([^\"]*)\".*?\)\s*$", text, re.M | re.S):
            yield entry(framework_of(path), "suricata", alert, path, [])
        found = TECHNIQUE.findall(text)
        if found:
            yield entry(framework_of(path), "suricata", f"{path.name} metadata", path, found)


def from_yara():
    for path in sorted(ROOT.glob("frameworks/*/yara/*.yar")):
        text = path.read_text(encoding="utf-8")
        for name, meta in re.findall(r"rule\s+(\w+)\s*\{(.*?)\bcondition:", text, re.S):
            yield entry(framework_of(path), "yara", name, path, TECHNIQUE.findall(meta))


def from_zeek():
    for path in sorted(ROOT.glob("frameworks/*/zeek/**/*.zeek")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.lstrip().startswith("#") and "ATT&CK" in line.upper():
                yield entry(framework_of(path), "zeek", path.name, path, TECHNIQUE.findall(line))


SOURCES = (from_sigma, from_sentinel, from_hunting, from_suricata, from_yara, from_zeek)


def collect():
    """Every mapping, and the ids that are not in this ATT&CK release. Naming one is not fatal by
    default: the rule keeps its place in the layers, and the page and --strict name it."""
    entries = [e for source in SOURCES for e in source()]
    unknown = sorted({t for e in entries for t in e["techniques"] if t not in mitre_attack_techniques})
    return entries, unknown


def layer(title, entries):
    by_technique = defaultdict(list)
    for e in entries:
        for t in e["techniques"]:
            by_technique[t].append(e["rule"])
    most = max((len(v) for v in by_technique.values()), default=1)
    return {
        "name": title,
        "versions": {"attack": ATTACK_VERSION, "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"{len(entries)} rules from {REPO}",
        "techniques": [{"techniqueID": t, "score": len(v), "comment": "; ".join(sorted(set(v))),
                        "enabled": True, "showSubtechniques": True}
                       for t, v in sorted(by_technique.items())],
        "gradient": {"colors": ["#ffe9e9", "#dc2626"], "minValue": 0, "maxValue": most},
        "legendItems": [],
        "showTacticsRow": False,
        "selectTechniquesAcrossTactics": True,
        "hideDisabled": False,
    }


def coverage(entries, unknown):
    frameworks = sorted({e["framework"] for e in entries})
    mapped = [e for e in entries if e["techniques"]]
    out = ["# ATT&CK coverage", "",
           f"Generated by `tools/build_attack.py` against ATT&CK {ATTACK_VERSION}. "
           f"{len({t for e in entries for t in e['techniques']})} techniques across {len(mapped)} of "
           f"{len(entries)} rules. The Navigator layers are in [`generated/attack/`](../generated/attack).", "",
           "| Framework | Rules | With a technique | Techniques |",
           "|---|---|---|---|"]
    for fw in frameworks:
        mine = [e for e in entries if e["framework"] == fw]
        out.append(f"| {fw} | {len(mine)} | {sum(1 for e in mine if e['techniques'])} | "
                   f"{len({t for e in mine for t in e['techniques']})} |")
    for fw in frameworks:
        mine = [e for e in entries if e["framework"] == fw and e["techniques"]]
        if not mine:
            continue
        by_technique = defaultdict(list)
        for e in mine:
            for t in e["techniques"]:
                by_technique[t].append(f"{e['kind']}: {e['rule']}")
        out += ["", f"## {fw}", "", "| Technique | Name | Rules |", "|---|---|---|"]
        for t in sorted(by_technique):
            names = "; ".join(sorted(set(by_technique[t])))
            out.append(f"| {t} | {mitre_attack_techniques.get(t, '')} | {names} |")
    if unknown:
        out += ["", f"## Not in ATT&CK {ATTACK_VERSION}", "",
                "These ids are named by a rule but are not techniques in this release. A retired or "
                "mistyped id covers nothing, so check each against attack.mitre.org:", ""]
        out += [f"- {t}: " + "; ".join(sorted({e["rule"] for e in entries if t in e["techniques"]}))
                for t in unknown]
    gaps = [e for e in entries if not e["techniques"]]
    if gaps:
        out += ["", "## Rules with no technique yet", ""]
        for kind in sorted({e["kind"] for e in gaps}):
            mine = [e for e in gaps if e["kind"] == kind]
            out.append(f"- {kind}: {len(mine)} of {sum(1 for e in entries if e['kind'] == kind)}")
    return "\n".join(out) + "\n"


def build():
    entries, unknown = collect()
    files = {MD: coverage(entries, unknown)}
    files.update({LAYERS / f"{fw}.json": layer(fw, [e for e in entries if e["framework"] == fw])
                  for fw in sorted({e["framework"] for e in entries})})
    files[LAYERS / f"{NAME}.json"] = layer("All frameworks", entries)
    return {p: (text if isinstance(text, str) else json.dumps(text, indent=1, sort_keys=True)) + "\n"
            for p, text in files.items()}, entries, unknown


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail if the committed files differ from a fresh build")
    ap.add_argument("--strict", action="store_true", help="also fail when a rule names no technique")
    args = ap.parse_args()
    files, entries, unknown = build()
    gaps = [e for e in entries if not e["techniques"]]
    for path, text in files.items():
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                raise SystemExit(f"{path.relative_to(ROOT)} is stale: run tools/build_attack.py and commit it")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
    mapped = len(entries) - len(gaps)
    print(f"attack: {mapped} of {len(entries)} rules mapped, {len(files)} files")
    for t in unknown:
        print(f"  not in ATT&CK {ATTACK_VERSION}: {t}")
    for kind in sorted({e["kind"] for e in gaps}):
        print(f"  no technique yet: {sum(1 for e in gaps if e['kind'] == kind)} {kind}")
    if args.strict and (gaps or unknown):
        raise SystemExit(f"{len(gaps)} rules name no technique, {len(unknown)} name one outside ATT&CK {ATTACK_VERSION}")


if __name__ == "__main__":
    sys.exit(main())
