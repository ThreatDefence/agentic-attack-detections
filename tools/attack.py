#!/usr/bin/env python3
"""The MITRE ATT&CK release every builder checks against, pinned in tools/attack-enterprise.json.

    python3 tools/attack.py                            # print the pinned version and its size
    python3 tools/attack.py --update enterprise-attack.json
        # rewrite tools/attack-enterprise.json from a STIX bundle downloaded from
        # https://github.com/mitre-attack/attack-stix-data/tree/master/enterprise-attack

The builders import this module instead of downloading ATT&CK when they run, so a build needs no network and gives
the same output until someone bumps the pinned release on purpose.
"""
import argparse
import functools
import json
import re
import sys
from pathlib import Path

DATA = Path(__file__).resolve().parent / "attack-enterprise.json"
TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
URL = "https://attack.mitre.org"

# Microsoft Sentinel still spells the tactics of ATT&CK 15 and refuses others. ATT&CK 19 split Defense Evasion into
# Stealth (keeping TA0005) and Defense Impairment (TA0112); Sentinel files both under DefenseEvasion.
SENTINEL_TACTIC = {"stealth": "DefenseEvasion", "defense-impairment": "DefenseEvasion"}


@functools.lru_cache(maxsize=None)
def load():
    return json.loads(DATA.read_text(encoding="utf-8"))


def version():
    return load()["version"]


def major():
    return version().split(".")[0]


def techniques():
    return load()["techniques"]


def tactics():
    """TA0001 -> {name, shortname}"""
    return load()["tactics"]


def tactic_by_shortname():
    return {v["shortname"]: (k, v["name"]) for k, v in tactics().items()}


def name(tid):
    """Full display name: 'Active Scanning: Vulnerability Scanning'."""
    t = techniques()[tid]
    return f"{t['parent']}: {t['name']}" if "parent" in t else t["name"]


def problems(ids):
    """[(id, why)] for each id that is not a technique in the pinned release."""
    out = []
    for tid in sorted(set(ids)):
        if tid in techniques():
            continue
        retired = load()["retired"]
        if tid in retired:
            new = retired[tid]
            out.append((tid, f"retired in ATT&CK {version()}" + (f", use {new} ({name(new)})" if new else "")))
        else:
            out.append((tid, f"not a technique in ATT&CK {version()}"))
    return out


def tactic_of(tid, preferred=()):
    """The tactic shortnames to show a technique under: the preferred ones it belongs to, else all of its own."""
    own = techniques()[tid]["tactics"]
    chosen = [t for t in own if t in set(preferred)]
    return chosen or own


def sentinel_tactic(shortname):
    if shortname in SENTINEL_TACTIC:
        return SENTINEL_TACTIC[shortname]
    return "".join(w.capitalize() for w in shortname.split("-")).replace("And", "And")


def suricata_metadata(pairs):
    """metadata entries in the form the Emerging Threats rules use, one group per (tactic, technique)."""
    by_short = tactic_by_shortname()
    out = []
    for tac, tid in pairs:
        ta, ta_name = by_short[tac]
        out += [f"mitre_tactic_id {ta}", f"mitre_tactic_name {ta_name.replace(' ', '_')}",
                f"mitre_technique_id {tid}", f"mitre_technique_name {techniques()[tid]['name'].replace(' ', '_')}"]
    return out


def elastic_threat(ids, preferred=()):
    """Kibana's threat field: one entry per tactic, its techniques, and sub-techniques under their parent."""
    by_short = tactic_by_shortname()
    by_tactic = {}
    for tid in sorted(set(ids)):
        if tid not in techniques():
            continue
        for tac in tactic_of(tid, preferred):
            by_tactic.setdefault(tac, set()).add(tid)
    out = []
    for tac in sorted(by_tactic, key=lambda s: by_short[s][0]):
        ta, ta_name = by_short[tac]
        parents = {}
        for tid in sorted(by_tactic[tac]):
            parent = tid.split(".")[0]
            p = parents.setdefault(parent, {"id": parent, "name": techniques()[parent]["name"],
                                            "reference": f"{URL}/techniques/{parent}/"})
            if "." in tid:
                p.setdefault("subtechnique", []).append({
                    "id": tid, "name": techniques()[tid]["name"],
                    "reference": f"{URL}/techniques/{tid.replace('.', '/')}/"})
        out.append({"framework": "MITRE ATT&CK",
                    "tactic": {"id": ta, "name": ta_name, "reference": f"{URL}/tactics/{ta}/"},
                    "technique": list(parents.values())})
    return out


def update(bundle):
    d = json.loads(Path(bundle).read_text(encoding="utf-8"))
    coll = next(o for o in d["objects"] if o["type"] == "x-mitre-collection")
    ids = {}
    for o in d["objects"]:
        ext = [r["external_id"] for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"]
        if ext:
            ids[o["id"]] = ext[0]
    tac, tech, retired = {}, {}, {}
    for o in d["objects"]:
        i = ids.get(o["id"])
        if not i:
            continue
        gone = o.get("revoked") or o.get("x_mitre_deprecated")
        if o["type"] == "x-mitre-tactic" and not gone:
            tac[i] = {"name": o["name"], "shortname": o["x_mitre_shortname"]}
        elif o["type"] == "attack-pattern":
            if gone:
                retired[i] = None
            else:
                tech[i] = {"name": o["name"], "tactics": sorted(
                    p["phase_name"] for p in o.get("kill_chain_phases", []) if p["kill_chain_name"] == "mitre-attack")}
    for o in d["objects"]:
        if o["type"] == "relationship" and o.get("relationship_type") == "revoked-by":
            s, t = ids.get(o["source_ref"]), ids.get(o["target_ref"])
            if s in retired and t in tech:
                retired[s] = t
    for k, v in tech.items():
        if "." in k:
            v["parent"] = tech[k.split(".")[0]]["name"]
    ver = coll["x_mitre_version"]
    out = {
        "version": ver,
        "source": f"https://github.com/mitre-attack/attack-stix-data/blob/master/enterprise-attack/enterprise-attack-{ver}.json",
        "tactics": dict(sorted(tac.items())),
        "techniques": dict(sorted(tech.items())),
        "retired": dict(sorted(retired.items())),
    }
    DATA.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{DATA.name}: ATT&CK {ver}, {len(tac)} tactics, {len(tech)} techniques, {len(retired)} retired")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--update", metavar="BUNDLE", help="rewrite the pinned table from an enterprise-attack STIX bundle")
    args = ap.parse_args()
    if args.update:
        update(args.update)
        return
    print(f"ATT&CK {version()}: {len(tactics())} tactics, {len(techniques())} techniques")


if __name__ == "__main__":
    sys.exit(main())
