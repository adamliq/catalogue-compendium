#!/usr/bin/env python3
"""
Build data/mitre-attack-universe.json from the official MITRE ATT&CK
Enterprise STIX corpus (https://github.com/mitre/cti).

Unlike tools/fetch_mitre_platform.py (which scopes to one platform's
techniques plus the newer Analytics/Detection-Strategy data model), this
script extracts the *entire* non-deprecated, non-revoked Enterprise ATT&CK
technique set across every platform, rolled up to parent-technique level
(T1595.001/.002/... all fold into T1595), with each parent's full tactic
membership. It powers the "Heat Coverage" tab: a technique x tactic matrix
shaded by how many of this library's detections (summed across all twelve
catalogues, not just one platform) reference each technique.

The per-technique detection *counts* are intentionally NOT baked into this
file — they're computed client-side at page-load from the combined DATA
array, the same data every other view in the page already has in memory.
That keeps this file valid across every future batch without needing to be
regenerated each time a data/*.json file changes; only re-run this when
MITRE ships a new ATT&CK release.

Usage:
    python3 tools/fetch_mitre_universe.py
    python3 tools/fetch_mitre_universe.py --bundle /path/to/enterprise-attack.json
"""
import argparse
import json
import pathlib
import sys
import urllib.request
from datetime import date

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_BUNDLE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# Kill-chain display order. Includes both "Stealth" (TA0005's current name)
# and "Defense Impairment" (TA0112) as separate, real, current tactics — see
# tools/fetch_mitre_platform.py for the same back-compat note re: the older
# "Defense Evasion" name some tooling/docs still use for TA0005.
TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Stealth", "Defense Impairment", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact",
]


def load_bundle(bundle_path):
    if bundle_path:
        return json.loads(pathlib.Path(bundle_path).read_text(encoding="utf-8"))
    print(f"Downloading {DEFAULT_BUNDLE_URL} ...", file=sys.stderr)
    with urllib.request.urlopen(DEFAULT_BUNDLE_URL, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8"))


def external_ref(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id"), ref.get("url")
    return None, None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bundle", help="Path to a local enterprise-attack.json (skips the download)")
    ap.add_argument("--output", default=str(ROOT / "data" / "mitre-attack-universe.json"))
    args = ap.parse_args()

    output = pathlib.Path(args.output)
    bundle = load_bundle(args.bundle)
    objs = bundle["objects"]

    attack_spec_version = next((o["x_mitre_attack_spec_version"] for o in objs if o.get("x_mitre_attack_spec_version")), None)

    tactics = [o for o in objs if o["type"] == "x-mitre-tactic"]
    tactic_by_shortname = {}
    tactic_id_by_name = {}
    for t in tactics:
        tid, _ = external_ref(t)
        tactic_by_shortname[t["x_mitre_shortname"]] = t["name"]
        tactic_id_by_name[t["name"]] = tid

    def tech_tactic_names(t):
        out = []
        for kcp in t.get("kill_chain_phases", []):
            if kcp.get("kill_chain_name") == "mitre-attack":
                out.append(tactic_by_shortname.get(kcp["phase_name"], kcp["phase_name"]))
        return out

    techniques = [
        o for o in objs
        if o["type"] == "attack-pattern" and not o.get("revoked") and not o.get("x_mitre_deprecated")
    ]

    # Roll every technique/sub-technique up to its parent (base) ATT&CK ID.
    parents = {}  # base_id -> {name, tactic_names: set, sub_ids: set}
    for t in techniques:
        full_id, _ = external_ref(t)
        if not full_id:
            continue
        base_id = full_id.split(".")[0]
        entry = parents.setdefault(base_id, {"name": None, "tactic_names": set(), "sub_ids": set()})
        entry["tactic_names"].update(tech_tactic_names(t))
        if "." not in full_id:
            entry["name"] = t.get("name")
        else:
            entry["sub_ids"].add(full_id)

    missing_name = [b for b, e in parents.items() if not e["name"]]
    if missing_name:
        print(f"Warning: {len(missing_name)} base technique(s) have no parent-level STIX object "
              f"(only sub-techniques were found): {sorted(missing_name)}", file=sys.stderr)

    techniques_out = []
    for base_id, entry in parents.items():
        if not entry["name"]:
            continue  # skip anything we can't confidently name
        tactic_ids = sorted(
            {tactic_id_by_name.get(n) for n in entry["tactic_names"] if tactic_id_by_name.get(n)}
        )
        techniques_out.append({
            "id": base_id,
            "name": entry["name"],
            "tactics": tactic_ids,
            "sub_technique_count": len(entry["sub_ids"]),
        })
    techniques_out.sort(key=lambda t: t["id"])

    tactics_out = [
        {"id": tactic_id_by_name[name], "name": name}
        for name in TACTIC_ORDER if name in tactic_id_by_name
    ]

    tactic_counts = {}
    for t in techniques_out:
        for tid in t["tactics"]:
            tactic_counts[tid] = tactic_counts.get(tid, 0) + 1

    output_data = {
        "metadata": {
            "title": "MITRE ATT&CK Enterprise - Full Technique Universe",
            "description": (
                "Every non-deprecated, non-revoked Enterprise ATT&CK technique (all platforms), "
                "rolled up to parent-technique level, with full tactic membership. Loaded by the "
                "Threat Detection Library app's Heat Coverage tab; per-technique detection counts "
                "are computed client-side from the combined detection set, not stored here."
            ),
            "source": "https://github.com/mitre/cti (enterprise-attack/enterprise-attack.json)",
            "attack_version_reference": "https://attack.mitre.org/resources/updates/",
            "attack_spec_version": attack_spec_version,
            "retrieved": str(date.today()),
            "technique_count": len(techniques_out),
            "tactic_breakdown": {tid: tactic_counts.get(tid, 0) for tid in [t["id"] for t in tactics_out]},
        },
        "tactics": tactics_out,
        "techniques": techniques_out,
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(output_data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {output.relative_to(ROOT)}: {len(techniques_out)} parent techniques across {len(tactics_out)} tactics")


if __name__ == "__main__":
    main()
