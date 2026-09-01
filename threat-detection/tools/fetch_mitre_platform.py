#!/usr/bin/env python3
"""
Build data/mitre-attack-<platform>.json from the official MITRE ATT&CK
Enterprise STIX corpus (https://github.com/mitre/cti).

For the given --platform (as it appears in MITRE's x_mitre_platforms, e.g.
"ESXi", "Windows", "Linux", "IaaS"), this extracts:

  - every non-deprecated, non-revoked technique/sub-technique scoped to that
    platform, its tactic(s), and whether it's covered by this repo's
    detection catalogues (matched on mitre_attack.techniques[].id across
    data/detections.json and data/aria-detections.json by default)
  - every official MITRE ATT&CK Detection Analytic (x-mitre-analytic)
    scoped to that platform, resolved to its parent Detection Strategy and
    the technique(s) that strategy detects

This is the newer MITRE "Analytics / Detection Strategy" data model
(x-mitre-analytic / x-mitre-detection-strategy STIX objects), separate from
and complementary to the classic technique/tactic/data-component model.

Usage:
    python3 tools/fetch_mitre_platform.py --platform ESXi
    python3 tools/fetch_mitre_platform.py --platform ESXi --bundle /path/to/enterprise-attack.json
"""
import argparse
import json
import pathlib
import sys
import urllib.request
from datetime import date, timezone
from datetime import datetime as dt

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_BUNDLE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Stealth", "Defense Impairment", "Defense Evasion", "Credential Access",
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
    ap.add_argument("--platform", required=True, help='MITRE platform name exactly as used in x_mitre_platforms, e.g. "ESXi"')
    ap.add_argument("--bundle", help="Path to a local enterprise-attack.json (skips the download)")
    ap.add_argument("--detections", action="append", default=None,
                     help="Path to a detections JSON file to cross-reference for coverage (repeatable; "
                          "any file whose entries expose mitre_attack.techniques[].id works, including "
                          "data/aria-detections.json). Default: data/detections.json and data/aria-detections.json.")
    ap.add_argument("--output", help="Output path (default: data/mitre-attack-<platform-lower>.json)")
    args = ap.parse_args()

    platform = args.platform
    output = pathlib.Path(args.output) if args.output else ROOT / "data" / f"mitre-attack-{platform.lower()}.json"

    bundle = load_bundle(args.bundle)
    objs = bundle["objects"]
    by_id = {o["id"]: o for o in objs}

    attack_spec_version = next((o["x_mitre_attack_spec_version"] for o in objs if o.get("x_mitre_attack_spec_version")), None)

    tactics = [o for o in objs if o["type"] == "x-mitre-tactic"]
    tactic_by_shortname = {t["x_mitre_shortname"]: t["name"] for t in tactics}

    def tech_tactics(t):
        out = []
        for kcp in t.get("kill_chain_phases", []):
            if kcp.get("kill_chain_name") == "mitre-attack":
                out.append(tactic_by_shortname.get(kcp["phase_name"], kcp["phase_name"]))
        return out

    data_components = {o["id"]: o for o in objs if o["type"] == "x-mitre-data-component"}

    techniques = [o for o in objs if o["type"] == "attack-pattern" and not o.get("revoked") and not o.get("x_mitre_deprecated")]
    platform_techniques = [t for t in techniques if platform in t.get("x_mitre_platforms", [])]

    rels = [o for o in objs if o["type"] == "relationship" and o["relationship_type"] == "detects"]
    strategy_to_tech, tech_to_strategies = {}, {}
    for r in rels:
        strategy_to_tech.setdefault(r["source_ref"], []).append(r["target_ref"])
        tech_to_strategies.setdefault(r["target_ref"], []).append(r["source_ref"])

    strategies = {o["id"]: o for o in objs if o["type"] == "x-mitre-detection-strategy"}
    analytic_to_strategy = {}
    for s in strategies.values():
        for aref in s.get("x_mitre_analytic_refs", []):
            analytic_to_strategy[aref] = s

    analytics_all = [o for o in objs if o["type"] == "x-mitre-analytic"]
    strategy_to_analytics = {}
    for a in analytics_all:
        strat = analytic_to_strategy.get(a["id"])
        if strat:
            strategy_to_analytics.setdefault(strat["id"], []).append(a)

    platform_analytics = [a for a in analytics_all if platform in a.get("x_mitre_platforms", [])]

    def build_analytic(a):
        an_id, an_url = external_ref(a)
        strat = analytic_to_strategy.get(a["id"])
        det_id, det_url, strat_name, techs = None, None, None, []
        if strat:
            det_id, det_url = external_ref(strat)
            strat_name = strat.get("name")
            for tref in strategy_to_tech.get(strat["id"], []):
                t = by_id.get(tref)
                if t and t["type"] == "attack-pattern":
                    t_id, t_url = external_ref(t)
                    techs.append({"attack_id": t_id, "name": t.get("name"), "tactics": tech_tactics(t), "url": t_url})
        log_sources = []
        for lr in a.get("x_mitre_log_source_references", []):
            dc = data_components.get(lr.get("x_mitre_data_component_ref"))
            log_sources.append({
                "log_source": lr.get("name"),
                "channel": lr.get("channel"),
                "data_component": dc.get("name") if dc else None,
            })
        return {
            "analytic_id": an_id,
            "name": a.get("name"),
            "description": a.get("description"),
            "platforms": a.get("x_mitre_platforms", []),
            "techniques": techs,
            "log_sources": log_sources,
            "mutable_elements": [{"field": m.get("field"), "description": m.get("description")} for m in a.get("x_mitre_mutable_elements", [])],
            "detection_strategy": {"id": det_id, "name": strat_name, "url": det_url} if strat else None,
            "version": a.get("x_mitre_version"),
            "modified": (a.get("modified") or "")[:10] or None,
            "url": an_url,
        }

    analytics_out = sorted((build_analytic(a) for a in platform_analytics), key=lambda x: x["analytic_id"] or "")

    techniques_out = []
    for t in sorted(platform_techniques, key=lambda x: external_ref(x)[0] or ""):
        t_id, t_url = external_ref(t)
        strat_ids = tech_to_strategies.get(t["id"], [])
        analytic_count, platform_analytic_count = 0, 0
        for sid in strat_ids:
            for a in strategy_to_analytics.get(sid, []):
                analytic_count += 1
                if platform in a.get("x_mitre_platforms", []):
                    platform_analytic_count += 1
        techniques_out.append({
            "attack_id": t_id,
            "name": t.get("name"),
            "is_subtechnique": bool(t.get("x_mitre_is_subtechnique", False)),
            "tactics": tech_tactics(t),
            "platforms": t.get("x_mitre_platforms", []),
            "description": (t.get("description") or "").split("\n")[0][:400],
            "url": t_url,
            "analytic_count_total": analytic_count,
            "analytic_count_platform": platform_analytic_count,
            "has_platform_analytic": platform_analytic_count > 0,
        })

    detections_paths = args.detections or [
        str(ROOT / "data" / "detections.json"),
        str(ROOT / "data" / "aria-detections.json"),
    ]
    our_technique_ids = set()
    for p in detections_paths:
        detections_path = pathlib.Path(p)
        if not detections_path.exists():
            continue
        our_detections = json.loads(detections_path.read_text(encoding="utf-8"))
        for d in our_detections:
            for t in d.get("mitre_attack", {}).get("techniques", []):
                our_technique_ids.add(t["id"])
    for t in techniques_out:
        t["covered_by_library"] = t["attack_id"] in our_technique_ids

    tactic_counts = {}
    for t in techniques_out:
        for tac in t["tactics"]:
            tactic_counts[tac] = tactic_counts.get(tac, 0) + 1
    tactic_counts = {k: tactic_counts[k] for k in TACTIC_ORDER if k in tactic_counts}

    output_data = {
        "metadata": {
            "title": f"MITRE ATT&CK Enterprise - {platform} Platform Analytics",
            "description": (
                f"Techniques and formal MITRE ATT&CK Detection Analytics scoped to the {platform} platform, "
                "extracted from the official MITRE ATT&CK Enterprise STIX dataset. Loaded by the Threat Detection "
                "Library app to show ATT&CK coverage for this platform's batch."
            ),
            "source": "https://github.com/mitre/cti (enterprise-attack/enterprise-attack.json)",
            "attack_version_reference": "https://attack.mitre.org/resources/updates/",
            "attack_spec_version": attack_spec_version,
            "platform": platform,
            "retrieved": str(date.today()),
            "technique_count": len(techniques_out),
            "analytic_count": len(analytics_out),
            "techniques_covered_by_library": sum(1 for t in techniques_out if t["covered_by_library"]),
            "tactic_breakdown": tactic_counts,
        },
        "techniques": techniques_out,
        "analytics": analytics_out,
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(output_data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {output.relative_to(ROOT)}: {len(techniques_out)} techniques, {len(analytics_out)} analytics "
          f"({output_data['metadata']['techniques_covered_by_library']} covered by this library)")


if __name__ == "__main__":
    main()
