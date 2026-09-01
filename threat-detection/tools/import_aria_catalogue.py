#!/usr/bin/env python3
"""
Parse docs/aria-catalogue-source.md (the VMware Aria Operations for Logs
Threat Detection Catalogue) into data/aria-detections.json.

Each source entry only supplies Component/Severity/MITRE tactic+technique/
Aria query/tuning-note; this script synthesizes the remaining
schema-required fields (description, data sources, how-to-implement,
known false positives, investigation steps, references) from that using
templates keyed on the MITRE tactic and VMware component, and auto-links
related_detections from "Correlate with VMW-XXX" mentions and
singular/mass title pairs (e.g. "Snapshot deleted" <-> "Mass snapshot
deletion").

Run this after editing docs/aria-catalogue-source.md, then run
tools/build.py to regenerate the combined index.html (these detections
are part of the combined library only; there is no standalone Aria
page anymore).

Usage:
    python3 tools/import_aria_catalogue.py
"""
import json
import pathlib
import re
from datetime import date

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE_PATH = ROOT / "docs" / "aria-catalogue-source.md"
OUT_PATH = ROOT / "data" / "aria-detections.json"

ENTRY_PATTERN = re.compile(
    r"### (VMW-\d+) - (.+?)\n"
    r"- \*\*Component:\*\* (.+?)\n"
    r"- \*\*Severity:\*\* (.+?)\n"
    r"- \*\*MITRE tactic:\*\* (.+?)\n"
    r"- \*\*MITRE technique:\*\* (.+?)\n"
    r"- \*\*Aria search query:\*\*\n\n"
    r"```text\n(.+?)\n```\n"
    r"- \*\*Detection logic / tuning:\*\* (.+?)\n",
    re.DOTALL,
)

TACTIC_IDS = {
    "Reconnaissance": "TA0043", "Resource Development": "TA0042", "Initial Access": "TA0001",
    "Execution": "TA0002", "Persistence": "TA0003", "Privilege Escalation": "TA0004",
    "Defense Evasion": "TA0005", "Credential Access": "TA0006", "Discovery": "TA0007",
    "Lateral Movement": "TA0008", "Collection": "TA0009", "Command and Control": "TA0011",
    "Exfiltration": "TA0010", "Impact": "TA0040",
}

TACTIC_RATIONALE = {
    "Credential Access": "credential-testing or credential-exposure activity that often precedes account takeover",
    "Initial Access": "a foothold-establishment signal worth correlating with what follows it",
    "Privilege Escalation": "a privilege change that can materially widen an attacker's blast radius across the virtualization estate",
    "Lateral Movement": "a path into the management or hypervisor plane that can be used to pivot further",
    "Persistence": "a mechanism attackers use to retain access across credential rotations, reboots, or incident response",
    "Defense Evasion": "an action that can blind, weaken, or hinder subsequent detection and response",
    "Discovery": "reconnaissance activity that typically precedes a more impactful action",
    "Collection": "a staging step that can precede data theft",
    "Exfiltration": "a high-confidence data-exfiltration signal",
    "Command and Control": "a signal that can indicate covert command-and-control or an unmonitored data channel",
    "Impact": "a high-impact action consistent with ransomware, sabotage, or denial of service against the virtualization estate",
}

TACTIC_INVESTIGATION = {
    "Credential Access": [
        "Identify the source IP/user and compare against known-good baselines for that identity.",
        "Check for a subsequent successful login or privileged action from the same identity or source.",
        "Correlate with other catalogue entries for the same actor within a short window.",
    ],
    "Initial Access": [
        "Identify the source IP/user and compare against known-good baselines for that identity.",
        "Check for a subsequent successful login or privileged action from the same identity or source.",
        "Correlate with other catalogue entries for the same actor within a short window.",
    ],
    "Privilege Escalation": [
        "Identify the actor and confirm they are authorized to make this change under your access model.",
        "Review exactly what was granted, created, or modified, and whether it exceeds least privilege.",
        "Check for related identity or configuration changes in the same session.",
    ],
    "Defense Evasion": [
        "Confirm whether this aligns with a documented maintenance window or change ticket.",
        "Check for other defense-impairment or destructive actions from the same actor/session.",
        "Restore the affected control and rotate credentials for the account used if unauthorized.",
    ],
    "Discovery": [
        "Determine whether the account/session is a known admin, monitoring, or automation identity.",
        "Check for follow-on destructive or configuration-change activity from the same source.",
        "Treat repeated or broad enumeration as higher priority than a single occurrence.",
    ],
    "Collection": [
        "Identify what was collected, cloned, or copied, and its sensitivity.",
        "Confirm the initiating account and the destination of the copy.",
        "Check for a subsequent export- or exfiltration-tagged event on the same object.",
    ],
    "Exfiltration": [
        "Identify what left the environment, its destination, and the initiating account.",
        "Treat as a high-priority incident pending confirmation of business authorization.",
        "Review for preceding collection, cloning, or snapshot activity on the same object.",
    ],
    "Command and Control": [
        "Review the configured destination/endpoint for legitimacy against your change records.",
        "Check whether this change opens an unmonitored egress path.",
        "Correlate with other configuration changes from the same actor.",
    ],
    "Lateral Movement": [
        "Identify the source and destination and whether this is an approved administrative path.",
        "Check for follow-on activity on the destination host or VM.",
        "Verify against your network segmentation and jump-host policy.",
    ],
    "Execution": [
        "Identify exactly what was executed, attached, or mounted, and by whom.",
        "Check whether this ties to known automation or a documented manual admin action.",
        "Review for follow-on discovery or destructive activity from the same session.",
    ],
    "Impact": [
        "Determine the scope - single object vs. bulk - and whether it aligns with a change window.",
        "Identify the actor/session and correlate with other precursor activity in this catalogue.",
        "If unauthorized, treat as an active incident and engage your IR process immediately.",
    ],
}

TACTIC_FALSE_POSITIVES = {
    "Credential Access": "Legitimate password rotations, forgotten-password lockouts, or misconfigured automation retrying with stale credentials.",
    "Initial Access": "Jump-host/bastion IP changes, VPN re-IP, or a new but legitimate administrative workstation.",
    "Privilege Escalation": "Planned RBAC/role changes as part of onboarding, project setup, or a documented access review.",
    "Defense Evasion": "Planned maintenance windows, vendor-guided support sessions, or change-managed configuration updates.",
    "Discovery": "Routine monitoring, backup pre-checks, or CMDB/inventory automation.",
    "Collection": "Legitimate backup, cloning, or template-creation workflows.",
    "Exfiltration": "Approved OVF/OVA export for migration, archival, or vendor support requests.",
    "Command and Control": "Legitimate monitoring/SNMP or proxy re-platforming by the infrastructure team.",
    "Lateral Movement": "Scheduled DRS/vMotion load balancing or planned maintenance evacuation.",
    "Execution": "Scripted orchestration (patch tools, backup agents, provisioning pipelines) performing the same action at scale.",
    "Impact": "Scheduled maintenance, DR failover tests, decommissioning projects, or backup-tool orchestration.",
}

MASS_PREFIXES = ["mass ", "multiple ", "bulk ", "repeated "]


def data_sources_for(component):
    c = component.lower()
    sources = []

    def add(name, path, desc):
        if not any(s["name"] == name for s in sources):
            sources.append({"name": name, "path": path, "description": desc})

    if "sso" in c:
        add("vCenter SSO / STS logs", "VCSA: /var/log/vmware/sso",
            "Single Sign-On / Security Token Service authentication and identity-source events, ingested via the Aria 'VMware - vCenter Server' content pack.")
    if "esxi" in c:
        add("ESXi host logs (hostd/vobd/shell/auth/vmkernel)", "/var/log/ on each ESXi host",
            "ESXi syslog streams forwarded to Aria Operations for Logs (esxcli system syslog config set --loghost=<Aria collector>), parsed by the 'VMware - vSphere' content pack.")
    if ("vcenter" in c or "vpxd" in c or c.startswith("cluster") or "kms" in c or "backup" in c
            or "content library" in c or "guest operations" in c or c == "storage" or "api" in c or c.strip() == "vm"):
        add("vCenter Server task/event logs", "VCSA: /var/log/vmware/vpxd",
            "vpxd task and event stream (VM/host/cluster/permission operations), ingested via the Aria 'VMware - vCenter Server' content pack.")
    if "networking" in c:
        add("vSphere/NSX networking logs", "VCSA vpxd + NSX Manager logs",
            "Virtual switch, portgroup, and distributed-switch configuration events, via the 'VMware - vSphere' and, where NSX is deployed, 'VMware - NSX-T' content packs.")
    if "storage" in c:
        add("Datastore / storage events", "vCenter vpxd + ESXi storage stack",
            "Datastore, VMFS, and virtual-disk lifecycle events surfaced through vCenter and ESXi logs.")
    if "kms" in c:
        add("vCenter native key provider / KMS logs", "VCSA: /var/log/vmware/vpxd",
            "Encryption policy and key-provider configuration events.")
    if not sources:
        add("vCenter Server task/event logs", "VCSA: /var/log/vmware/vpxd",
            "vpxd task and event stream, ingested via the Aria 'VMware - vCenter Server' content pack.")
    return sources


def risk_objects_for(component):
    c = component.lower()
    objs = [{"field": "user", "type": "user"}]
    if "esxi" in c:
        objs.append({"field": "host", "type": "system"})
    else:
        objs.append({"field": "vc_username", "type": "user"})
    if "vm" in c or c == "storage" or "guest" in c:
        objs.append({"field": "vm_name", "type": "system"})
    return objs


def type_for(title):
    t = title.lower()
    if any(k in t for k in ["ransomware sequence", "ransomware destructive", "burst"]):
        return "Correlation"
    if any(k in t for k in ["mass ", "multiple ", "bulk ", "repeated ", "unusual ", "unexpected "]):
        return "Anomaly"
    return "TTP"


def slug(vmw_id, title):
    s = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return f"{vmw_id.lower()}-{s}"


def technique_url(tid):
    parts = tid.split(".")
    if len(parts) == 2:
        return f"https://attack.mitre.org/techniques/{parts[0]}/{parts[1]}/"
    return f"https://attack.mitre.org/techniques/{tid}/"


def main():
    raw = SOURCE_PATH.read_text(encoding="utf-8")
    rows = ENTRY_PATTERN.findall(raw)
    if not rows:
        raise SystemExit(f"No entries parsed from {SOURCE_PATH}")

    title_to_id = {}
    for vmw_id, title, *_ in rows:
        title_to_id[vmw_id] = slug(vmw_id, title)

    by_title = {title.lower(): vmw_id for vmw_id, title, *_ in rows}
    today = str(date.today())

    entries = []
    for vmw_id, title, component, severity, tactic, technique_raw, query, tuning in rows:
        tid, tname = technique_raw.split(" ", 1)
        entry_id = title_to_id[vmw_id]
        rationale = TACTIC_RATIONALE.get(tactic, "an activity worth correlating with surrounding events")
        description = (
            f"{title} - detected within {component} and surfaced through VMware Aria Operations for Logs. "
            f"Represents {rationale}."
        )
        related = sorted(set(re.findall(r"VMW-\d+", tuning)))
        related_ids = [title_to_id[r] for r in related if r in title_to_id and r != vmw_id]

        entries.append({
            "id": entry_id,
            "vmw_id": vmw_id,
            "title": title,
            "description": description,
            "analytic_story": ["VMware vSphere Attack & Ransomware Precursor Activity (Aria Catalogue)"],
            "type": type_for(title),
            "status": "production",
            "severity": severity.lower(),
            "confidence": "medium",
            "platform": component,
            "product_version": "vSphere/VCSA 6.7+, Aria Operations for Logs 8.x+",
            "tool": "VMware Aria Operations for Logs",
            "mitre_attack": {
                "tactics": [{"id": TACTIC_IDS.get(tactic, ""), "name": tactic}],
                "techniques": [{"id": tid, "name": tname, "url": technique_url(tid)}],
            },
            "data_sources": data_sources_for(component),
            "detection_logic": tuning,
            "aria_query": query,
            "how_to_implement": (
                f"Ingest {component} activity into VMware Aria Operations for Logs via the relevant VMware "
                "content pack ('VMware - vSphere', 'VMware - vCenter Server', or 'VMware - NSX-T' depending on "
                "source), then confirm the field names referenced in this query (user, vc_username, src, "
                "vm_name, host, principal, etc.) match what your content-pack version and source product "
                "actually extract before enabling the alert. Use Aria's UI-native time range, grouping, and "
                "threshold functions for any count/burst logic rather than embedding statistics in the query."
            ),
            "known_false_positives": TACTIC_FALSE_POSITIVES.get(
                tactic, "Planned administrative or automated activity matching this pattern; validate against change records before treating as malicious."),
            "investigation_steps": TACTIC_INVESTIGATION.get(tactic, [
                "Identify the actor/session responsible and confirm authorization.",
                "Check for correlated activity elsewhere in this catalogue within a short time window.",
                "Escalate per your incident-response process if unauthorized.",
            ]),
            "risk_objects": risk_objects_for(component),
            "references": [
                {"title": f"MITRE ATT&CK {tid}: {tname}", "url": technique_url(tid)},
                {"title": "VMware Aria Operations for Logs: Content Packs documentation", "url": "https://docs.vmware.com/en/VMware-Aria-Operations-for-Logs/index.html"},
            ],
            "related_detections": related_ids,
            "tags": sorted(set(
                ["vmware", "aria-operations-for-logs"]
                + [w.strip().lower().replace(" ", "-") for w in component.split("/")]
                + [tactic.lower().replace(" ", "-")]
            )),
            "author": "Threat Detection Library",
            "created": today,
            "modified": today,
            "version": "1.0",
        })

    # Link singular <-> mass/multiple/bulk/repeated title pairs both ways.
    by_id = {e["id"]: e for e in entries}
    for e in entries:
        t = e["title"].lower()
        for p in MASS_PREFIXES:
            if not t.startswith(p):
                continue
            base = t[len(p):]
            for candidate in (base, base.replace("vms", "vm"), base.replace("hosts", "host")):
                vmw = by_title.get(candidate)
                if vmw and title_to_id[vmw] != e["id"]:
                    other = by_id[title_to_id[vmw]]
                    if other["id"] not in e["related_detections"]:
                        e["related_detections"].append(other["id"])
                    if e["id"] not in other["related_detections"]:
                        other["related_detections"].append(e["id"])
                    break

    ids = [e["id"] for e in entries]
    if len(ids) != len(set(ids)):
        seen = set()
        dupes = sorted({i for i in ids if i in seen or seen.add(i)})
        raise SystemExit(f"Duplicate ids: {dupes}")

    OUT_PATH.write_text(json.dumps(entries, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {OUT_PATH.relative_to(ROOT)}: {len(entries)} entries")


if __name__ == "__main__":
    main()
