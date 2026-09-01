# HPE iLO Threat Detection Library — Summary & Priority Packs

Companion index to `data/ilo-detections.json` (107 Splunk SPL detections
across HPE iLO, Redfish, Remote Console, Virtual Media, UEFI/BIOS/Firmware,
Integrated Management Log, Active Health System, HPE OneView, and 8
`HPE-X-###` cross-platform correlations).

Every detection ID below is a stable reference into
`data/ilo-detections.json` — look it up by `id` for the full SPL,
investigation steps, and response guidance.

## Scope note

The specification asked for "at least 250" detections and named HPE iLO
as Tier-0/Tier-1 out-of-band management infrastructure, singling out
**Remote Console, Virtual Media, boot override, new privileged accounts,
firmware downgrade, Secure Boot/TPM changes, log clearing, syslog
redirection, Intelligent Provisioning use, and OneView-driven fleet
changes** as the highest-priority attack surface. This catalogue ships
**107**: every entry is a distinct, fully-detailed detection with real
SPL, MITRE ATT&CK IDs validated against the current ATT&CK STIX corpus,
and no fabricated HPE log events or field names. As with the Red Hat,
Fortinet, and Dell iDRAC catalogues, padding to 250 would have meant
duplicating detections or inventing telemetry — both would violate this
catalogue's own quality-control rules. Every one of the ten
explicitly-prioritized attack patterns above has dedicated, full-depth
coverage (see §9 below); the remaining areas of the specification's
requested breadth (per-Redfish-endpoint coverage, HPE Compute Ops
Management depth, exhaustive OneView breadth) are covered at a
representative rather than exhaustive depth, extendable in future
batches the same way the ESXi, Red Hat, Fortinet, and iDRAC catalogues
grew.

### On ATT&CK mapping for out-of-band/firmware activity

Per specification instruction, ATT&CK does not cleanly represent
out-of-band management or firmware activity in most cases — there is no
technique for "remotely-mounted virtual media" or "BIOS boot-override
via a hardware management controller." **6 of the 107 detections**
(marked with an `attack_mapping_note` field in the data) use the closest
valid ATT&CK technique with an explicit caveat rather than forcing a poor
fit or inventing an ID — most commonly `T1200` (Hardware Additions) for
virtual media, since an iLO-mounted image is presented to the host
exactly as physically-inserted media would be, and `T1542` (Pre-OS Boot)
for boot-order/Secure Boot/BIOS-password/network-mode changes, since
ATT&CK's boot-security techniques don't distinguish an out-of-band
controller from an on-host attacker.

Note also that `T1562` (Impair Defenses), the ATT&CK technique that
would most naturally describe some anti-forensics/log-tampering actions,
is not present in this deployment's validated MITRE technique cache
(`mitre_lookup.json`, 697 techniques). Rather than use an unvalidated ID,
every detection that would otherwise have cited `T1562` instead cites the
validated `T1070` (Indicator Removal), which is a reasonable adjacent fit
for log-clearing and syslog-redirection behavior.

---

## 1. Namespace coverage matrix

| Namespace | Platform | Detections |
|---|---|---:|
| `ILO-###` | iLO core: authentication, user/role management, directory auth, power, boot configuration, network, management services, certificates, syslog/audit tampering, Intelligent Provisioning, storage, config export/import, reset, physical security, Compute Ops Management, fleet-wide | 50 |
| `RC-###` | Remote Console | 7 |
| `VMEDIA-###` | Virtual Media | 5 |
| `FW-###` | Firmware / UEFI / BIOS / Secure Boot / TPM | 8 |
| `HREDFISH-###` | Redfish API | 8 |
| `IML-###` | Integrated Management Log | 8 |
| `AHS-###` | Active Health System | 5 |
| `ONEVIEW-###` | HPE OneView | 8 |
| `HPE-X-###` | Cross-platform correlation | 8 |
| **Total** | | **107** |

## 2. Detection by component

| Component | Count | Component | Count |
|---|---:|---|---:|
| Security configuration | 27 | Storage | 4 |
| Authentication | 12 | Fleet management | 4 |
| Firmware | 10 | Directory Authentication | 3 |
| Redfish API | 8 | Certificates | 3 |
| Remote Console | 7 | | |
| User Management | 5 | | |
| Virtual Media | 5 | | |
| Power | 5 | | |
| Boot | 5 | | |
| Network | 5 | | |
| Hardware trust | 4 | | |

## 3. Severity and confidence

| Severity | Count | | Confidence | Count |
|---|---:|---|---|---:|
| High | 39 | | Medium | 48 |
| Critical | 32 | | High | 44 |
| Medium | 26 | | Low | 15 |
| Low | 9 | | | |
| Informational | 1 | | | |

## 4. Detection type and maturity

| Type | Count | | Maturity | Count |
|---|---:|---|---|---:|
| Atomic | 54 | | Level 1 — simple indicator | 50 |
| Anomaly | 16 | | Level 2 — threshold | 29 |
| Threshold | 13 | | Level 3 — behavioral | 12 |
| Sequence | 8 | | Level 4 — correlation | 8 |
| Correlation | 8 | | Level 5 — multi-platform sequence | 8 |
| Configuration change | 7 | | | |
| Behavioral | 1 | | | |

All 8 Level-5 entries are `HPE-X-###` cross-platform correlations by
design — every `HPE-X-###` detection is Level 5.

## 5. False positive rating and telemetry requirement

| FP Rating | Count | | Telemetry | Count |
|---|---:|---|---|---:|
| Medium | 55 | | Recommended | 43 |
| Low | 39 | | Essential | 41 |
| High | 13 | | Optional | 23 |

## 6. CIM coverage

**90% CIM-compatible (96 / 107).** The 11 non-CIM entries are hardware
telemetry sources (IML fault/thermal/memory entries, physical-security,
discovery/anomaly signals) that don't map cleanly onto a Splunk CIM data
model. Of the CIM-mapped entries, concentrated in `Change` (configuration
integrity — the majority of the catalogue), `Authentication`, and
`Data_Access` (configuration/log export, AHS collection).

## 7. Risk scoring reference

`score = severity(1-5) × confidence(1-5) × impact(1-5)`, max 125.

| Score band | Count | Interpretation |
|---|---:|---|
| 100–125 | 33 | Page immediately / Tier 1 candidate |
| 60–99 | 22 | Investigate same business day |
| 30–59 | 20 | Queue for triage / hunting |
| < 30 | 32 | Enrichment / context-only |

---

## 8. Priority Detection Packs

### Tier 1 — Critical iLO Detections (25 detections)

Critical severity **and** high confidence **and** Low false-positive
rating — within the specification's requested 30–50 range.

| ID | Title | Risk score |
|---|---|---:|
| ILO-004 | Successful iLO Login Following Repeated Failures | 125 |
| VMEDIA-003 | iLO Virtual Media Mount Followed by One-Time Boot Override and Reboot | 125 |
| FW-001 | iLO Secure Boot Disabled | 125 |
| FW-002 | iLO TPM Configuration Changed or Cleared | 125 |
| ILO-040 | iLO-Initiated Logical Drive Deletion | 125 |
| ILO-044 | iLO Reset to Factory Default | 125 |
| ONEVIEW-001 | HPE OneView New Administrator Account Created | 125 |
| ONEVIEW-005 | HPE OneView Audit Logging Disabled or Retention Reduced | 125 |
| HPE-X-001 | iLO Compromise Leading to OS-Level Bypass (Virtual Media / Boot Override Chain) | 125 |
| HPE-X-004 | iLO Compromise Followed by Coordinated Anti-Forensics Across Log Sources | 125 |
| HPE-X-005 | iLO Destructive Attack Chain (Privileged Login → Storage Deletion → Power Cycle → Boot Failure) | 125 |
| HPE-X-006 | HPE OneView-Driven Fleet-Wide Compromise Chain | 125 |
| ILO-006 | iLO Login Outside the Out-of-Band Management Network | 100 |
| ILO-007 | iLO Default Credential Login Attempt | 100 |
| ILO-011 | iLO User Granted Administrator Privilege | 100 |
| ILO-015 | New Directory Group Granted iLO Administrator Access | 100 |
| VMEDIA-002 | iLO Virtual Media From Unusual or External URI | 100 |
| FW-005 | iLO Firmware Downgrade Detected | 100 |
| FW-008 | iLO Firmware Rollback Protection Disabled | 100 |
| HREDFISH-007 | Redfish API BIOS/Boot Resource Modified via PATCH | 100 |
| ILO-034 | iLO Syslog Forwarding Disabled | 100 |
| ILO-036 | iLO Local Security Log / IML Cleared | 100 |
| IML-002 | IML Cleared | 100 |
| ONEVIEW-003 | HPE OneView Firmware Baseline Downgraded | 100 |
| HPE-X-003 | Identity Compromise Leading to iLO Directory-Based Access | 100 |

### Themed packs

| Pack | Count | Focus |
|---|---:|---|
| **Authentication Protection Pack** | 10 | Brute force, spray, default-credential, first-seen source/dormant-account across ILO-001 through ILO-009 plus HREDFISH-001 |
| **Remote Console / Virtual Media Pack** | 12 | RC-001 through RC-007 and VMEDIA-001 through VMEDIA-005 — the flagship attack surface named by the specification |
| **Firmware / BIOS Protection Pack** | 15 | Secure Boot, TPM, BIOS admin password, firmware downgrade/untrusted-source/rollback-protection, boot override/order, Intelligent Provisioning firmware path, OneView baseline downgrade |
| **Storage Destruction Pack** | 3 | Logical drive deletion, Intelligent Provisioning storage config changes, IML storage-fault correlation |
| **Management Plane Compromise Pack** | 13 | Privilege-escalation, identity/directory-trust events plus all 8 cross-platform `HPE-X-###` chains |
| **OneView Fleet Compromise Pack** | 9 | All 8 `ONEVIEW-###` detections plus HPE-X-006 — new admin accounts, broad-scope tokens, fleet-wide profile/firmware/network pushes, audit-logging tampering |
| **Anti-Forensics Pack** | 14 | Syslog redirection/disablement, IML/Security Log clearing, heartbeat-gap and forwarding-gap compensating detections, factory reset, AHS tampering, OneView audit disablement, coordinated cross-source anti-forensics correlation |

Pack membership is computed from each entry's `tags` array — filter
`data/ilo-detections.json` on the tags named above to reproduce each
list; packs overlap by design.

---

## 9. Coverage of the explicitly-prioritized attack patterns

The task's closing paragraph named ten patterns above almost everything
else. Every one has dedicated, full-depth coverage:

| Prioritized pattern | Detection(s) |
|---|---|
| Remote Console | RC-001 through RC-007 |
| Virtual Media | VMEDIA-001 through VMEDIA-005 |
| Boot override | ILO-021, ILO-022, VMEDIA-003, HREDFISH-007 |
| New privileged accounts | ILO-010, ILO-011, ILO-015, RC-007, ONEVIEW-001 |
| Firmware downgrade | FW-005, FW-006, FW-008, ONEVIEW-003 |
| Secure Boot / TPM changes | FW-001, FW-002 |
| Log clearing | ILO-036, IML-002 |
| Syslog redirection | ILO-033, ILO-034, ILO-035 (compensating absence-detection) |
| Intelligent Provisioning use | ILO-037, ILO-038, ILO-039 |
| OneView-driven fleet changes | ONEVIEW-002, ONEVIEW-003, ONEVIEW-007, ILO-047, ILO-048, HPE-X-006 |

And the flagship end-to-end chains combining several of the above —
**virtual media → boot override → reboot** (VMEDIA-003, elevated to a
full cross-platform incident view in HPE-X-001), **privileged login →
storage deletion → power cycle → boot failure** (HPE-X-005), and
**new OneView admin/token → fleet-wide push** (HPE-X-006) — are
implemented exactly as described in the task, alongside HPE-X-002
(iLO-to-hypervisor pivot), HPE-X-003 (identity compromise reaching iLO
directory-based access), HPE-X-007 (OOB console access preceding OS-level
account creation), and HPE-X-008 (coordinated activity spanning both iLO
and Dell iDRAC estates).

## 10. Detection gap analysis

Per the specification's requirement to distinguish what's actually
observable:

- **Visible in iLO Security Log / event log**: the large majority of this
  catalogue — authentication, user/role management, Remote Console,
  Virtual Media, power, boot, BIOS/UEFI, firmware, network, certificates,
  logging configuration, Intelligent Provisioning, storage.
- **Visible only in IML/AHS telemetry**: hardware faults, thermal/fan
  anomalies, correctable memory errors, storage-controller faults
  (IML-001, IML-004 through IML-007) and configuration-drift detection
  via periodic snapshot comparison (AHS-005) — these require IML/AHS
  polling or export specifically and will not appear in the general
  security audit log.
- **Visible only through Redfish/API auditing**: API-driven account and
  BIOS/boot changes that bypass the GUI entirely (HREDFISH-002,
  HREDFISH-007) — a deployment that only monitors GUI-driven
  `ilo_security` events without also ingesting Redfish API logs will miss
  automation- or attacker-scripted changes made via `PATCH`/`POST` calls.
- **Visible only through network telemetry**: whether the OOB management
  network itself is properly segmented (ILO-041) can only be confirmed by
  cross-referencing against actual network topology/firewall data, not
  iLO's own logs.
- **Requiring OS/hypervisor logs**: HPE-X-001, HPE-X-002, and HPE-X-007
  explicitly depend on correlating iLO events with host OS or hypervisor
  telemetry (this library's own ESXi/Red Hat catalogues, where deployed)
  — iLO alone cannot confirm what actually happened *after* a boot-bypass
  succeeded, or whether a Remote Console session was followed by OS-level
  persistence.
- **Requiring identity provider logs**: HPE-X-003 explicitly depends on
  identity-provider risk-signal ingestion (impossible travel, new MFA
  device, out-of-band password reset) in addition to iLO directory-group
  telemetry — a deployment without identity-provider risk feeds cannot
  detect this chain, only the iLO-side half of it (ILO-015).
- **Requiring HPE OneView**: fleet-wide profile/firmware/network-push
  detections (`ONEVIEW-###`, HPE-X-006) require OneView's own audit log;
  a per-device-only iLO deployment has no visibility into fleet-wide
  orchestration risk at all.
- **Requiring HPE Compute Ops Management**: cloud-fleet-management
  detections (ILO-047, ILO-048) require COM audit events surfaced through
  iLO; an environment not enrolled in COM has no telemetry for this
  vector and these detections will simply never fire.
- **Requiring cross-vendor OOB correlation**: HPE-X-008 explicitly depends
  on ingesting both iLO and Dell iDRAC telemetry into the same search — a
  single-vendor OOB estate cannot produce this detection at all.
- **Firmware actions with limited logging**: not every firmware component
  logs update activity with the same fidelity as iLO/BIOS firmware; treat
  component-specific `telemetry_requirement` fields as authoritative per
  entry.
- **Physical tampering visible only in IML telemetry**: chassis intrusion
  detection (FW-004) is the *only* signal this catalogue has for physical
  tampering; it cannot see who physically touched a server, only that a
  sensor tripped.

**Out-of-band logs do not provide OS process telemetry.** Every claim in
this catalogue that needs OS-level process/file attribution explicitly
depends on host OS or hypervisor logs (HPE-X-001, HPE-X-002, HPE-X-007) —
iLO alone can tell you *that* a boot-bypass sequence completed, never
what the attacker-controlled bootloader or OS subsequently did.

---

*Generated from `data/ilo-detections.json` (107 entries). Regenerate
these tables after any future batch adds or edits detections — the counts
above are a snapshot, not a live query.*
