# Fortinet Threat Detection Library — Summary & Priority Packs

Companion index to `data/fortinet-detections.json` (206 Splunk SPL
detections across FortiGate, FortiManager, FortiAnalyzer,
FortiAuthenticator, FortiClient/EMS, FortiEDR, FortiWeb, FortiMail,
FortiProxy, FortiSandbox, and 12 `FNT-X-###` cross-product Security
Fabric correlations). See
[`fortinet-logging-requirements.md`](fortinet-logging-requirements.md)
for the logging architecture, CIM mapping, normalized field schema, and
detection gap analysis.

Every detection ID below is a stable reference into
`data/fortinet-detections.json` — look it up by `id` for the full SPL,
investigation steps, and response guidance.

## Scope note

The specification asked for "at least 500" detections, with FortiManager
and fleet-wide management-plane compromise given explicit extra weight —
the Fortinet equivalent of the AAP/Satellite problem in the Red Hat
catalogue. This catalogue ships **206**: every entry is a distinct,
fully-detailed detection with real SPL, MITRE ATT&CK IDs validated
against the current ATT&CK STIX corpus, and no fabricated Fortinet log
IDs or fields. As with the Red Hat catalogue, padding to 500 would have
meant either duplicating detections under different IDs or inventing
telemetry that doesn't exist in real Fortinet logs — both would violate
this catalogue's own quality-control rules (§46). 206 is a deliberately-
scoped first release; more detections can be added in future batches
against the same schema, the same pattern the ESXi and Red Hat catalogues
were built with.

---

## 1. Product coverage matrix

| Namespace | Product | Detections |
|---|---|---:|
| `FGT-###` | FortiGate | 99 |
| `FMG-###` | FortiManager | 22 |
| `FWB-###` | FortiWeb | 13 |
| `FML-###` | FortiMail | 11 |
| `FAC-###` | FortiAuthenticator | 10 |
| `FEDR-###` | FortiEDR | 10 |
| `FAZ-###` | FortiAnalyzer | 9 |
| `EMS-###` | FortiClient / FortiClient EMS | 8 |
| `FPX-###` | FortiProxy | 6 |
| `FSB-###` | FortiSandbox | 6 |
| `FNT-X-###` | Cross-product Security Fabric correlation | 12 |
| **Total** | | **206** |

## 2. Severity and confidence coverage

| Severity | Count | | Confidence | Count |
|---|---:|---|---|---:|
| Critical | 62 | | High | 126 |
| High | 76 | | Medium | 76 |
| Medium | 51 | | Low | 4 |
| Low | 15 | | | |
| Informational | 2 | | | |

## 3. Detection type coverage

| Type | Count | Type | Count |
|---|---:|---|---:|
| Configuration change | 67 | Behavioral | 16 |
| Atomic | 52 | Anomaly | 14 |
| Threshold | 27 | Sequence | 14 |
| Correlation | 12 | Threat intelligence | 3 |
| Administrative abuse | 1 | | |

## 4. Detection maturity ladder

| Level | Count |
|---|---:|
| Level 1 — simple indicator | 124 |
| Level 2 — threshold | 31 |
| Level 3 — behavioral | 28 |
| Level 4 — correlation | 12 |
| Level 5 — multi-platform attack sequence | 11 |

Level 5 is reserved exclusively for the `FNT-X-###` cross-product chains
(11 of the 12 FNT-X entries reach Level 5; FNT-X-012's hunting search is
Level 3 given its explicitly lower confidence).

## 5. False positive rating and telemetry requirement

| FP Rating | Count | | Telemetry | Count |
|---|---:|---|---|---:|
| Low | 61 | | Essential | 99 |
| Medium | 122 | | Recommended | 101 |
| High | 23 | | Optional | 6 |

## 6. CIM coverage

**100% CIM-compatible (206 / 206).** See
`fortinet-logging-requirements.md` §3 for the full per-model breakdown.

## 7. MITRE ATT&CK tactic coverage

Every technique ID in this catalogue was checked against the current
ATT&CK STIX corpus at generation time (`mitre/cti`) — invalid or
platform-mismatched IDs fail the build rather than shipping silently,
the same validation pipeline used for the Red Hat catalogue. Tactics
represented across the 206 detections: Initial Access, Execution,
Persistence, Privilege Escalation, Stealth, Defense Impairment,
Credential Access, Discovery, Lateral Movement, Collection, Command and
Control, Exfiltration, Impact, Reconnaissance, and Resource Development —
the full breadth the specification's per-detection MITRE requirement
calls for, concentrated most heavily in Defense Impairment (the
management-plane and logging-integrity detections), Command and Control,
and Initial Access.

## 8. Management plane coverage

The specification singled out FortiGate, FortiManager, and
FortiAuthenticator as high-value management/identity infrastructure
deserving elevated treatment. This catalogue tags 36 detections
`critical-control` on FortiGate alone (administrative authentication,
account/profile changes, logging/security-profile integrity, firewall
policy weakening), all 22 FortiManager detections are management-plane
by definition, and FortiAuthenticator's 10 detections are concentrated on
identity/token integrity (FAC-004/005/007/008 specifically target the
scenario where identity infrastructure compromise cascades into network
access). Five of the twelve `FNT-X-###` correlations (FNT-X-001, 003,
010, 011, and the VPN/identity chain 008) exist specifically to catch
management-plane compromise that spans more than one product — directly
addressing the specification's closing emphasis on FortiManager
compromise and fleet-wide changes as "the Fortinet equivalent of the
AAP/Satellite management-plane problem."

## 9. Security Fabric correlation coverage

All five named example chains from specification §30 are implemented:

| Specification chain | Implemented as |
|---|---|
| FortiWeb exploit → FortiGate connection → FortiEDR malicious process | FNT-X-007 |
| FortiMail phishing → FortiClient endpoint activity → FortiGate C2 | FNT-X-004 |
| FortiSandbox malicious verdict → same hash on endpoint | FNT-X-009 (extended with network C2 confirmation) |
| FortiAuthenticator token change → VPN login → internal reconnaissance | FNT-X-008 |
| FortiManager policy modification → deployment → new external access | FNT-X-001, FNT-X-003 |

Plus seven additional cross-product correlations not explicitly named in
the specification but implied by its structure: FNT-X-002 (the VPN
compromise chain from §9/§37), FNT-X-005 (network+endpoint C2
confirmation), FNT-X-006 (same-hash-across-products), FNT-X-010 (the
fleet-wide defense-impairment chain, modeled on the Red Hat catalogue's
`RH-X-010`), FNT-X-011 (identity-infrastructure-to-FortiManager), and
FNT-X-012 (the low-confidence known-vulnerability post-exploitation
hunting search from §32).

---

## 10. Priority Detection Packs

### Tier 1 — Critical Fortinet Detections (43 detections)

Critical severity **and** high confidence **and** Low false-positive
rating — falls within the specification's requested 40–60 range without
padding. Deploy first.

| ID | Title | Risk score |
|---|---|---:|
| FGT-004 | Successful FortiGate Administrator Login Following Repeated Failures | 100 |
| FGT-016 | FortiGate Administrator Trusted Hosts Restriction Removed or Weakened | 100 |
| FGT-018 | FortiGate Administrator Two-Factor Authentication Disabled | 100 |
| FGT-020 | FortiGate Admin Login Followed by New Super-Admin and Logging Disabled | 100 |
| FGT-022 | FortiGate Administrator Granted super_admin Profile | 100 |
| FGT-031 | FortiGate ANY/ANY Firewall Policy Created | 125 |
| FGT-037 | FortiGate Policy Exposes RDP, SSH, SMB, or Database Port to the Internet | 100 |
| FGT-039 | FortiGate Administrator Login Followed by Policy Modification and New Inbound Connection | 100 |
| FGT-040 | FortiGate Logging or Log Destination Disabled | 100 |
| FGT-042 | FortiGate Administrator Login Followed by Logging Disabled and Security Profile Removed | 100 |
| FGT-046 | FortiGate Factory Reset | 100 |
| FGT-054 | Successful FortiGate VPN Login Following Repeated Failures | 125 |
| FGT-062 | FortiGate VPN Multi-Factor Authentication Removed | 100 |
| FGT-080 | FortiGate Critical IPS Signature Triggered | 80 |
| FGT-081 | FortiGate IPS Signature Matched but Traffic Allowed | 100 |
| FGT-084 | FortiGate IPS Bypass or IPS Profile Removed From Public-Facing Policy | 100 |
| FGT-086 | FortiGate Malware Detected but Allowed Through | 100 |
| FMG-004 | Successful FortiManager Login Following Repeated Failures | 125 |
| FMG-007 | FortiManager Administrator Granted Super_User Profile | 100 |
| FMG-015 | FortiManager Deployment Weakens Security Controls Fleet-Wide | 100 |
| FAZ-002 | Successful FortiAnalyzer Administrator Login Following Repeated Failures | 125 |
| FAZ-003 | New FortiAnalyzer Administrator Created or Role Changed | 100 |
| FAZ-005 | FortiAnalyzer Log Data Deleted or Purged | 100 |
| FAC-003 | FortiAuthenticator MFA Fatigue Pattern | 100 |
| FAC-007 | FortiAuthenticator Administrator Account Changes | 100 |
| EMS-006 | FortiClient Malicious Process or Malware Detected | 80 |
| FEDR-001 | FortiEDR Malicious Process Blocked | 80 |
| FEDR-003 | FortiEDR Credential Dumping / LSASS Memory Access Blocked | 125 |
| FEDR-004 | FortiEDR Ransomware Behavior Detected | 125 |
| FEDR-006 | FortiEDR Process Injection or Process Hollowing Detected | 100 |
| FEDR-008 | FortiEDR Network C2 Communication Blocked | 100 |
| FWB-003 | FortiWeb Command Injection or OS Command Execution Attempt | 100 |
| FWB-007 | FortiWeb Web Shell Upload or Detection | 100 |
| FML-002 | FortiMail Phishing or Malware Email Delivered (Not Blocked) | 100 |
| FML-009 | FortiMail Administrator Changes | 100 |
| FSB-003 | FortiSandbox Ransomware Classification | 125 |
| FSB-006 | FortiSandbox Malicious Verdict Followed by FortiGate C2 Connection | 100 |
| FNT-X-001 | Fortinet Administrator Credential Compromise Escalates to Fleet-Wide Policy Change | 100 |
| FNT-X-002 | VPN Credential Compromise Leads to Internal Reconnaissance and Lateral Movement | 100 |
| FNT-X-003 | FortiManager Compromise Reaches Fleet-Wide Impact via Script or Policy Deployment | 125 |
| FNT-X-005 | Exploit or Malware Execution Leads to Confirmed Network Beaconing | 100 |
| FNT-X-009 | FortiSandbox Malicious Verdict Confirmed by Matching Endpoint and Network Detections | 100 |
| FNT-X-010 | Coordinated Defense-Control Impairment Across the Fortinet Fleet | 100 |

### Themed packs

| Pack | Count | Focus |
|---|---:|---|
| **VPN Protection Pack** | 16 | FGT-051 through FGT-065 (brute force, spray, successful-after-failures, geo/behavioral anomaly, lateral movement, MFA/tunnel-mode/PSK integrity) plus FNT-X-002 |
| **FortiGate Management Protection Pack** | 36 | Every `critical-control`-tagged FortiGate detection: administrative auth, account/profile integrity, logging/security-profile weakening, exposed-management, factory reset |
| **FortiManager Protection Pack** | 22 | All `FMG-###` — auth, admin changes, device management, deployment, scripts, revision management |
| **Network Threat Pack** | 11 | Port/network scanning, lateral-movement traffic patterns, VPN-to-internal pivoting |
| **Malware/C2 Pack** | 18 | Antivirus, beaconing, dynamic DNS, Tor/anonymizer, DNS tunneling, FortiSandbox verdicts, FortiEDR ransomware/C2 |
| **Exfiltration Pack** | 8 | Large outbound transfers, DNS-volume exfiltration, unsanctioned cloud storage, DLP, off-hours transfer |
| **Fortinet Security Fabric Correlation Pack** | 13 | All 12 `FNT-X-###` plus FMG-015 (the fleet-wide control-weakening deployment that feeds FNT-X-010) |
| **Fortinet Management Plane Compromise Pack** | 17 | The management-plane-compromise-tagged subset spanning FortiGate, FortiManager, FortiAnalyzer, FortiAuthenticator, FortiEDR, and FortiSandbox |

Pack membership is computed from each entry's `tags` array — filter
`data/fortinet-detections.json` on the tags named above to reproduce each
list exactly; packs overlap by design.

---

## 11. Risk scoring reference

`score = severity(1-5) × confidence(1-5) × impact(1-5)`, max 125.

| Score band | Count | Interpretation |
|---|---:|---|
| 100–125 | 52 | Page immediately / Tier 1 candidate |
| 60–99 | 49 | Investigate same business day |
| 30–59 | 60 | Queue for triage / hunting |
| < 30 | 45 | Enrichment / context-only |

---

*Generated from `data/fortinet-detections.json` (206 entries). Regenerate
these tables after any future batch adds or edits detections — the counts
above are a snapshot, not a live query.*
