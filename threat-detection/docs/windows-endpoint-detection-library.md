# Windows Endpoint Threat Detection Library

Companion index to `data/windows-endpoint-detections.json` (73 Splunk SPL
detections). This is this library's fourteenth catalogue, and — like the
Cisco Network Device catalogue before it — authored for this project
rather than sourced from a single upstream project, with the same
methodology: every entry here exists specifically to close a gap this
library already knew about.

## Why this catalogue exists

Investigating "which ATT&CK techniques is this library missing" surfaced
a real bug: `data/mitre-attack-windows.json` predates the Splunk ESCU
catalogue and had never been re-cross-referenced against it, so it was
only checking coverage against the three dedicated Windows catalogues
(`data/ad-detections.json`, `data/rdp-detections.json`,
`data/dhcp-detections.json`) and missing the 1,236 ESCU entries whose
`component` is `"Windows Endpoint"` or `"Windows Network Telemetry"` —
content that closes 179 of the techniques the file was reporting as
gaps. That was fixed as its own standalone correction first (see the git
history for that commit): coverage moved from a reported 87/474 to an
accurate 261/474.

The *real*, corrected gap is 213 techniques, 211 of which have a real,
official MITRE Detection Analytic. This catalogue closes the first 73 of
those 211 — the ones with the strongest genuine Windows Event Log /
Sysmon signal, spanning the **Persistence**, **Credential Access**,
**Discovery**, **Stealth**, and **Defense Impairment** tactics in full or
near-full. The remaining ~138 (Execution, Privilege Escalation, Lateral
Movement, Collection, Command and Control, Exfiltration, Impact, Initial
Access, plus a handful of Persistence/Stealth/Credential Access/Discovery
techniques triaged out of this batch — see below) are a candidate for a
future batch.

## Scoping: what got left out of this batch, and why

Not every technique in the corrected 213-technique gap belongs in a
Splunk-SPL, Windows-Event-Log-based catalogue. Two categories were
deliberately excluded from this batch rather than force-fitted with a
weak, non-actionable search:

1. **Wrong telemetry domain.** A meaningful share of MITRE's Windows-
   platform gap techniques are genuinely network/DNS/proxy techniques
   (Dynamic Resolution, Encrypted Channel, Data Encoding, Non-Application
   Layer Protocol), email-gateway/O365-specific techniques (Email
   Collection, Additional Email Delegate Permissions — these belong with
   the `saas`/`identity-provider` coverage work instead), or
   physical/hardware-layer techniques (Exfiltration Over Bluetooth/
   Physical Medium, Firmware Corruption, Hardware Supply Chain
   Compromise) that a Windows Event Log/Sysmon-based catalogue has no
   real signal for. MITRE tags these "Windows" because a Windows host is
   often the actor, not because Windows endpoint logs are where you'd
   catch them.
2. **Too weak a log signal for a real search.** A handful of Stealth
   sub-techniques (static-analysis-level file obfuscation like
   Steganography, Polymorphic Code, Junk Code Insertion, Invisible
   Unicode; or EDR-API-level behaviors like Process Argument Spoofing
   and Mutual Exclusion mutex checks) fundamentally require byte-level
   static analysis or raw API telemetry that standard Windows Event Log
   /Sysmon fields don't expose. Writing SPL against a log source that
   doesn't carry the needed signal would produce a search that looks
   like coverage but never fires — worse than no entry at all.

This is the same "verify genuine telemetry scope before claiming
coverage" discipline this library has applied to every platform-coverage
batch this session (SaaS, Identity Provider, Containers) — just applied
here to detection *authoring* rather than to a coverage cross-reference.

## Methodology

1. **Start from the corrected diff, not a blank page.** Every candidate
   technique came from the corrected `data/mitre-attack-windows.json`'s
   `covered_by_library: false` list, filtered to `has_platform_analytic:
   true`, then further filtered to the Persistence/Credential
   Access/Discovery/Stealth/Defense Impairment tactics with genuine
   Windows-log-based signal (see Scoping above).
2. **One entry per technique.** No technique got more than one detection
   and no detection covers more than one technique — a clean 1:1 mapping
   that keeps `covered_by_library` accounting exact when the coverage
   file is regenerated against this catalogue.
3. **Detection logic follows MITRE's own analytic description**, not an
   independent guess — each entry's `detection_logic` field says which
   analytic it's grounded in.
4. **Single component**: `"Windows Endpoint"` — this catalogue's whole
   scope is generic Windows OS endpoint telemetry, the same domain as
   ESCU's `"Windows Endpoint"` component, whose gap it closes.
5. **Namespace**: `WEND-<TAC>-###`, one namespace per primary MITRE
   tactic — the same fifteen-namespace convention the Splunk ESCU and
   Cisco catalogues use.
6. **Severity/confidence/risk scoring** follow this library's derived
   model — `detection_type` (TTP/Anomaly/Correlation, inferred from the
   SPL's own structure) sets a severity/confidence baseline, then
   severity gets a bump for Credential Access and Defense Impairment
   (the two tactics in this batch where the individual action is
   inherently high-stakes), plus keyword-triggered bumps for LSASS
   access, ransomware/wiper indicators, root-store tampering, firewall
   disablement, and code-integrity disablement.

## Namespace coverage matrix

| Namespace | Primary MITRE tactic | Detections |
|---|---|---:|
| `WEND-PERSIST-###` | Persistence | 26 |
| `WEND-STEALTH-###` | Stealth (TA0005) | 18 |
| `WEND-DISC-###` | Discovery | 13 |
| `WEND-CRED-###` | Credential Access | 9 |
| `WEND-IMPAIR-###` | Defense Impairment (TA0112) | 7 |
| **Total** | | **73** |

`Persistence` dominates because Windows offers an unusually large number
of distinct, individually-obscure autostart/hook mechanisms (Office
template macros, Outlook forms/rules/add-ins, Winlogon helper DLLs,
AppInit_DLLs, authentication packages, network provider DLLs, netsh
helper DLLs) — each one is its own MITRE sub-technique with its own
Detection Analytic, unlike, say, Discovery, where several closely-related
enumeration behaviors (device, driver, VM, locale checks) still only add
up to a baker's dozen.

## Component

| Component | Detections |
|---|---:|
| Windows Endpoint | 73 |

## Severity, confidence, and false positives

| Severity | Count | | Confidence | Count | | FP Rating | Count |
|---|---:|---|---|---:|---|---|---:|
| Medium | 51 | | High | 68 | | Low | 26 |
| High | 12 | | Medium | 5 | | Medium | 37 |
| Critical | 7 | | | | | High | 10 |
| Low | 3 | | | | | | |

Confidence skews heavily `high` because every entry is grounded in a
named, official MITRE Detection Analytic rather than an independently
invented heuristic. FP rating skews `Medium` more than this library's
other MITRE-gap-fill batches (Cisco skewed `Low`) — a direct consequence
of this batch's Discovery and generic-process-behavior entries (window
enumeration, browser-file access, device/driver queries), which overlap
more with legitimate administrative and troubleshooting activity than
config-change or credential-theft detections do.

## Detection type and search cost

| Type | Count | | Search cost | Count |
|---|---:|---|---|---:|
| TTP | 65 | | Low cost | 61 |
| Anomaly | 5 | | Medium cost | 12 |
| Correlation | 3 | | | |

`Low cost` dominates because most searches are single-event-source
lookups against Sysmon/Security-log fields (a specific `EventCode` plus a
`TargetObject`/`Image` filter) rather than multi-source joins — Windows
Event Log telemetry is comparatively cheap and well-indexed for this
class of technique-specific pattern matching, unlike, say, the Cisco
batch's config-change-then-traffic-pattern correlations.

## Telemetry requirements

| Requirement | Count | Meaning |
|---|---:|---|
| Essential | 73 | Every entry in this batch relies on Sysmon or the native Windows Security Event Log — telemetry any properly-instrumented Windows endpoint fleet already collects, once Sysmon is deployed with a reasonably complete configuration. |

## Risk scoring reference

`score = severity(1-5) × confidence(1-5) × impact(1-5)`, max 125.

| Score band | Count | Interpretation |
|---|---:|---|
| 100–125 | 2 | Page immediately / Tier 1 candidate |
| 60–99 | 13 | Investigate same business day |
| 30–59 | 42 | Queue for triage / hunting |
| < 30 | 16 | Enrichment / context-only |

## Named threat cross-reference

One entry cites a specific, MITRE-documented threat in its
`threat_reference` field, verified against that object's own MITRE
`uses` relationship to the technique (not inferred from the technique
name alone). The rest of this batch's candidate attributions (APT19 for
Office Test-key persistence, Kimsuky for AppInit_DLLs, FIN13 for
create-then-delete persistence cleanup) were checked against the STIX
corpus and **could not be verified** as a direct `uses` relationship for
this specific technique, so they were left uncited rather than asserted
— consistent with this library's standing rule that a `threat_reference`
requires verification, not plausibility.

| Detection | Technique | Threat |
|---|---|---|
| `WEND-IMPAIR-002` — Newly-Created Code-Signing Certificate Used to Sign a Binary Within Minutes | T1553.002 Code Signing | **Bazar** (S0534) |

## SPL notes

Every entry's `spl` is hand-authored for this project against plain
Sysmon/Windows Security Event Log field names (`Image`, `CommandLine`,
`TargetObject`, `TargetFilename`, `EventCode`) in the same raw
event-search style as the AD/RDP/DHCP catalogues — not the Splunk ESCU
app's `tstats`/CIM-data-model/`security_content_*` macro conventions,
since this catalogue doesn't depend on that app. `tuning_guidance` on
every entry says explicitly to adapt sourcetypes and field names to
whichever Windows Event Log forwarding pipeline is actually deployed
(Splunk Add-on for Microsoft Windows, the Sysmon TA, or equivalent), and
names the specific reference lookup table(s) a search depends on
(`approved_office_addins`, `managed_extension_allowlist`,
`security_product_processes`, etc.) so they can be populated before
deployment.

## Attribution and license

This catalogue's detection logic is this project's own, but its scope
and grounding are directly downstream of MITRE ATT&CK's own STIX corpus
([mitre/cti](https://github.com/mitre/cti), Apache-2.0-licensed on
`mitre-attack`, CC-BY-4.0 on ATT&CK-name content) — every entry's
`mitre_analytics[]` and `references[]` cite the exact Detection Analytic
and technique page it's built from. `data/mitre-attack-windows.json`
remains the live source of truth for what's covered and what isn't;
regenerate it and re-diff after a future MITRE ATT&CK release, or after a
future batch closes more of the remaining ~138-technique gap.

---

*Generated from `data/windows-endpoint-detections.json` (73 entries),
diffed against the corrected `data/mitre-attack-windows.json` as of
2026-08-20. Regenerate the coverage file and re-run the diff after a
future MITRE ATT&CK release or after adding more Windows-scoped
content — the gap is a live comparison, not a permanent list.*
