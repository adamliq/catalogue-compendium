# Cisco Network Device Threat Detection Library

Companion index to `data/cisco-detections.json` (62 Splunk SPL detections).
This is this library's thirteenth catalogue, and — like the ESXi/Splunk,
Red Hat, Fortinet, Dell iDRAC, HPE iLO, Windows DHCP/RDP, VCF, Splunk
Platform, and Active Directory catalogues before it — authored for this
project rather than sourced from a single upstream project. What sets it
apart from most of those is its methodology: every entry here exists
specifically to close a gap this library already knew about.

## Why this catalogue exists

Earlier work in this session built [`data/mitre-attack-cisco.json`](../data/mitre-attack-cisco.json)
— every technique MITRE ATT&CK scopes to its **`Network Devices`**
platform (the ATT&CK platform value that covers Cisco IOS/IOS XE/ASA/FTD
router, switch, and firewall techniques; MITRE does not define a separate
"Cisco" platform), cross-referenced against this library's existing
70-entry Cisco-scoped ESCU content (`component: "Cisco Network"`, `"Cisco
ASA"`, `"Cisco IOS XE"`, `"Cisco SD-WAN"`). That comparison found:

- **100 techniques** MITRE scopes to the Network Devices platform
- **32 already covered** by this library's Cisco ESCU content
- **68 uncovered**, of which **62 have a real, official MITRE Detection
  Analytic** — concrete log-source guidance, not just a bare technique
  name — the same kind of grounding this library used once before for
  the original ESXi catalogue's MITRE-driven gap-fill batch

This catalogue is those 62. Every entry's `mitre_analytics[]` field cites
the specific MITRE Detection Analytic ID it's built from, and the SPL,
data sources, and detection logic are written to match what that analytic
actually describes — not invented independently of it.

**A subset is grounded in more than an abstract technique, too.** While
researching the gap, four real, MITRE-documented Cisco-targeting threats
turned up in the STIX corpus's malware/campaign objects — objects that
exist independently of, and predate, this catalogue's own construction:

- **SYNful Knock** (`S0519`) — the covert Cisco IOS firmware implant
  first documented publicly in 2015, still the canonical reference case
  for image-patching persistence on Cisco routers.
- **ArcaneDoor** (`C0046`) and its associated malware **Line Dancer**
  (`S1186`, a memory-only Lua shellcode loader) and **Line Runner**
  (`S1188`, a persistent web-shell backdoor) — a 2023–24 campaign that
  targeted Cisco ASA/FTD devices specifically.
- **Salt Typhoon**'s **JumbledPath** (`S1206`) — a custom Go-based
  utility the PRC state actor used to obscure the true source of its
  network-device-focused operations. (Salt Typhoon itself is already a
  well-represented `analytic_story` tag across this library's ESCU
  catalogue; JumbledPath is the specific tool within that campaign this
  catalogue adds coverage for.)
- **KV Botnet Activity** (`C0035`) — a campaign against end-of-life
  SOHO/edge network equipment.

Twelve of the 62 entries cite one of these directly, verified against
each object's own MITRE `uses` relationship to the technique in question
(not asserted from the technique name alone) — see the cross-reference
table below.

## Methodology

1. **Start from the diff, not a blank page.** Every candidate technique
   came from `data/mitre-attack-cisco.json`'s `covered_by_library: false`
   list, filtered to `has_platform_analytic: true` (a real MITRE Detection
   Analytic exists to ground the entry in).
2. **One entry per technique.** No technique got more than one detection
   and no detection covers more than one technique — a clean 1:1 mapping
   that keeps `covered_by_library` accounting exact when the coverage file
   is regenerated against this catalogue.
3. **Detection logic follows MITRE's own analytic description**, not an
   independent guess — each entry's `detection_logic` field says which
   analytic it's grounded in, and the SPL's approach (what to look for,
   what log source, what correlation) matches what that analytic
   describes.
4. **Component split by device/feature area**: `"Cisco IOS/IOS XE"` for
   router/switch firmware-and-boot-specific techniques (ROMMON, boot
   images, flash/NVRAM), `"Cisco ASA/FTD"` for firewall-specific
   techniques (including the ArcaneDoor-relevant ones), `"Cisco Network
   Device"` for behavior that applies across the device family (AAA/
   TACACS+, SNMP, generic CLI/config, C2 traffic patterns).
5. **Namespace**: `CSCO-<TAC>-###`, one namespace per primary MITRE
   tactic — the same fifteen-namespace convention the Splunk ESCU
   catalogue uses, chosen for consistency rather than inventing a new
   scheme. Primary tactic is the first tactic (in MITRE's own tactic
   ordering) among the technique's full tactic list, for the handful of
   techniques MITRE maps to more than one.
6. **Severity/confidence/risk scoring** follow this library's derived
   model (not copied from anywhere) — `detection_type` (TTP/Anomaly/
   Correlation, inferred from the SPL's own structure: multi-event `join`/
   `transaction` searches are `Correlation`, statistical searches using
   `stdev`/entropy/time-bucketing are `Anomaly`, everything else is
   `TTP`) sets a severity/confidence baseline, then severity gets a bump
   for tactics where the individual action is inherently high-stakes
   (Credential Access, Impact, Lateral Movement, Privilege Escalation,
   Defense Impairment, Initial Access) — the same rule this library's
   other derived-scoring catalogues use.

## Namespace coverage matrix

| Namespace | Primary MITRE tactic | Detections |
|---|---|---:|
| `CSCO-IMPAIR-###` | Defense Impairment (TA0112) | 11 |
| `CSCO-PERSIST-###` | Persistence | 9 |
| `CSCO-C2-###` | Command and Control | 9 |
| `CSCO-DISC-###` | Discovery | 6 |
| `CSCO-CRED-###` | Credential Access | 6 |
| `CSCO-IMPACT-###` | Impact | 6 |
| `CSCO-STEALTH-###` | Stealth (TA0005) | 5 |
| `CSCO-EXEC-###` | Execution | 4 |
| `CSCO-COLL-###` | Collection | 3 |
| `CSCO-INIT-###` | Initial Access | 2 |
| `CSCO-EXFIL-###` | Exfiltration | 1 |
| **Total** | | **62** |

`Defense Impairment`, `Persistence`, and `Command and Control` lead the
pack — reflecting where MITRE's own Network Devices analytic coverage is
richest: firmware/image/crypto tampering (impairment), boot-persistence
mechanisms unique to embedded network-device firmware (ROMMON, TFTP
netbooting), and the C2-channel-blending techniques (DNS, pub/sub,
non-standard-port tunneling) that apply to a device sitting directly on
the network path.

## Component

| Component | Detections |
|---|---:|
| Cisco Network Device (generic/cross-model) | 38 |
| Cisco IOS/IOS XE | 17 |
| Cisco ASA/FTD | 7 |

## Severity, confidence, and false positives

| Severity | Count | | Confidence | Count | | FP Rating | Count |
|---|---:|---|---|---:|---|---|---:|
| Medium | 26 | | High | 58 | | Low | 30 |
| High | 26 | | Medium | 4 | | Medium | 27 |
| Critical | 7 | | | | | High | 5 |
| Low | 3 | | | | | | |

Confidence skews heavily `high` because every entry is grounded in a
named, official MITRE Detection Analytic rather than an independently
invented heuristic. False-positive rating skews toward `Low`/`Medium`
rather than `High` — discovery/enumeration-style searches (the ones most
prone to legitimate administrative noise) are a minority of this batch
compared to the config-change, firmware-integrity, and destructive-command
detections that dominate it.

## Detection type and search cost

| Type | Count | | Search cost | Count |
|---|---:|---|---|---:|
| TTP | 42 | | Medium cost | 41 |
| Correlation | 16 | | Low cost | 17 |
| Anomaly | 4 | | High cost | 4 |

`Correlation` is unusually well-represented for a catalogue this size (16
of 62, roughly a quarter — well above the small minority share it
typically holds in this library's other catalogues) — a direct
consequence of MITRE's own analytics for
this platform frequently describing multi-step patterns (discovery
command *then* configuration change, privileged login *then* destructive
command, port-knock probe *then* service enablement) rather than a single
atomic event. `Medium cost` dominates because most searches read raw
`cisco:ios`/`cisco:asa` syslog or NetFlow rather than an accelerated CIM
data model — Cisco network-device telemetry doesn't map onto Splunk's CIM
the way Windows/Linux endpoint telemetry does, the same structural reason
this library's ESCU cloud and second-application batches skew `Medium
cost` too.

## Telemetry requirements

| Requirement | Count | Meaning |
|---|---:|---|
| Essential | 51 | Relies on standard Cisco IOS/ASA syslog, CLI/AAA command-accounting logs, or configuration-change logging — telemetry any properly-configured Cisco network device already emits. |
| Recommended | 11 | Relies on NetFlow/IPFIX, network-sensor flow data, or a wireless controller's WIDS/WIPS log — telemetry that requires an additional sensor or feature enablement (flow export, wireless intrusion detection) beyond baseline device logging. |

## Risk scoring reference

`score = severity(1-5) × confidence(1-5) × impact(1-5)`, max 125.

| Score band | Count | Interpretation |
|---|---:|---|
| 100–125 | 5 | Page immediately / Tier 1 candidate |
| 60–99 | 20 | Investigate same business day |
| 30–59 | 30 | Queue for triage / hunting |
| < 30 | 7 | Enrichment / context-only |

## Named threat cross-references

Twelve entries cite a specific, MITRE-documented Cisco-targeting
malware family or campaign in their `threat_reference` field —
verified against that object's own MITRE `uses` relationship to the
technique, not inferred from the technique name alone:

| Detection | Technique | Threat |
|---|---|---|
| `CSCO-PERSIST-004` — Port-Knock / SYNful-Knock-Style Probe Pattern | T1205 Traffic Signaling | **SYNful Knock** (S0519) |
| `CSCO-IMPAIR-007` — System Image Patch Indicators | T1601.001 Patch System Image | **SYNful Knock** (S0519) |
| `CSCO-PERSIST-001` — Startup-Config Modified to Add Boot-Time Execution | T1037 Boot or Logon Initialization Scripts | **ArcaneDoor** (C0046) |
| `CSCO-IMPAIR-011` — Session History Logging Disabled | T1690 Prevent Command History Logging | **ArcaneDoor / Line Dancer** (S1186) |
| `CSCO-EXEC-002` — Anomalous Privileged CLI Session via Remote SSH/Telnet | T1059.008 Network Device CLI | **ArcaneDoor / Line Dancer** (S1186) |
| `CSCO-EXEC-003` — Embedded Lua Interpreter Execution | T1059.011 Lua | **ArcaneDoor / Line Runner** (S1188) |
| `CSCO-C2-009` — Encrypted Tunnel/Proxy Traffic to a Non-Standard Destination | T1665 Hide Infrastructure | **Salt Typhoon / JumbledPath** (S1206) |
| `CSCO-DISC-003` — Process/Task Enumeration (Embedded-Linux Discovery) | T1057 Process Discovery | **KV Botnet Activity** (C0035) |
| `CSCO-C2-006` — Non-Standard Port/Protocol Pairing or ICMP Tunneling | T1095 Non-Application Layer Protocol | **KV Botnet Activity** (C0035) |
| `CSCO-EXEC-001` — Unix/Embedded-Linux Shell Invocation | T1059.004 Unix Shell | **KV Botnet Activity** (C0035) |
| `CSCO-DISC-004` — File/Directory Discovery Commands | T1083 File and Directory Discovery | **KV Botnet Activity** (C0035) |
| `CSCO-C2-007` — Unusual TLS-Like Traffic Tunnel | T1573 Encrypted Channel | **KV Botnet Activity** (C0035) |

Filter `data/cisco-detections.json` on `threat_reference.name` to pull
every detection relevant to one of these threats specifically.

## SPL notes

Every entry's `spl` is hand-authored for this project, grounded in
publicly documented Cisco IOS/ASA syslog conventions (`%FACILITY-
SEVERITY-MNEMONIC`-style messages, TACACS+/AAA command accounting) and
common Splunk Cisco add-on sourcetype conventions (`cisco:ios`,
`cisco:asa`), not sourced from or claiming to be any specific vendor's
production content. `tuning_guidance` on every entry says explicitly to
adapt sourcetypes and field names to whichever Cisco TA or
syslog-forwarding pipeline is actually deployed, and names the specific
reference lookup table(s) (e.g. `approved_admin_lookup`,
`maintenance_windows`) a search depends on so they can be populated
before deployment — several searches reference an allowlist/baseline
lookup rather than hardcoding thresholds, since "what's an approved
management subnet/account" is inherently environment-specific.

## Attribution and license

This catalogue's detection logic is this project's own, but its scope and
grounding are directly downstream of MITRE ATT&CK's own STIX corpus
([mitre/cti](https://github.com/mitre/cti), Apache-2.0-licensed on
`mitre-attack`, CC-BY-4.0 on ATT&CK-name content) — every entry's
`mitre_analytics[]` and `references[]` cite the exact Detection Analytic
and technique page it's built from, and `threat_reference` cites the
exact campaign/malware object where applicable. `data/mitre-attack-
cisco.json` remains the live source of truth for what's covered and
what isn't; regenerate it and re-diff after a future MITRE ATT&CK release
to find the next gap.

---

*Generated from `data/cisco-detections.json` (62 entries), diffed against
`data/mitre-attack-cisco.json` as of 2026-08-19. Regenerate the coverage
file and re-run the diff after a future MITRE ATT&CK release or after
adding more Cisco ESCU content — the gap is a live comparison, not a
permanent list.*
