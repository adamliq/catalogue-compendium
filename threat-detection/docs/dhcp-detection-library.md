# Windows DHCP Server Threat Detection Library — Summary & Priority Packs

Companion index to `data/dhcp-detections.json` (169 Splunk SPL detections
across Windows DHCP Server core operation, AD authorization, audit-log
integrity, DNS/gateway/route/PXE option redirection, failover, rogue-DHCP
network telemetry, DHCPv6, dynamic DNS, PowerShell administration, and
8 `DHCP-X-###` cross-platform correlations).

Every detection ID below is a stable reference into
`data/dhcp-detections.json` — look it up by `id` for the full SPL,
investigation steps, and response guidance.

## Scope note

The specification asked for "at least 250" detections and named DHCP as
critical network identity/configuration infrastructure, singling out
**DNS option redirection, default-gateway redirection, static-route
injection, PXE boot-server/file redirection, DHCP authorization tampering,
audit-log impairment, failover abuse, rogue DHCP servers, and DHCP
starvation** as the highest-value attack surface. This catalogue ships
**169**: every entry is a distinct, fully-detailed detection with real
SPL and MITRE ATT&CK IDs validated against the current ATT&CK STIX
corpus, and no fabricated DHCP audit event IDs, Windows Event IDs, or
Microsoft field names. As with the Red Hat, Fortinet, iDRAC, and iLO
catalogues, padding to 250 would have meant duplicating detections or
inventing telemetry. Every one of the specification's named highest-value
patterns has dedicated, full-depth coverage (see §9); remaining breadth
(exhaustive per-vendor switch DHCP-snooping syntax, NAC-vendor-specific
integration depth) is covered at a representative level, extendable in
future batches.

### On ATT&CK mapping for DHCP-specific behavior

Per the specification's own instruction, ATT&CK does not map cleanly onto
several DHCP-specific behaviors. Three notable cases in this catalogue:

- **DHCP option redirection (DNS/gateway/route)** uses `T1557`
  (Adversary-in-the-Middle) as the closest fit — DHCP option poisoning is
  functionally an AiTM technique even though it operates at the
  configuration-management layer rather than the wire.
- **Rogue DHCP servers** use the ATT&CK sub-technique built specifically
  for this: `T1557.003` (DHCP Spoofing).
- **PXE boot-server/file redirection** uses `T1542` (Pre-OS Boot) as the
  closest fit, per the same rationale used in the iDRAC/iLO catalogues.

No entries required an `attack_mapping_note` override for an unvalidated
technique ID in this catalogue (unlike the iLO catalogue's `T1562`
substitution) — every technique cited here was already present in the
validated MITRE technique cache.

---

## 1. Namespace coverage matrix

| Namespace | Scope | Detections |
|---|---|---:|
| `DHCP-###` | Core: service security, scopes, address pools, exclusions, reservations, options (DNS/gateway/route/PXE), policies, filters, lease behavior/starvation, decline/NACK abuse, DHCPv6, process execution, remote admin, registry, database/backup, behavioral, fleet-wide, destructive | 100 |
| `DHCP-DNS-###` | DNS option redirection + dynamic DNS updates + update credential security | 12 |
| `DHCP-FO-###` | DHCP failover | 12 |
| `DHCP-NET-###` | Rogue DHCP, spoofing/MITM, snooping, relay, NAC correlation | 11 |
| `DHCP-PS-###` | PowerShell administration + netsh dhcp | 10 |
| `DHCP-AD-###` | Active Directory server authorization | 9 |
| `DHCP-AUD-###` | DHCP audit-logging tampering / anti-forensics | 9 |
| `DHCP-X-###` | Cross-platform correlation | 6 |
| **Total** | | **169** |

## 2. Detection by component

| Component | Count | Component | Count |
|---|---:|---|---:|
| DHCP service | 28 | DNS dynamic update | 9 |
| Option | 20 | DHCPv6 | 6 |
| DHCPv4 | 18 | Policy | 5 |
| DHCP relay | 13 | Filter | 4 |
| DHCP scope | 12 | Registry | 2 |
| Reservation | 12 | | |
| Failover | 12 | | |
| PowerShell | 10 | | |
| Server authorization | 9 | | |
| DHCP audit logging | 9 | | |

## 3. Severity and confidence

| Severity | Count | | Confidence | Count |
|---|---:|---|---|---:|
| High | 62 | | Medium | 107 |
| Medium | 49 | | High | 52 |
| Critical | 45 | | Low | 10 |
| Low | 13 | | | |

## 4. Detection type and maturity

| Type | Count | | Maturity | Count |
|---|---:|---|---|---:|
| Atomic | 79 | | Level 1 — simple indicator | 70 |
| Anomaly | 36 | | Level 2 — threshold | 49 |
| Threshold | 33 | | Level 3 — behavioral | 31 |
| Sequence | 10 | | Level 4 — correlation | 8 |
| Correlation | 10 | | Level 5 — multi-source sequence | 11 |
| Behavioral | 1 | | | |

All 6 `DHCP-X-###` correlations are Level 5, plus 5 additional Level-5
sequences elsewhere in the catalogue (e.g. `DHCP-DNS-007`'s critical
DNS-overwrite behavioral check chained with corroborating detections).

## 5. False positive rating and telemetry requirement

| FP Rating | Count | | Telemetry | Count |
|---|---:|---|---|---:|
| Medium | 94 | | Recommended | 96 |
| Low | 59 | | Optional | 43 |
| High | 16 | | Essential | 30 |

## 6. CIM coverage

**93% CIM-compatible (158 / 169).** The 11 non-CIM entries are network
protocol-level or cross-source correlation searches (bad-address-table
analysis, snooping-binding-table comparison) that don't map cleanly onto
a single Splunk CIM data model. Of the CIM-mapped entries, concentrated
in `Change` (configuration integrity — the majority of the catalogue) and
`Network_Traffic` (lease/protocol-level behavioral and starvation
detections).

## 7. Risk scoring reference

`score = severity(1-5) × confidence(1-5) × impact(1-5)`, max 125.

| Score band | Count | Interpretation |
|---|---:|---|
| 100–125 | 51 | Page immediately / Tier 1 candidate |
| 60–99 | 18 | Investigate same business day |
| 30–59 | 49 | Queue for triage / hunting |
| < 30 | 51 | Enrichment / context-only |

---

## 8. Priority Detection Packs

### Tier 1 — Critical DHCP Detections (40 detections)

Critical severity **and** high confidence **and** Low false-positive
rating — within the specification's requested 30–50 range.

| ID | Title | Risk score |
|---|---|---:|
| DHCP-AD-008 | Privileged AD Change Immediately Followed by DHCP Authorization | 125 |
| DHCP-006 | DHCP Server Service Binary Path Changed | 125 |
| DHCP-AUD-008 | DHCP Activity Continues While Audit Telemetry Disappears | 125 |
| DHCP-011 | Multiple DHCP Scopes Disabled at Once | 125 |
| DHCP-012 | Bulk DHCP Scope Deletion | 125 |
| DHCP-DNS-001 | DHCP DNS Server Option (006) Changed | 125 |
| DHCP-DNS-002 | DHCP DNS Server Option Changed Across Multiple Scopes | 125 |
| DHCP-033 | DHCP Default Gateway Option (003) Changed | 125 |
| DHCP-034 | DHCP Gateway Changed to Endpoint-Class Address | 125 |
| DHCP-035 | Same New Gateway Pushed Across Multiple Scopes | 125 |
| DHCP-038 | New Default Route Injected via DHCP Static Route Option | 125 |
| DHCP-NET-001 | DHCP OFFER from Unapproved Server | 125 |
| DHCP-PS-005 | DNS or Gateway Option Changed via PowerShell | 125 |
| DHCP-097 | Coordinated DHCP Service Stop or Audit Logging Disable Across Fleet | 125 |
| DHCP-098 | Bulk Scope/Reservation/Exclusion Destruction Sequence | 125 |
| DHCP-X-001 | AD Privilege Escalation Leading to DHCP Manipulation | 125 |
| DHCP-X-002 | DHCP DNS Redirection Followed by Client Resolution Shift | 125 |
| DHCP-X-003 | DHCP Gateway Poisoning Followed by New Next-Hop Traffic | 125 |
| DHCP-X-005 | Rogue DHCP Compromise Chain: OFFER to Client ACK to Rogue DNS/Gateway Use | 125 |
| DHCP-X-006 | DHCP Starvation Leading to Legitimate Client Failure | 125 |
| DHCP-AUD-001 | DHCP Audit Logging Disabled | 100 |
| DHCP-036 | DHCP Classless Static Route Option (121/249) Created or Modified | 100 |
| DHCP-037 | DHCP Static Route Targets Identity or Security Infrastructure | 100 |
| DHCP-040 | DHCP PXE Boot Server Option (066) Changed | 100 |
| DHCP-041 | DHCP PXE Boot Filename Option (067) Changed | 100 |
| DHCP-FO-002 | DHCP Failover Partner Changed | 100 |
| DHCP-FO-010 | Manual DHCP Failover State Transition Forced | 100 |
| DHCP-061 | Multiple Scopes Exhausted Simultaneously | 100 |
| DHCP-NET-007 | DHCP Snooping Violation: OFFER/ACK on Untrusted Switch Port | 100 |
| DHCP-064 | Competing DHCP OFFERs with Conflicting Gateway/DNS Values | 100 |
| DHCP-074 | DHCPv6 DNS Server Option Changed | 100 |
| DHCP-DNS-007 | DHCP DNS Update Unexpectedly Overwrites Critical Hostname | 100 |
| DHCP-PS-003 | Encoded PowerShell Command Manipulating DHCP | 100 |
| DHCP-PS-006 | PXE Boot Options Changed via PowerShell | 100 |
| DHCP-PS-008 | DHCP Server Authorization/Deauthorization via PowerShell | 100 |
| DHCP-NET-010 | DHCP Relay Target (Helper Address) Changed | 100 |
| DHCP-096 | Same New DHCP Option Value Pushed Across Fleet | 100 |
| DHCP-099 | DHCP/Gateway/DNS Option Poisoning Immediately Preceding Server Reboot | 100 |
| DHCP-X-004 | PXE Compromise Chain: Option Change to Boot to Provisioning Activity | 100 |
| DHCP-AUD-004 | DHCP Audit Log File Deleted | 80 |

### Themed packs

| Pack | Focus |
|---|---|
| **DHCP Infrastructure Protection Pack** | Service security (`DHCP-001` to `DHCP-008`), server authorization (`DHCP-AD-###`), registry tampering |
| **DHCP Option Poisoning Pack** | DNS (`DHCP-DNS-001` to `004`), gateway (`DHCP-033` to `035`), route injection (`DHCP-036` to `039`), PXE (`DHCP-040` to `044`), policy-based option assignment (`DHCP-046`, `DHCP-047`) |
| **Rogue DHCP Detection Pack** | All `DHCP-NET-###` network-telemetry-dependent detections plus `DHCP-AD-006` |
| **DHCP Starvation / DoS Pack** | `DHCP-054` through `DHCP-063`, decline/NACK abuse (`DHCP-066` to `072`) |
| **DHCP Failover Protection Pack** | All `DHCP-FO-###` |
| **DHCP-DNS Security Pack** | All `DHCP-DNS-###` (option redirection + dynamic update integrity + credential security) |
| **PXE / Boot Security Pack** | `DHCP-040` to `044`, `DHCP-PS-006`, `DHCP-X-004` |
| **Administrative Abuse Pack** | All `DHCP-PS-###`, remote-admin (`DHCP-078` to `083`), fleet-wide (`DHCP-095` to `097`) |
| **Anti-Forensics Pack** | All `DHCP-AUD-###`, `DHCP-069`, `DHCP-084`, `DHCP-089` |

---

## 9. Coverage of the explicitly-prioritized attack patterns

| Prioritized pattern | Detection(s) |
|---|---|
| DHCP authorization change | DHCP-AD-001, DHCP-AD-002, DHCP-AD-008 |
| DNS option changed | DHCP-DNS-001, DHCP-DNS-002, DHCP-PS-005 |
| Gateway option changed | DHCP-033, DHCP-034, DHCP-035, DHCP-PS-005 |
| Route option changed | DHCP-036, DHCP-037, DHCP-038 |
| PXE boot server/file changed | DHCP-040, DHCP-041, DHCP-PS-006 |
| Failover partner changed | DHCP-FO-002, DHCP-FO-010 |
| Audit logging disabled | DHCP-AUD-001, DHCP-AUD-008 |
| Service disabled | DHCP-001, DHCP-097 |
| Rogue DHCP server | DHCP-NET-001, DHCP-NET-003, DHCP-NET-007 |
| DHCP starvation | DHCP-058, DHCP-059, DHCP-060, DHCP-X-006 |
| DHCP admin privilege change | DHCP-AD-009, DHCP-X-001 |
| Bulk scope deletion | DHCP-012 |
| Bulk scope disable | DHCP-011 |
| Dynamic DNS abuse | DHCP-DNS-007, DHCP-DNS-009, DHCP-DNS-011 |

## 10. Detection gap analysis

- **Visible in the Windows DHCP audit log**: the large majority of this
  catalogue — service state, scopes, pools, exclusions, reservations,
  options, policies, filters, failover, most authorization events.
- **Visible only in Windows Event Log channels beyond the DHCP audit
  log**: service-binary/account/permission tampering (System/Security),
  PowerShell-scripted administration (PowerShell Operational), and
  process-level watch-list activity (Security 4688/Sysmon) — a deployment
  ingesting only the DHCP audit log will miss all `DHCP-PS-###` and
  process-execution detections entirely.
- **Visible only through network telemetry**: rogue-DHCP detection
  (`DHCP-NET-###`) is explicitly *not* reliably achievable from Windows
  DHCP Server logs alone — a server has no visibility into a rogue
  server's OFFERs unless it loses the race or the rogue server is later
  reported. Zeek/Suricata/DHCP-snooping telemetry is required for
  high-confidence rogue-server and MITM detection.
- **Requiring switch-level DHCP snooping**: `DHCP-NET-007`/`DHCP-NET-008`
  depend on switch DHCP snooping specifically and cannot be produced from
  any server-side or generic network-tap telemetry.
- **Requiring NAC integration**: `DHCP-NET-011` requires an integrated
  Network Access Control system's per-port authentication records.
- **Requiring DNS Server logs**: the dynamic-DNS-update detections
  (`DHCP-DNS-006` through `012`) need DNS zone/audit data in addition to
  the DHCP audit log to confirm what the update actually did to the zone.
- **Requiring registry/Sysmon auditing**: `DHCP-084`/`DHCP-085` depend on
  Sysmon registry-event auditing scoped to the DHCP Server configuration
  hive, which is not enabled by default and whose exact path is
  version-dependent — validate against the deployed Windows Server
  version before relying on these two entries.
- **Requiring identity-provider/AD telemetry**: `DHCP-AD-###` and
  `DHCP-X-001` depend on Active Directory audit logging in addition to
  DHCP telemetry.
- **Activity impossible to attribute to an administrator without Windows
  auditing**: any change made directly via registry/database file
  manipulation while Windows Security auditing is disabled will not
  attribute to an account at all — this is a fundamental limitation, not
  a gap this catalogue can close with SPL alone.

**DHCP logs do not provide OS process telemetry beyond the DHCP server
itself.** Every claim in this catalogue that needs endpoint-level
attribution on a *client* (e.g. confirming a PXE-booted device actually
ran attacker-controlled provisioning) explicitly depends on endpoint
telemetry from that client (`DHCP-X-004`) — DHCP server logs alone can
tell you a boot sequence occurred, never what happened on the client
afterward.

---

*Generated from `data/dhcp-detections.json` (169 entries). Regenerate
these tables after any future batch adds or edits detections — the counts
above are a snapshot, not a live query.*
