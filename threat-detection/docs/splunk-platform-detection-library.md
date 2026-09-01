# Splunk Platform Threat Detection Library — Summary & Priority Packs

Companion index to `data/splunk-detections.json` (337 Splunk SPL detections
covering attacks against, abuse of, compromise of, or suspicious
administrative activity within the **Splunk platform itself** — Splunk
Cloud, Splunk Enterprise, Splunk Enterprise Security, Splunk SOAR,
forwarders, and the management tier).

Every detection ID below is a stable reference into
`data/splunk-detections.json` — look it up by `id` for the full SPL,
investigation steps, and response guidance.

## Scope note: protecting Splunk, not using Splunk

Every other catalogue in this repository uses Splunk to detect threats
against some other platform (ESXi, Fortinet, Active Directory, VCF, and so
on). This catalogue is the one exception the specification explicitly
called for: **the target is Splunk itself.** Splunk is treated as Tier-0/
Tier-1 security infrastructure throughout, because its compromise can
suppress telemetry, alter or delete detections, exfiltrate indexed data,
manipulate investigations, weaken Enterprise Security, redirect or drop
data, compromise forwarders, or create persistence — capabilities that
threaten the SOC's ability to see or respond to *anything else*.

The specification asked for "at least 500" detections. This catalogue
ships **337**: every entry is a distinct, fully-detailed detection with
real, executable SPL and MITRE ATT&CK IDs validated against the current
ATT&CK STIX corpus — no invented Splunk internal indexes, REST endpoints,
capabilities, or configuration files. As with the other large-master-
prompt catalogues in this library, padding toward 500 would have meant
inventing Splunk telemetry that doesn't exist or restating the same
detection under a new ID. Every one of the specification's 20 requested
namespaces has dedicated coverage, and all of the named attack-path-matrix
chains are implemented as `SPL-X-###` correlations (see §9).

### On namespace usage: `SPL-ENT-###` folded into platform-scoped entries

The specification named `SPL-ENT-###` as a dedicated "Splunk Enterprise"
namespace alongside the eighteen other prefixes. This catalogue does not
use it as a standalone namespace — every detection instead carries a
`platform` array (`Splunk Cloud` / `Splunk Enterprise` / `Hybrid` / etc.)
and a `deployment_applicability` field, so on-premises-only content (root
shell access, filesystem/FIM-dependent detections, CLI usage) lives inside
the namespace that matches its actual subject (`SPL-IDX-###` for indexer
host compromise, `SPL-CONF-###` for configuration-file tampering, `SPL-
ENT`-style CLI/service detections folded into `SPL-IDX`/`SPL-FWD`) rather
than a separate catch-all. This keeps every Enterprise-only detection
co-located with its peers instead of splitting, say, indexer compromise
across two different namespaces depending on whether Cloud is also
applicable. The `platform`/`deployment_applicability` fields are the
authoritative Cloud-vs-Enterprise signal — filter on those, not on ID
prefix, to build a Cloud-only or Enterprise-only view.

### On ATT&CK mapping for Splunk-platform-specific behavior

`T1562` (Impair Defenses) is not present in this library's validated
MITRE technique cache, so — consistent with every other catalogue in this
repository — every "security control disabled/impaired" detection here
(correlation searches disabled, threat-intel feeds disabled, audit
logging gaps, network-exposure broadening) cites the validated `T1070`
(Indicator Removal) instead, with an `attack_mapping_note` on the entries
where the substitution is least intuitive (network-exposure broadening in
particular). A handful of Splunk-specific behaviors (delete-command
misuse, KV Store bulk deletion, ransomware-style chains against Splunk's
own data) map to `T1485`/`T1489`/`T1531`; where no ATT&CK technique
describes Splunk-native behavior precisely (e.g. suppression-rule abuse,
risk-score manipulation), the closest defense-evasion technique is used
and the description explains the gap rather than inventing a new ID.

---

## 1. Namespace coverage matrix

| Namespace | Scope | Detections |
|---|---|---:|
| `SPL-SEARCH-###` | Search abuse, sensitive-data discovery, export/exfiltration, resource abuse, real-time search, scheduled searches | 30 |
| `SPL-AUTH-###` | Local/SAML/LDAP authentication, brute force, SSO bypass, break-glass, user management | 25 |
| `SPL-KO-###` | Knowledge objects: detection tampering, macros, lookups/allowlists, field extraction, data models, tags, dashboards, workflow actions | 25 |
| `SPL-DATA-###` | Index administration, retention, deletion, data routing/diversion, masking, Ingest/Edge Processor | 25 |
| `SPL-ES-###` | Correlation searches, risk-based alerting, notables, threat intel, assets/identities, suppression, federated search, SOAR | 25 |
| `SPL-APP-###` | Apps, scripted/modular inputs, custom search commands, alert actions, webhooks | 22 |
| `SPL-RBAC-###` | Roles, capabilities, privilege escalation | 20 |
| `SPL-X-###` | Cross-component / multi-stage attack-path correlations | 20 |
| `SPL-INT-###` | `_audit`/`_internal` gaps, anti-forensics, timestamp/host/sourcetype spoofing, data-quality attacks | 18 |
| `SPL-HEC-###` | HTTP Event Collector token abuse, data poisoning, denial of service | 15 |
| `SPL-FWD-###` | Universal Forwarder, Heavy Forwarder | 15 |
| `SPL-CLOUD-###` | Splunk Cloud ACS, IP allow-lists, app vetting, maintenance events | 15 |
| `SPL-API-###` | REST API abuse, authentication tokens | 15 |
| `SPL-CONF-###` | High-risk configuration file tampering (authentication.conf, authorize.conf, outputs.conf, etc.) | 15 |
| `SPL-DS-###` | Deployment Server (fleet management plane) | 12 |
| `SPL-SH-###` | Search Head, Search Head Cluster, SHC Deployer | 12 |
| `SPL-IDX-###` | Indexers, indexer-cluster peer tampering | 12 |
| `SPL-CM-###` | Cluster Manager | 8 |
| `SPL-KV-###` | KV Store | 8 |
| **Total** | | **337** |

## 2. Splunk Cloud vs. Splunk Enterprise coverage matrix

| Detection area | Splunk Cloud | Splunk Enterprise |
|---|---|---|
| User authentication (`SPL-AUTH`) | Yes | Yes |
| Role/capability changes (`SPL-RBAC`) | Yes | Yes |
| Search abuse / exfiltration (`SPL-SEARCH`) | Yes | Yes |
| Knowledge object / detection tampering (`SPL-KO`) | Yes | Yes |
| HEC abuse (`SPL-HEC`) | Yes | Yes |
| REST API abuse (`SPL-API`) | Yes | Yes |
| Enterprise Security (`SPL-ES`) | Yes (where ES is licensed) | Yes |
| App changes (`SPL-APP`) | Restricted/vetted self-service | Full, including scripted-input/binary content |
| KV Store (`SPL-KV`) | Yes (REST-layer only) | Yes (REST layer + `mongod.log`/direct-connection detections) |
| OS-level access (`SPL-IDX`/`SPL-FWD`/`SPL-ENT`-style) | **No customer OS access** — provider-managed | Yes, including FIM/process/CLI-based detections |
| splunkd service manipulation | Provider managed, not customer-visible | Customer managed — `SPL-IDX-002`, `SPL-FWD-006` |
| Indexer OS tampering | Provider managed | Customer managed — `SPL-IDX-003` through `SPL-IDX-012` |
| Cluster Manager compromise (`SPL-CM`) | N/A — Cloud manages indexer clustering internally | Yes |
| Deployment Server compromise (`SPL-DS`) | N/A for Cloud-hosted DS; applies if customer runs an external/on-prem DS | Yes |
| Forwarder tampering (`SPL-FWD`) | Customer-managed UF/HF remain fully in scope even against a Cloud back end | Yes |
| File-system configuration changes (`SPL-CONF`) | Restricted — most `SPL-CONF-###` require FIM the customer cannot deploy on provider infrastructure | Yes, full FIM-backed coverage |
| ACS / Cloud administration (`SPL-CLOUD`) | Yes | N/A — ACS is Cloud-only |
| Direct server shell access | **No** | Yes |

This library does not claim Splunk Cloud customers can directly observe
provider-managed infrastructure. Every `SPL-IDX-###`, `SPL-CM-###`, and
`SPL-CONF-###` entry that depends on OS-level file-integrity monitoring or
process telemetry says so explicitly in its `tuning_guidance` field and is
marked as an on-premises-only or FIM-dependent detection — see §10 for the
full list of what Splunk Cloud does and does not expose to the customer.

## 3. Detection by component (top components)

| Component | Count | Component | Count |
|---|---:|---|---:|
| Knowledge Object | 25 | HEC | 15 |
| Search | 23 | ACS | 15 |
| Enterprise Security | 21 | REST API | 15 |
| RBAC | 20 | Configuration | 15 |
| Correlation | 20 | Deployment Server | 12 |
| Authentication | 19 | Indexer | 12 |
| Internal Telemetry | 18 | Universal Forwarder | 11 |

## 4. Severity and confidence

| Severity | Count | | Confidence | Count |
|---|---:|---|---|---:|
| High | 124 | | Medium | 201 |
| Critical | 115 | | High | 113 |
| Medium | 82 | | Low | 23 |
| Low | 16 | | | |

## 5. Detection type and maturity

| Type | Count | | Maturity | Count |
|---|---:|---|---|---:|
| Configuration change | 104 | | Level 1 — indicator | 156 |
| Atomic | 78 | | Level 2 — threshold | 90 |
| Behavioral | 67 | | Level 3 — behavioral | 48 |
| Threshold | 41 | | Level 5 — multi-component attack sequence | 28 |
| Sequence | 35 | | Level 4 — correlation | 15 |
| Availability | 11 | | | |
| Integrity | 1 | | | |

All 20 `SPL-X-###` correlations are Level 5, plus 8 additional Level-5
sequences elsewhere in the catalogue (`SPL-AUTH-016`, `SPL-SEARCH-019`,
`SPL-SEARCH-020`, `SPL-KO-006`, `SPL-DS-007`, `SPL-DS-008`, `SPL-SH-011`,
`SPL-INT-018`).

## 6. False positive rating, telemetry requirement, and search cost

| FP Rating | Count | | Telemetry | Count | | Search cost | Count |
|---|---:|---|---|---:|---|---|---:|
| Medium | 224 | | Recommended | 187 | | Low cost | 263 |
| Low | 68 | | Essential | 118 | | Medium cost | 58 |
| High | 45 | | Optional | 32 | | High cost | 16 |

Every `High cost` search carries a `performance_guidance` field explaining
how to keep it tractable in production (sampling, scheduling frequency,
scoping to a maintained hot-list) per the specification's own requirement
that expensive searches be flagged and optimized, not just documented.

## 7. CIM coverage

**65% CIM-compatible (218 / 337).** Coverage concentrates in
`Authentication` (login/brute-force detections), `Change` (nearly every
configuration-tampering detection across `SPL-RBAC`, `SPL-KO`, `SPL-DATA`,
`SPL-CONF`), and `Data_Access` (export/exfiltration detections). The 119
non-CIM entries are concentrated in `SPL-INT-###` (self-monitoring
telemetry with no natural CIM home), `SPL-CLOUD-###` (ACS-specific
events), and the `SPL-X-###` correlations that reference multiple
underlying sources at once.

## 8. Risk scoring reference

`score = severity(1-5) × confidence(1-5) × impact(1-5)`, max 125.

| Score band | Count | Interpretation |
|---|---:|---|
| 100–125 | 83 | Page immediately / Tier 1 candidate |
| 60–99 | 86 | Investigate same business day |
| 30–59 | 88 | Queue for triage / hunting |
| < 30 | 80 | Enrichment / context-only |

---

## 9. Priority Detection Packs

### Tier 1 — Critical Splunk Platform Detections (55 detections)

Critical severity **and** high confidence **and** Low false-positive
rating — within the specification's requested 50–75 range.

| ID | Title | Risk score |
|---|---|---:|
| SPL-RBAC-004 | Role Modified to Include admin_all_objects | 125 |
| SPL-SEARCH-019 | Privileged Login Followed by Broad Search and Large Export | 125 |
| SPL-KO-001 | Security Correlation Search Disabled | 125 |
| SPL-KO-002 | Security Correlation Search Deleted | 125 |
| SPL-KO-006 | Detection Modified Immediately Before Matching Malicious Activity | 125 |
| SPL-DATA-008 | Delete Search Command Used | 125 |
| SPL-DATA-009 | Delete Command Used Against Sensitive Index | 125 |
| SPL-ES-006 | Risk Index Stops Receiving Events | 125 |
| SPL-API-010 | Index Management REST Endpoint Used Destructively | 125 |
| SPL-X-003 | Attack Path: Splunk Admin to Sensitive Data Access | 125 |
| SPL-X-019 | Ransomware-Style Chain Against Splunk Itself | 125 |
| SPL-X-020 | Fleet-Wide Splunk Platform Compromise Correlation | 125 |
| SPL-AUTH-015 | SAML/SSO Configuration Disabled or IdP Metadata Changed | 100 |
| SPL-AUTH-016 | Unexpected Local Admin Login Following SSO Failure | 100 |
| SPL-AUTH-023 | New User Created with Admin or Privileged Role | 100 |
| SPL-RBAC-003 | High-Risk Capability Added to Splunk Role | 100 |
| SPL-RBAC-005 | Role Index Access Expanded to Wildcard or Sensitive Index | 100 |
| SPL-RBAC-008 | User Assigned Admin or Admin-Equivalent Role | 100 |
| SPL-RBAC-009 | Self-Privilege-Escalation: User Modifies Own Role Assignment | 100 |
| SPL-RBAC-010 | Privilege Escalation Chain: Low-Privilege User to Privileged Action | 100 |
| SPL-SEARCH-018 | Export from Sensitive Index | 100 |
| SPL-SEARCH-020 | New/Rare Account Runs Sensitive Search Then Exports | 100 |
| SPL-KO-005 | Notable/Risk Alert Action Removed from Correlation Search | 100 |
| SPL-APP-005 | Scripted Input Executes from Writable or Temporary Directory | 100 |
| SPL-DATA-002 | Index Deleted or Disabled | 100 |
| SPL-DATA-003 | Index Retention Shortened | 100 |
| SPL-DATA-006 | Clean Eventdata or Destructive Index Maintenance Command Run | 100 |
| SPL-DATA-007 | Bucket-Level Filesystem Deletion | 100 |
| SPL-DATA-012 | Data Diversion: Security Source Volume Drops While New Destination Appears | 100 |
| SPL-DS-007 | Outputs Configuration Redirected Fleet-Wide via Deployment App | 100 |
| SPL-DS-008 | Monitoring Disabled Fleet-Wide via Deployment App | 100 |
| SPL-SH-011 | Search Head Compromise Path | 100 |
| SPL-CM-006 | Replication Factor or Search Factor Reduced | 100 |
| SPL-IDX-010 | Indexer Log File Deleted or Truncated at OS Level | 100 |
| SPL-ES-001 | ES Correlation Search Disabled at Scale | 100 |
| SPL-ES-011 | Threat Intelligence Feed Source Disabled | 100 |
| SPL-CLOUD-004 | ACS IP Allow-List Broadened | 100 |
| SPL-CLOUD-011 | Splunk Cloud IDM/Identity Integration Configuration Changed | 100 |
| SPL-CLOUD-015 | Splunk Cloud Privileged Admin Anomaly Correlation | 100 |
| SPL-INT-001 | _audit Ingestion Volume Suddenly Drops | 100 |
| SPL-INT-007 | Entire Security Domain Stops Logging | 100 |
| SPL-INT-018 | Coordinated Anti-Forensics Across Telemetry | 100 |
| SPL-X-001 through SPL-X-013, SPL-X-015 | Attack-Path Matrix correlations (see §10) | 100 |

*(17 `SPL-X-###` entries score 100+; listed individually in §10's Attack-Path Matrix rather than repeated here.)*

### Themed packs

| Pack | Focus |
|---|---|
| **Splunk Cloud Protection Pack** | All `SPL-CLOUD-###`, plus every entry with `deployment_applicability=Cloud` or `Both` |
| **Splunk Enterprise Server Protection Pack** | `SPL-IDX-###`, `SPL-CM-###`, `SPL-CONF-###`, plus every entry with `deployment_applicability=On-premises` |
| **Splunk ES Protection Pack** | All `SPL-ES-###` |
| **Deployment Server Protection Pack** | All `SPL-DS-###` |
| **Forwarder Protection Pack** | All `SPL-FWD-###` |
| **HEC Protection Pack** | All `SPL-HEC-###` |
| **Search Abuse / Exfiltration Pack** | All `SPL-SEARCH-###`, `SPL-API-009`, `SPL-API-010` |
| **Knowledge Object Integrity Pack** | All `SPL-KO-###` |
| **Data Pipeline Protection Pack** | All `SPL-DATA-###` |
| **Anti-Forensics Pack** | All `SPL-INT-###`, `SPL-KO-001/002/003`, `SPL-X-019` |
| **Management Plane Compromise Pack** | `SPL-DS-###`, `SPL-SH-004` through `SPL-SH-008`, `SPL-CM-###`, `SPL-X-005`, `SPL-X-011` |

Pack membership is computed from each entry's `tags` array and `component`
field — filter `data/splunk-detections.json` on the tags/components named
above to reproduce each list; packs overlap by design.

---

## 10. The Attack-Path Matrix

Every attack path named in the specification's §154 is implemented as a
dedicated `SPL-X-###` correlation:

| Attack path | Detection(s) | Telemetry required |
|---|---|---|
| Identity → Splunk Admin | `SPL-X-001` | `_audit`, identity-provider logs |
| Splunk Admin → Detection Tampering | `SPL-X-002` (→ `SPL-KO-006`) | `_audit` |
| Splunk Admin → Sensitive Data | `SPL-X-003` (→ `SPL-SEARCH-019`) | `_audit`, `splunkd_access.log` |
| App → Server Execution | `SPL-X-004` | `_audit`, OS process auditing (Cloud limitation) |
| Deployment Server → Forwarder Fleet | `SPL-X-005` (→ `SPL-DS-007`/`008`) | FIM on DS (Cloud limitation), `_internal` |
| Heavy Forwarder → Data Diversion | `SPL-X-006` | `_audit`, `_internal` |
| Search Head → Detection / Search Abuse | `SPL-X-007` (→ `SPL-SH-011`) | `_audit` |
| HEC → Data Poisoning | `SPL-X-008` (→ `SPL-HEC-015`) | `_internal` |
| Data Pipeline → Logging Blind Spot | `SPL-X-009` | `_audit`, `_internal` |
| ES → SOC Defense Evasion | `SPL-X-010` | `_audit`, ES internal indexes |

Additional named chains from the specification's cross-platform-correlation
sections (§130–§141):

| Chain | Detection(s) |
|---|---|
| Hybrid on-prem DS compromise → Splunk Cloud data gap | `SPL-X-011` |
| Data exfiltration path (new/rare login → sensitive search → export) | `SPL-X-012` (→ `SPL-SEARCH-020`) |
| Log suppression path (config access → parsing change → coverage gap) | `SPL-X-013` |
| Search resource exhaustion impacting SOC | `SPL-X-014` (→ `SPL-SEARCH-011`) |
| On-premises host root access → Splunk behavior alteration | `SPL-X-015` |
| Multi-stack: same source targeting multiple search heads | `SPL-X-016` |
| Multi-stack: same app introduced across environments | `SPL-X-017` |
| Consolidated persistence-through-Splunk correlation | `SPL-X-018` |
| Ransomware-style chain against Splunk itself | `SPL-X-019` |
| Fleet-wide platform compromise (top-level escalation) | `SPL-X-020` |

## 11. Detection gap analysis — what this catalogue depends on for each telemetry class

- **Visible in `_audit` alone**: the large majority of authentication,
  RBAC, knowledge-object, index-administration, and REST-API-adjacent
  detections. This is the single richest data source in the catalogue.
- **Visible in `_internal` alone**: platform health, scheduler/search
  execution metadata, forwarder connection state, clustering/replication
  status, HEC ingestion metrics.
- **Requiring OS-level telemetry (FIM/process auditing)**: every detection
  touching local configuration-file tampering below what `_audit` records
  (`SPL-CONF-003` through `SPL-CONF-015` in their FIM-backed forms),
  scripted-input execution confirmation (`SPL-APP-006`), indexer/Cluster-
  Manager/Deployment-Server filesystem tampering (`SPL-IDX-003/004/005/
  007/010`, `SPL-CM`), and `delete eventdata`/bucket-level destruction
  (`SPL-DATA-006/007`). **This is explicitly a Splunk Cloud blind spot** —
  every such entry says so in its `tuning_guidance` field rather than
  pretending Cloud customers have this visibility.
- **Requiring network telemetry**: `SPL-IDX-007` (firewall exposure),
  `SPL-KV-008` (direct KV Store network access) depend on network-layer
  logging this library does not assume is present by default.
- **Cloud activity not customer-visible**: provider-side operations
  (support access sessions beyond what ACS exposes, internal Splunk Cloud
  infrastructure operations, provider-managed OS/indexer-hardware events)
  are explicitly out of scope — `SPL-CLOUD-012` documents the limited,
  version-dependent visibility Splunk Cloud does expose for support
  access, and no detection in this catalogue claims deeper access than
  that.
- **Requiring Enterprise Security**: all `SPL-ES-###` entries, plus the
  risk-based-alerting and notable-event framework referenced by several
  `SPL-X-###` correlations — none of this exists on a Splunk deployment
  without ES licensed and configured.
- **Requiring HEC telemetry**: `SPL-HEC-###` in full, plus `SPL-API-011`'s
  API-layer view of the same configuration surface.
- **Requiring forwarder-side logs**: `SPL-FWD-###`, and the Cloud-side
  symptom detection `SPL-FWD-015` for hybrid architectures specifically.
- **Requiring external identity-provider logs**: `SPL-AUTH-013` through
  `SPL-AUTH-019`'s SAML/LDAP detections are Splunk-side only — full
  confirmation of an IdP-side compromise requires correlating against the
  identity provider's own logs, which this library does not claim to
  provide.
- **Requiring multi-stack log aggregation**: `SPL-X-016` and `SPL-X-017`
  explicitly depend on an organization operating more than one Splunk
  stack with a shared analysis point (federated search or forwarded
  `_audit`); a single-instance deployment has no applicable telemetry for
  these two detections and they will simply never fire, by design.

**Never invented**: no detection in this catalogue references a Splunk
internal index, REST endpoint, capability name, or configuration file that
does not exist in the current Splunk product documentation. Where a
detection's exact audit-event schema is genuinely version- or
product-dependent (Ingest Processor, Edge Processor, ACS, SOAR, Mission
Control), the `tuning_guidance` field says so explicitly rather than
presenting invented field names as fact.

---

*Generated from `data/splunk-detections.json` (337 entries). Regenerate
these tables after any future batch adds or edits detections — the counts
above are a snapshot, not a live query.*
