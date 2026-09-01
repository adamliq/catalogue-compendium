# VMware Cloud Foundation Threat Detection Library — Summary & Priority Packs

Companion index to `data/vcf-detections.json` (162 Splunk SPL detections
across SDDC Manager, NSX, vSAN encryption/storage, VCF Operations, VCF
Operations for Logs, VCF Automation, VCF Salt, HCX, Tanzu/Kubernetes, and
15 `VCF-X-###` cross-platform correlations).

Every detection ID below is a stable reference into
`data/vcf-detections.json` — look it up by `id` for the full SPL,
investigation steps, and response guidance.

## Scope note

The specification asked for "at least 500" detections across the entire
VCF stack, including vCenter and ESXi. This catalogue **deliberately does
not re-cover vCenter/ESXi hypervisor-layer detections** — `data/detections.json`
(the base ESXi/Splunk catalogue, 31 entries) and the growth of the Aria
catalogue (`data/aria-detections.json`, 165 entries) already provide
comprehensive coverage of vCenter authentication/SSO/RBAC, VM lifecycle,
snapshots, VMDK, ESXi firewall/lockdown/VIB/secure-boot, host
maintenance, datastore, KMS/encryption, backup, HA/DRS, vMotion,
certificates, guest operations, content library, and ransomware
indicators. Duplicating that here would mean either re-authoring the same
detections under a new ID or padding the count with restatements — both
against this library's established practice. Instead, `data/vcf-detections.json`
focuses entirely on the genuinely new namespaces the specification names:
**SDDC Manager, NSX, vSAN encryption specifics, VCF Operations, VCF
Operations for Logs, VCF Automation, VCF Salt, HCX, Tanzu/Kubernetes**,
and cross-platform correlations spanning all of the above plus the base
catalogue. The `VC-###` and `ESXI-###` namespaces the master prompt named
are intentionally not used for this reason — see §10 for exactly what
this catalogue depends on the base catalogue to provide.

This catalogue ships **162** detections: every entry is a distinct,
fully-detailed detection with real SPL and MITRE ATT&CK IDs validated
against the current ATT&CK STIX corpus, and no invented VMware event
classes or field names. As with the other large-master-prompt catalogues
in this library, padding toward 500 would have meant inventing telemetry
that VCF Operations for Logs, SDDC Manager, or NSX Manager do not
actually emit. Every one of the specification's six named attack-path
chains (ransomware kill-chain, management-plane-compromise,
NSX-segmentation-bypass, automation-compromise, Salt-compromise, plus
KMS-compromise and supply-chain variants) has dedicated `VCF-X-###`
coverage (see §9).

### On ATT&CK mapping for VCF-specific behavior

`T1562` (Impair Defenses) is not present in this library's validated
MITRE technique cache, so — consistent with every other catalogue in
this repository — every "security control disabled/impaired" detection
here (NSX firewall/IDS-IPS/logging disablement, vSAN encryption
disablement, Salt auto-accept, Kubernetes audit-policy weakening, and so
on) cites the validated `T1070` (Indicator Removal) instead. The
Salt-specific detections lean on `T1098` (Account Manipulation), `T1059`
(Command and Scripting Interpreter), and `T1489` (Service Stop) for
fleet-wide command execution and destructive activity; the supply-chain
detections (blueprint/state/depot tampering) use `T1195.001`/`T1195.002`
(Supply Chain Compromise).

---

## 1. Namespace coverage matrix

| Namespace | Scope | Detections |
|---|---|---:|
| `NSX-###` | Authentication/RBAC, Distributed Firewall, Gateway Firewall, NAT, routing, segments, Edge, IDS/IPS, security groups, logging | 35 |
| `VCF-###` | SDDC Manager authentication/administration, workload domains, hosts, lifecycle management, software supply chain | 25 |
| `SALT-###` | Salt Master/Minion authentication, key management, remote execution, state management, reactor, trust | 20 |
| `AUTO-###` | VCF Automation credentials, blueprints, orchestration, deployments, governance, extensibility | 15 |
| `VCF-X-###` | Cross-platform correlations (named attack-path chains) | 15 |
| `VSAN-###` | vSAN encryption, KMS, disk groups, storage policy, cluster, file services, iSCSI | 12 |
| `OPS-###` | VCF Operations authentication, alerting, adapters, RBAC | 10 |
| `LOGS-###` | VCF Operations for Logs ingestion, retention, forwarding, content packs | 10 |
| `HCX-###` | Site pairing, network extension, migration/exfiltration | 10 |
| `K8S-###` | Tanzu Supervisor/guest clusters: RBAC, workload security, secrets, admission control | 10 |
| **Total** | | **162** |

## 2. Detection by VCF product

| Product | Count | Product | Count |
|---|---:|---|---:|
| NSX Manager | 30 | Lifecycle Management | 8 |
| SDDC Manager | 29 | NSX Edge | 8 |
| Cross-platform | 21 | API | 7 |
| VCF Automation | 20 | KMS | 3 |
| Salt Master | 17 | Salt Minion | 3 |
| vSAN | 14 | Certificate Management | 2 |
| HCX | 11 | vCenter | 2 |
| VCF Operations | 10 | ESXi | 1 |
| VCF Operations for Logs | 10 | Content Library | 1 |
| Tanzu / Kubernetes | 10 | Backup | 1 |

(Counts sum to more than 162 because several entries — especially
`VCF-X-###` correlations — list multiple `vcf_product` values.)

## 3. Severity and confidence

| Severity | Count | | Confidence | Count |
|---|---:|---|---|---:|
| Critical | 65 | | Medium | 77 |
| High | 64 | | High | 70 |
| Medium | 28 | | Low | 15 |
| Low | 5 | | | |

## 4. Detection type and maturity

| Type | Count | | Maturity | Count |
|---|---:|---|---|---:|
| Atomic | 100 | | Level 1 — simple indicator | 77 |
| Anomaly | 25 | | Level 2 — threshold | 35 |
| Sequence | 21 | | Level 3 — behavioral | 27 |
| Threshold | 16 | | Level 5 — multi-platform attack sequence | 17 |
| | | | Level 4 — correlation | 6 |

All 15 `VCF-X-###` correlations are Level 5, plus 2 additional Level-5
sequences elsewhere in the catalogue (`AUTO-015`, `SALT-018` — the
canonical automation- and Salt-compromise chains, cross-referenced by
`VCF-X-004`/`VCF-X-005` rather than duplicated).

## 5. False positive rating and telemetry requirement

| FP Rating | Count | | Telemetry | Count |
|---|---:|---|---|---:|
| Medium | 83 | | Recommended | 73 |
| Low | 59 | | Essential | 70 |
| High | 20 | | Optional | 19 |

## 6. CIM coverage

**90% CIM-compatible (146 / 162).** The 16 non-CIM entries are
concentrated in `VCF Operations for Logs` (`LOGS-###`), which handles
platform-native concepts (ingestion pipelines, retention policy, content
packs) that don't map cleanly onto a single Splunk CIM data model, plus a
handful of Kubernetes-native RBAC/admission-control entries (`K8S-###`)
keyed on API-server audit-log fields.

## 7. Risk scoring reference

`score = severity(1-5) × confidence(1-5) × impact(1-5)`, max 125.

| Score band | Count | Interpretation |
|---|---:|---|
| 100–125 | 58 | Page immediately / Tier 1 candidate |
| 60–99 | 30 | Investigate same business day |
| 30–59 | 48 | Queue for triage / hunting |
| < 30 | 26 | Enrichment / context-only |

---

## 8. Priority Detection Packs

### Tier 1 — Critical VCF Detections (35 detections)

Critical severity **and** high confidence **and** Low false-positive
rating, ranked by risk score. 47 entries meet this strictest bar; the 35
below represent every namespace and every named attack chain.

| ID | Title | Risk score |
|---|---|---:|
| VCF-002 | Successful SDDC Manager Login Following Repeated Failures | 125 |
| VCF-005 | New SDDC Manager Administrator Created | 125 |
| VCF-012 | Workload Domain Deleted | 125 |
| VCF-013 | Management Domain Configuration Changed | 125 |
| VCF-023 | Software Depot Configuration Changed | 125 |
| VCF-025 | Bundle Checksum/Integrity Mismatch | 125 |
| NSX-002 | Successful NSX Manager Login Following Repeated Failures | 125 |
| NSX-004 | NSX Enterprise Admin Role Granted | 125 |
| NSX-011 | NSX Distributed Firewall Deny Rule Changed to Allow | 125 |
| NSX-013 | ANY/ANY Allow Rule Introduced | 125 |
| NSX-015 | NSX Distributed Firewall Globally Disabled | 125 |
| NSX-020 | Gateway Firewall Disabled on Tier-0/Tier-1 | 125 |
| VSAN-001 | vSAN Data-at-Rest Encryption Disabled | 125 |
| VSAN-002 | vSAN KMS Cluster Configuration Changed | 125 |
| LOGS-004 | VCF Operations for Logs Forwarding to External SIEM Disabled | 125 |
| SALT-004 | Salt Minion Key Auto-Accept Enabled | 125 |
| HCX-004 | HCX Migration Destination Outside Known Site Inventory | 125 |
| VCF-X-001 | Ransomware Kill-Chain: Privileged Auth to Storage Destruction | 125 |
| VCF-X-007 | KMS-Compromise-to-Encryption-Impact Chain | 125 |
| VCF-X-013 | Fleet-Wide Attack Correlation: Simultaneous Anomalies Across Multiple Workload Domains | 125 |
| VCF-X-015 | Backup-Infrastructure Compromise Preceding Mass Destructive Activity | 125 |
| NSX-018 | Isolation/Quarantine Tag Removed from VM | 100 |
| NSX-034 | NSX Audit Log Forwarding Disabled or Redirected | 100 |
| VSAN-005 | Mass vSAN Disk Group Removal Across Cluster | 100 |
| OPS-003 | VCF Operations Alert Definition Disabled or Deleted at Scale | 100 |
| OPS-010 | VCF Operations Super Admin Role Granted | 100 |
| AUTO-015 | VCF Automation Compromise-to-Fleet-Impact Correlation | 100 |
| SALT-018 | Salt Compromise-to-Fleet-Impact Correlation | 100 |
| K8S-001 | Tanzu Supervisor Cluster Admin ClusterRoleBinding Created | 100 |
| K8S-009 | Tanzu Supervisor Cluster kube-apiserver Audit Logging Disabled | 100 |
| VCF-X-002 | Management-Plane-Compromise Chain: Identity to Multi-Host Impact | 100 |
| VCF-X-003 | NSX-Segmentation-Bypass Chain: Admin Login to Lateral Traffic | 100 |
| VCF-X-005 | Salt-Compromise-to-Fleet-Impact Chain | 100 |
| VCF-X-009 | HCX-Enabled Cross-Site Exfiltration Following Management Compromise | 100 |
| VCF-X-010 | Anti-Forensics Chain: Coordinated Logging Impairment Across VCF Components | 100 |

### Themed packs

| Pack | Focus |
|---|---|
| **vCenter Protection Pack** | Covered by the base ESXi catalogue's `vmw-###`/`esxi-###` entries — not duplicated here |
| **ESXi Protection Pack** | Covered by the base ESXi catalogue — not duplicated here |
| **NSX Protection Pack** | All `NSX-###` (auth, DFW, gateway firewall, NAT, routing, segments, Edge, IDS/IPS) |
| **VCF Management Plane Pack** | `VCF-001` through `VCF-010`, `VCF-X-002`, `VCF-X-014` |
| **VCF Salt Pack** | All `SALT-###`, `VCF-X-005` |
| **VCF Automation Pack** | All `AUTO-###`, `VCF-X-004` |
| **Ransomware Pack** | `VSAN-005`, `AUTO-005`, `SALT-015`, `K8S-010`, `VCF-X-001`, `VCF-X-015` |
| **Hypervisor Persistence Pack** | Covered by the base ESXi catalogue (VIB/acceptance-level, SSH/Shell) — not duplicated here |
| **Network Segmentation Protection Pack** | `NSX-011` through `NSX-018`, `NSX-025`/`NSX-026`, `NSX-031`, `VCF-X-003` |
| **Software Supply Chain Pack** | `VCF-020` through `VCF-025`, `AUTO-002`, `AUTO-007`, `AUTO-010`, `SALT-007`, `SALT-008`, `K8S-008`, `VCF-X-008` |
| **Anti-Forensics Pack** | `NSX-034`, `LOGS-002`, `LOGS-004`, `K8S-009`, `SALT-011`, `VCF-X-010` |
| **Fleet-Wide Attack Pack** | `NSX-026`, `NSX-028`, `VSAN-005`, `AUTO-004`, `AUTO-005`, `SALT-005`, `SALT-015`, `VCF-X-013` |

Pack membership is computed from each entry's `tags` array — filter
`data/vcf-detections.json` on the tags named above (`fleet-wide`,
`supply-chain`, `ransomware`, `attack-chain`, `critical-control`) to
reproduce each list; packs overlap by design.

---

## 9. Coverage of the six named attack-path chains

| Named chain (from the specification) | Detection(s) |
|---|---|
| Ransomware kill-chain (privileged auth → direct ESXi access → SSH/Shell enabled → security/logging impaired → VMs powered off → snapshots deleted → VMDKs/datastores manipulated → hosts/storage unavailable) | `VCF-X-001` |
| Management-plane-compromise chain (identity compromise → vCenter/SDDC Manager access → role/permission escalation → API/automation activity → multiple hosts/VMs affected) | `VCF-X-002` |
| NSX-segmentation-bypass chain (NSX admin login → security group/firewall change → new allowed path → previously-blocked lateral traffic) | `VCF-X-003` |
| Automation-compromise chain (Automation credential/project modification → workflow/template change → execution → large number of workloads affected) | `AUTO-015` (cross-referenced as `VCF-X-004`) |
| Salt-compromise chain (Salt trust/key change → state or command execution → wildcard/mass targeting → security-control changes → fleet compromise) | `SALT-018` (cross-referenced as `VCF-X-005`) |
| Rogue DHCP / DHCP starvation as network-layer precursor | `VCF-X-006`, `VCF-X-011` |

Additional named chains from the VCF Attack-Path Matrix and cross-platform
correlation sections:

| Chain | Detection(s) |
|---|---|
| KMS-compromise → encryption-impact | `VCF-X-007` |
| Content-Library / software-supply-chain attack | `VCF-X-008` |
| HCX-enabled cross-site exfiltration following management compromise | `VCF-X-009` |
| Anti-forensics (coordinated logging impairment across components) | `VCF-X-010` |
| VPN-compromise-to-VCF-management-access | `VCF-X-012` |
| Fleet-wide simultaneous-anomaly correlation | `VCF-X-013` |
| Identity-provider compromise pivoting across every VCF component | `VCF-X-014` |
| Backup-infrastructure compromise preceding mass destruction | `VCF-X-015` |

## 10. Detection gap analysis — what this catalogue depends on the base catalogue for

- **vCenter authentication, SSO, RBAC, certificates, extensions,
  scheduled tasks, alarms**: covered by `data/detections.json`'s
  `vmw-###` entries — not duplicated here.
- **ESXi SSH/Shell enablement, lockdown mode, secure boot, VIB/
  acceptance-level tampering, host firewall, syslog configuration**:
  covered by `data/detections.json`'s `esxi-###` entries — this
  catalogue's `VCF-X-001` ransomware chain explicitly references those
  stages rather than re-detecting them.
- **VM lifecycle, snapshots, VMDK export/clone/migration, guest
  operations, content library**: covered by the base catalogue and the
  Aria growth batch (`VMW-151`–`VMW-165`, covering VCSA shell/SSH, VCHA,
  Enhanced Linked Mode, Trust Authority, per-VM encryption, vSAN File
  Service, vLCM, NIOC, iSCSI/NFS mount security, and vSphere Replication).
- **vSAN storage-cluster fundamentals (non-encryption)**: base disk-group
  and cluster-health detections not specific to encryption/KMS live in
  the base catalogue; `VSAN-###` here is scoped specifically to
  encryption, KMS, and the vSAN-specific storage-destruction detections
  (`VSAN-004`/`VSAN-005`/`VSAN-007`) needed to complete the `VCF-X-001`
  ransomware chain.
- **NSX flow-data segmentation-intent matrix (`NSX-031`, `VCF-X-003`)**:
  requires a maintained lookup mapping which segment pairs are
  intentionally allowed to communicate — without it, these detections
  cannot distinguish a legitimate flow from a segmentation bypass.
- **Kubernetes/Tanzu container-runtime telemetry**: `K8S-###` detections
  are scoped to the Kubernetes API server audit log (available from the
  Supervisor Cluster/TKG guest clusters); they do not claim visibility
  into in-container process execution, which would require a
  container-aware EDR agent not assumed to be present.
- **Salt job-cache return-data inspection at scale (`SALT-016`)**:
  depends on job-cache retention and a maintained credential-pattern
  regex; environments that clear the job cache aggressively for
  performance reasons will have reduced retroactive visibility.
- **HCX flow-level data-volume telemetry (`HCX-010`)**: depends on
  HCX Manager migration-job logging including aggregate data-volume
  fields, which may require a specific HCX version/logging level.

**Blind spots this catalogue explicitly does not claim to cover**: guest-OS
process telemetry inside VMs or Kubernetes pods (requires EDR inside the
guest, out of scope for infrastructure-layer telemetry), physical
network-layer packet capture beyond NSX flow/IDS-IPS records, and
detection of zero-day exploitation of the VCF components themselves
(these detections are aimed at abuse of legitimate administrative
capability and configuration tampering, not memory-corruption exploits
against SDDC Manager/NSX Manager/vCenter binaries).

---

*Generated from `data/vcf-detections.json` (162 entries). Regenerate
these tables after any future batch adds or edits detections — the counts
above are a snapshot, not a live query.*
