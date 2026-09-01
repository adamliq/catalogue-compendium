# Threat Detection Library

![version](https://img.shields.io/badge/version-1.2.0-informational) [Changelog](CHANGELOG.md)

A searchable, self-contained library of platform-specific threat detections —
technique description, data sources, detection logic, MITRE ATT&CK mapping,
known false positives, investigation steps, and references — in the same
spirit as [Splunk-spl-library](https://github.com/adamliq/Splunk-spl-library),
but for full detection rules rather than raw SPL snippets. The page header's
**Companion Tools** menu links out to other tools from the same author —
currently [Splunk Taxonomy — My Tools](https://adamliq.github.io/Splunk_Taxonomy/#my-tools).

Open `index.html` directly in a browser, or serve the repo statically (e.g.
GitHub Pages) — there's no build step or server dependency to browse it.
Search, filter by catalogue/tool, MITRE ATT&CK tactic, severity, method,
component, or data source, open any card for the full write-up, copy the
search/query/CLI reference, and export the current (filtered) result set
as JSON. A second top-level tab, **Heat Coverage**, shows the whole
library as an ATT&CK technique × tactic matrix shaded by detection density
— see [Heat Coverage tab](#heat-coverage-tab) below. A third top-level
tab, **Validations**, holds this library's **validation catalogues**
(RHEL, FortiGate, Cisco SD-WAN, RHEL IdM/IPA, and Windows) —
test-execution references for confirming an existing detection actually
fires, not
production detection rules of their own — see
[Validations](#validations) below.

The repo holds fourteen catalogues of detection content, spanning two
different query languages and sixteen platform families — combined
into one filterable view:

| Catalogue | Query language | Scope | Detections |
|---|---|---|---|
| ESXi / Splunk | Splunk SPL | VMware ESXi hypervisor only | 31 |
| VMware Aria Operations for Logs | Aria search expressions | The whole vSphere stack (vCenter, SSO, ESXi, storage, networking, cluster) | 165 |
| Red Hat / Splunk | Splunk SPL | RHEL, Red Hat IdM/IPA/FreeIPA, Ansible Automation Platform, Satellite, plus cross-platform (`RH-X-###`) correlations | 171 |
| Fortinet / Splunk | Splunk SPL | FortiGate, FortiManager, FortiAnalyzer, FortiAuthenticator, FortiClient/EMS, FortiEDR, FortiWeb, FortiMail, FortiProxy, FortiSandbox, plus cross-product (`FNT-X-###`) Security Fabric correlations | 206 |
| Dell iDRAC / Splunk | Splunk SPL | Dell iDRAC, Lifecycle Controller, Redfish, RACADM, IPMI, Dell OpenManage Enterprise, plus cross-platform (`DELL-X-###`) correlations | 96 |
| HPE iLO / Splunk | Splunk SPL | HPE iLO, Remote Console, Virtual Media, UEFI/BIOS/Firmware, Redfish, Integrated Management Log, Active Health System, HPE OneView, plus cross-platform (`HPE-X-###`) correlations | 107 |
| Windows DHCP Server / Splunk | Splunk SPL | Windows DHCP Server core operation, AD authorization, audit-log integrity, DNS/gateway/route/PXE option redirection, failover, rogue-DHCP network telemetry, DHCPv6, dynamic DNS, PowerShell administration, plus cross-platform (`DHCP-X-###`) correlations | 169 |
| Windows RDP / Splunk | Splunk SPL | RDP authentication/brute-force, lateral movement, RD Gateway, session lifecycle/hijacking, credential-protection configuration, network exposure/tunneling, post-RDP process-execution correlation, plus cross-platform (`RDP-X-###`) correlations | 94 |
| VMware Cloud Foundation / Splunk | Splunk SPL | SDDC Manager, NSX, vSAN encryption, VCF Operations, VCF Operations for Logs, VCF Automation, VCF Salt, HCX, Tanzu/Kubernetes, plus cross-platform (`VCF-X-###`) correlations | 162 |
| Splunk Platform / Splunk | Splunk SPL | Attacks against, abuse of, or suspicious administrative activity within **Splunk itself** — Splunk Cloud, Splunk Enterprise, Enterprise Security, SOAR, forwarders, and the management tier — plus cross-component (`SPL-X-###`) attack-path correlations | 337 |
| Active Directory / Splunk | Splunk SPL | Active Directory Domain Services as Tier-0 identity infrastructure — Kerberos, NTLM, LDAP, Group Policy, trusts/SIDHistory, privileged groups/AdminSDHolder, delegation/RBCD, AD CS, LAPS/gMSA, domain controller integrity, credential access, plus cross-platform (`AD-X-###`) identity-correlation chains | 332 |
| Splunk ESCU (security_content) / Splunk | Splunk SPL | Curated subset of Splunk's own official detections (`splunk/security_content`) — Windows, Linux, and macOS Sysmon/EDR/CrowdStrike/osquery TTP coverage, VMware ESXi syslog and Splunk CVE-exploit-signature detections, Cisco/network-perimeter telemetry (including Isovalent eBPF and NVM endpoint-flow data), AWS/Azure/Microsoft 365/GCP/Kubernetes/GitHub cloud-identity telemetry, web-application CVE-exploit-signature detections (Ivanti, Citrix, Confluence, JetBrains TeamCity, Zscaler, and more), and identity-provider/Cisco-appliance/AI-LLM-abuse telemetry (Okta, PingID, Cisco ASA/Duo/IOS XE/SD-WAN, AWS Bedrock, MCP, Microsoft 365 Copilot), spanning the full MITRE kill chain, complementary to (and in the Linux/Kerberos case, partially overlapping with) the AD/RDP/DHCP/Fortinet, ESXi/Splunk Platform, and Red Hat catalogues | 2012 |
| Cisco Network Device / Splunk | Splunk SPL | MITRE ATT&CK-driven gap fill for Cisco IOS/IOS XE/ASA/FTD network devices — every ATT&CK `Network Devices`-platform technique this library didn't already detect via its ESCU Cisco content but MITRE itself has a real Detection Analytic for, including entries grounded in named real-world threats (SYNful Knock, the ArcaneDoor campaign's Line Dancer/Line Runner, Salt Typhoon's JumbledPath, KV Botnet Activity) | 62 |
| Windows Endpoint / Splunk | Splunk SPL | MITRE ATT&CK-driven gap fill for generic Windows OS endpoint telemetry — Persistence, Credential Access, Discovery, Stealth, and Defense Impairment techniques this library didn't already detect via its ESCU Windows Endpoint content but MITRE itself has a real Detection Analytic for | 73 |

`index.html` is the **combined library** — all 4017 detections from all
fourteen catalogues, filterable by a **Catalogue / Tool** facet (so you can
view any one alone or all together) alongside the usual tactic/severity/
component/method/data-source facets. Filter groups render in
alphabetical order and start collapsed — click a group's heading to
expand it. A detail card renders whichever query type applies (a Splunk
SPL search block for ESXi, Red Hat, Fortinet, iDRAC, iLO, DHCP, RDP, VCF,
Splunk Platform, Active Directory, Splunk ESCU, Cisco Network Device, and
Windows Endpoint entries, an Aria search query block for Aria entries)
plus a CLI/API reference, auditd rule set, or risk/maturity/CIM metadata
where present.

## Batch 1: VMware ESXi

The first 18 detections cover the command-line and API techniques attackers
use against VMware ESXi hosts in the run-up to ransomware deployment —
deleting snapshots, disabling autostart, powering off VMs, tampering with
syslog/firewall/coredump/VIB-acceptance settings, enabling SSH, and
enumerating the host — modeled on real campaigns (ESXiArgs, LockBit, Black
Basta, Akira, and the VirtualPita/VirtualPie/VirtualGate ESXi implants) and
public guidance from CISA, VMware/Broadcom, and Mandiant. See each entry's
**References** section for sources.

| # | Detection | Method | Severity |
|---|---|---|---|
| 1 | ESXi Virtual Machine Snapshots Deleted via API | API | High |
| 2 | ESXi Autostart Settings Modified via API | API | Medium |
| 3 | ESXi Virtual Machine Powered Off via ESXi API | API | Critical |
| 4 | ESXi Syslog Configuration Changed via ESXCLI | ESXCLI | High |
| 5 | ESXi Welcome Message Changed via ESXCLI | ESXCLI | Medium |
| 6 | ESXi VM Snapshots Deleted via VIM-CMD | VIM-CMD | High |
| 7 | ESXi VM Autostart Disabled via VIM-CMD | VIM-CMD | Medium |
| 8 | ESXi Coredump Generation Disabled via ESXCLI | ESXCLI | Medium |
| 9 | ESXi Firewall Disabled via ESXCLI | ESXCLI | High |
| 10 | SSH Enable on ESXi Host via VIM-CMD | VIM-CMD | Critical |
| 11 | ESXi VM IDs Enumerated via ESXCLI or VIM-CMD | ESXCLI / VIM-CMD | Low |
| 12 | ESXi System Network Information Enumerated via ESXCLI | ESXCLI | Low |
| 13 | ESXi System Information Discovery via VIM-CMD | VIM-CMD | Low |
| 14 | ESXi System Storage Enumerated via ESXCLI | ESXCLI | Low |
| 15 | ESXi System Users Enumerated via ESXCLI | ESXCLI | Low |
| 16 | ESXi Firewall Default Action Set to Pass | ESXCLI | High |
| 17 | ESXi VM Powered Off via VIM-CMD | VIM-CMD | Critical |
| 18 | ESXi VIB Acceptance Level Set to Community Supported via ESXCLI | ESXCLI | Critical |

## Batch 2: MITRE-ATT&CK-driven gap fill (ESXi)

Sourced by diffing the library against `data/mitre-attack-esxi.json` — every
entry below is grounded in a real MITRE ATT&CK Detection Analytic for the
ESXi platform (see each entry's `mitre_analytics` field for the exact
analytic ID). Raised ESXi ATT&CK technique coverage from 7/117 to 22/117.

| # | Detection | Method | Severity |
|---|---|---|---|
| 19 | ESXi Lockdown Mode Disabled via ESXCLI or VIM-CMD | ESXCLI / VIM-CMD | Critical |
| 20 | ESXi Local Account Removed or Password Reset via ESXCLI | ESXCLI | Critical |
| 21 | SSH Authorized Keys Modified on ESXi Host | Shell | Critical |
| 22 | ESXi Malicious VIB Installed via ESXCLI | ESXCLI | Critical |
| 23 | New Local Account Created on ESXi Host via ESXCLI | ESXCLI | High |
| 24 | ESXi Root/Default Account Login Anomaly | Shell / API | High |
| 25 | ESXi Shell Command History Cleared or Disabled | Shell | High |
| 26 | ESXi Log Files or Artifacts Deleted via Shell | Shell | High |
| 27 | ESXi Host Logs Enumerated via Shell | Shell | Low |
| 28 | ESXi VM/Datastore File Permissions Modified via Shell | Shell | Medium |
| 29 | ESXi Host Shutdown or Rebooted via ESXCLI/VIM-CMD | ESXCLI / VIM-CMD | High |
| 30 | ESXi Guest Operations API Abused for Command Execution | API | High |
| 31 | ESXi VM Escape Attempt (Hypervisor Anomaly) | Hypervisor | Critical (hunting) |

**Also corrected in this pass:** MITRE's current ESXi platform data no
longer includes any `T1562.*` (Impair Defenses) sub-techniques — they were
retired in favor of new top-level techniques under a new **Defense
Impairment** tactic (`TA0112`). Five batch-1 entries (syslog, coredump,
firewall ×2, VIB acceptance level) were retagged from `T1562.001/.004/.006`
to `T1685`/`T1686` accordingly.

## VMware Aria Operations for Logs Catalogue

`data/aria-detections.json` is a second, independent catalogue: 165
detections (`VMW-001`–`VMW-165`) spanning the full vSphere stack —
vCenter/SSO identity and access, ESXi host security configuration,
virtual networking, storage/datastores, cluster HA/DRS, the vCenter
control plane, content libraries, guest operations, and (in the
`VMW-151`–`VMW-165` growth batch) the vCenter Server Appliance
OS/VAMI layer, vCenter High Availability, Enhanced Linked Mode,
vSphere Trust Authority, per-VM encryption, vSAN File Services,
vSphere Lifecycle Manager, Network I/O Control, and vSphere
Replication — written as
**VMware Aria Operations for Logs search expressions** rather than
Splunk SPL, since Aria is a different query language with its own
field-extraction model per content pack. These detections live only in
the combined `index.html` library — there is no standalone Aria-only
page.

Its canonical source is human-authored markdown, not hand-written JSON:
[`docs/aria-catalogue-source.md`](docs/aria-catalogue-source.md) holds one
`### VMW-XXX` section per detection (component, severity, MITRE tactic and
technique, Aria query, tuning notes) plus the catalogue's suggested
detection groups and a priority implementation set. `data/aria-detections.json`
is generated from that document; the remaining schema-required fields
(description, data sources, false positives, investigation steps,
references) are synthesized from each entry's component and MITRE tactic
via templates in the importer, and `related_detections` are auto-linked
from "Correlate with VMW-XXX" mentions and singular/mass title pairs (e.g.
"Snapshot deleted" ↔ "Mass snapshot deletion").

To edit a detection or add a new one: edit `docs/aria-catalogue-source.md`
in the same `### VMW-XXX` format, then run:

```bash
python3 tools/import_aria_catalogue.py   # docs/aria-catalogue-source.md -> data/aria-detections.json
python3 tools/build.py                   # data/aria-detections.json (+ all other catalogues) -> index.html
```

Editing `data/aria-detections.json` directly also works for one-off fixes
(e.g. a description tweak) that don't belong in the source markdown — just
re-run `tools/build.py` afterward and skip the importer so your edit
isn't overwritten.

## Red Hat Threat Detection Library

`data/redhat-detections.json` is a third, independent catalogue: 171
Splunk SPL detections covering RHEL, Red Hat IdM/IPA/FreeIPA, Red Hat
Ansible Automation Platform (AAP), Red Hat Satellite, and 10 cross-platform
`RH-X-###` correlations that join saved searches across those platforms by
identity/timing to catch attacks on the Red Hat management plane itself
(e.g. a compromised IdM admin account used to SSH into the fleet, or an
AAP job template modified to disable security controls fleet-wide).

| Namespace | Platform | Detections |
|---|---|---|
| `RHEL-###` | RHEL (auditd, PAM, SELinux, sudo, SSH, systemd, fapolicyd, kernel, cron/at) | 70 |
| `IPA-###` | Red Hat IdM/IPA/FreeIPA (Kerberos KDC, 389 DS, Dogtag PKI, HBAC, sudo rules, trusts) | 31 |
| `AAP-###` | Ansible Automation Platform (Controller, credentials, EE, EDA, Automation Hub, receptor) | 33 |
| `SAT-###` | Red Hat Satellite (Foreman, Candlepin, Pulp, Katello, Capsule, REX, kickstart) | 27 |
| `RH-X-###` | Cross-platform correlations | 10 |

Every entry follows `schema/redhat-detection.schema.json` — a superset of
the ESXi schema's fields with the additions the Red Hat catalogue needed:
`component`, `detection_type`, `required_fields`, `threshold`,
`tuning_guidance`, `response_guidance`, `telemetry_requirement`,
`requires_auditd`, `audit_rules`, `detection_maturity`,
`false_positive_rating`, and `risk_scoring` (`severity × confidence ×
impact`, 1–5 each, max 125). All 171 entries' MITRE ATT&CK tactic/technique
IDs are validated against the current ATT&CK STIX corpus at generation
time — invalid or platform-mismatched IDs fail the build rather than
silently shipping (this caught several IDs that exist in MITRE's data but
were the wrong platform or tactic for the detection in question, e.g.
`T1685.001` being Windows-only despite `T1685.004`/`T1685.006` being the
correct Linux siblings).

Two companion documents ship alongside the data:

- [`docs/redhat-audit-policy.md`](docs/redhat-audit-policy.md) — every
  `auditd` rule any RHEL detection depends on, consolidated into one
  deployable ruleset and organized into the categories a Linux audit
  policy is expected to cover (Identity, Authentication, Privilege,
  Persistence, Audit protection, Security controls, Kernel, Network,
  Package management, Credentials, Destructive activity), each rule
  cross-referenced back to the detection ID(s) it supports. Includes a
  gap-analysis summary and a small set of clearly-labeled supplemental
  rules for the two categories (Network, Package management) no single
  detection's telemetry currently depends on.
- [`docs/redhat-detection-library.md`](docs/redhat-detection-library.md) —
  coverage matrices (platform × severity, detection type, maturity,
  telemetry requirement, false-positive rating, component), Priority
  Detection Packs (Tier 1: 32 highest-confidence/lowest-noise detections
  to deploy first; Tier 2: 99 more; Tier 3: 40 hunting/low-confidence
  searches) plus themed packs (Defense-Impairment, Persistence,
  Software Supply-Chain, Fleet-Wide Correlation, Credential Access,
  Identity & Privileged Access), a normalized field schema, and the
  risk-scoring/maturity-ladder reference.

This is a deliberately-scoped first release (171 detections, not padded to
an arbitrary target) covering every required section from the spec with
real, non-fabricated telemetry — extendable in future batches the same way
the ESXi catalogue grew from 18 to 31.

## Fortinet Security Fabric Threat Detection Library

`data/fortinet-detections.json` is a fourth, independent catalogue: 206
Splunk SPL detections covering the full Fortinet Security Fabric, with
FortiManager and fleet-wide management-plane compromise given explicit
extra weight — the Fortinet equivalent of the AAP/Satellite
management-plane problem in the Red Hat catalogue.

| Namespace | Product | Detections |
|---|---|---|
| `FGT-###` | FortiGate (admin auth/config, firewall policy, VPN, IPS, antivirus, application control, web/DNS filter, SSL inspection, C2/exfiltration) | 99 |
| `FMG-###` | FortiManager (auth, admin, device management, policy-package deployment, scripts, revision management) | 22 |
| `FWB-###` | FortiWeb (SQLi/XSS/command-injection/SSRF/XXE, web shells, credential stuffing, API abuse, WAF policy integrity) | 13 |
| `FML-###` | FortiMail (phishing, malware, spoofing/BEC, DLP, quarantine integrity) | 11 |
| `FAC-###` | FortiAuthenticator (auth, MFA fatigue, token management, LDAP/RADIUS/SAML, certificates) | 10 |
| `FEDR-###` | FortiEDR (malicious process, credential dumping, process injection, ransomware, network C2, prevention-policy integrity) | 10 |
| `FAZ-###` | FortiAnalyzer (auth, admin, log-source/retention/forwarding integrity, detection-content tampering) | 9 |
| `EMS-###` | FortiClient / FortiClient EMS (endpoint management, policy integrity, malware, ZTNA posture) | 8 |
| `FPX-###` | FortiProxy | 6 |
| `FSB-###` | FortiSandbox (verdicts, ransomware classification, evasion indicators) | 6 |
| `FNT-X-###` | Cross-product Security Fabric correlations | 12 |

Every entry follows `schema/fortinet-detection.schema.json` and is
CIM-compatible (100%). Two companion documents ship alongside the data:

- [`docs/fortinet-logging-requirements.md`](docs/fortinet-logging-requirements.md) —
  logging architecture per product, Splunk CIM mapping, normalized field
  schema, and a detailed detection gap analysis (what's observable
  directly vs. requires FortiEDR/FortiWeb/SSL inspection/DNS logging/
  external threat intel — including an explicit statement that this
  catalogue does not claim to reliably detect specific Fortinet CVEs by
  signature).
- [`docs/fortinet-detection-library.md`](docs/fortinet-detection-library.md) —
  coverage matrices, Priority Detection Packs (Tier 1: 43 detections,
  within the spec's requested 40–60 range, plus 7 themed packs), and the
  risk-scoring reference. All five named Security Fabric correlation
  chains from the spec are implemented (`FNT-X-004/007/008/009` plus
  `FNT-X-001/003` for the FortiManager chain).

This is a deliberately-scoped first release (206 detections against a
requested 500) for the same reason as the Red Hat catalogue: every entry
is genuinely distinct with real SPL and no fabricated Fortinet log IDs or
fields.

## Dell iDRAC Threat Detection Library

`data/idrac-detections.json` is a fifth, independent catalogue: 96
Splunk SPL detections treating iDRAC as Tier-0/Tier-1 out-of-band
management infrastructure, since compromise can bypass the operating
system entirely and provide power, console, firmware, and boot-level
control.

| Namespace | Platform | Detections |
|---|---|---|
| `IDRAC-###` | iDRAC core (auth, users, virtual console/media, power, boot, BIOS/UEFI, firmware, network, certificates, logging, SEL, storage/RAID, factory reset, fleet-wide) + Dell OpenManage Enterprise | 65 |
| `LC-###` | Lifecycle Controller (jobs, configuration profile import/export, inventory) | 6 |
| `REDFISH-###` | Redfish API | 6 |
| `IPMI-###` | IPMI | 6 |
| `RACADM-###` | RACADM | 5 |
| `DELL-X-###` | Cross-platform correlations | 8 |

Every entry follows `schema/idrac-detection.schema.json`. Per the spec's
own instruction that ATT&CK does not cleanly represent out-of-band/
firmware activity, 12 entries carry an `attack_mapping_note` field
explaining the closest-fit technique used (most commonly `T1200`
Hardware Additions for virtual media, and `T1542` Pre-OS Boot for boot/
BIOS-security changes) rather than forcing a poor fit or inventing an ID.

The two flagship attack chains named explicitly in the spec are both
implemented as full sequence/correlation detections: **Virtual Media
mount → one-time boot override → reboot** (`IDRAC-032`, elevated to a
cross-platform incident view in `DELL-X-001`) and **privileged login →
storage deletion → power cycle → boot failure** (`DELL-X-005`). See
[`docs/idrac-detection-library.md`](docs/idrac-detection-library.md) for
coverage matrices, Priority Detection Packs (Tier 1: 25 detections, 7
themed packs), an explicit table mapping all ten of the spec's named
priority patterns to their detection IDs, and the detection gap analysis.

This is a deliberately-scoped first release (96 detections against a
requested 250) for the same reason as the Red Hat and Fortinet
catalogues — every one of the ten explicitly-prioritized attack patterns
has dedicated, full-depth coverage; the remaining breadth is extendable
in future batches.

## HPE iLO Threat Detection Library

`data/ilo-detections.json` is a sixth, independent catalogue: 107
Splunk SPL detections treating HPE iLO as Tier-0/Tier-1 out-of-band
management infrastructure, since compromise can bypass the operating
system entirely and provide power, console, firmware, boot, and
hardware-level control — the same conceptual model used for the Dell
iDRAC catalogue.

| Namespace | Platform | Detections |
|---|---|---|
| `ILO-###` | iLO core (auth, users, directory auth, power, boot configuration, network, management services, certificates, syslog/audit tampering, Intelligent Provisioning, storage, config export/import, reset, physical security, Compute Ops Management, fleet-wide) | 50 |
| `RC-###` | Remote Console | 7 |
| `VMEDIA-###` | Virtual Media | 5 |
| `FW-###` | Firmware / UEFI / BIOS / Secure Boot / TPM | 8 |
| `HREDFISH-###` | Redfish API | 8 |
| `IML-###` | Integrated Management Log | 8 |
| `AHS-###` | Active Health System | 5 |
| `ONEVIEW-###` | HPE OneView | 8 |
| `HPE-X-###` | Cross-platform correlations | 8 |

Note the `HREDFISH-###` namespace (not `REDFISH-###`, which the spec
literally names): Redfish is a cross-vendor DMTF standard also exposed
by Dell iDRAC, and `schema/idrac-detection.schema.json` already claims
`REDFISH-###` for that catalogue's own Redfish detections. Since all
detection IDs must be globally unique across the combined `index.html`
library, this catalogue's Redfish namespace was renamed to `HREDFISH-###`
to avoid a real ID collision (verified: `REDFISH-001` through
`REDFISH-006` in the iDRAC catalogue vs. `HREDFISH-001` through
`HREDFISH-008` here — zero overlap across all 761 combined-library IDs).

Every entry follows `schema/ilo-detection.schema.json`. Per the spec's
own instruction that ATT&CK does not cleanly represent out-of-band/
firmware activity, 6 entries carry an `attack_mapping_note` field
explaining the closest-fit technique used (most commonly `T1200`
Hardware Additions for virtual media, and `T1542` Pre-OS Boot for boot/
BIOS-security changes) rather than forcing a poor fit or inventing an ID.
Separately, `T1562` (Impair Defenses) — the technique that would most
naturally fit some anti-forensics detections — is absent from this
deployment's validated MITRE technique cache, so those entries cite the
validated `T1070` (Indicator Removal) instead rather than ship an
unverified ID.

The flagship attack chains named explicitly in the spec are all
implemented as full sequence/correlation detections: **Virtual Media
mount → one-time boot override → reboot** (`VMEDIA-003`, elevated to a
cross-platform incident view in `HPE-X-001`), **privileged login →
storage deletion → power cycle → boot failure** (`HPE-X-005`), and
**new OneView admin/token → fleet-wide push** (`HPE-X-006`), alongside
an iLO-to-hypervisor pivot chain (`HPE-X-002`), an identity-compromise-
to-iLO chain (`HPE-X-003`), a coordinated anti-forensics correlation
(`HPE-X-004`), an OOB-access-to-OS-persistence chain (`HPE-X-007`), and
a cross-vendor iLO/iDRAC coordinated-activity correlation (`HPE-X-008`).
See [`docs/ilo-detection-library.md`](docs/ilo-detection-library.md) for
coverage matrices, Priority Detection Packs (Tier 1: 25 detections, 7
themed packs), an explicit table mapping all ten of the spec's named
priority patterns to their detection IDs, and the detection gap analysis.

This is a deliberately-scoped first release (107 detections against a
requested 250) for the same reason as the Red Hat, Fortinet, and Dell
iDRAC catalogues — every one of the ten explicitly-prioritized attack
patterns has dedicated, full-depth coverage; the remaining breadth
(per-Redfish-endpoint coverage, HPE Compute Ops Management depth,
exhaustive OneView breadth) is extendable in future batches.

## Windows DHCP Server Threat Detection Library

`data/dhcp-detections.json` is a seventh, independent catalogue: 169
Splunk SPL detections treating Windows DHCP Server as critical network
identity/configuration infrastructure, since compromise can redirect
DNS, gateways, proxy settings, routes, and other network parameters for
every endpoint that leases from it.

| Namespace | Scope | Detections |
|---|---|---|
| `DHCP-###` | Core: service security, scopes, address pools, exclusions, reservations, options (DNS/gateway/route/PXE), policies, filters, lease behavior/starvation, decline/NACK abuse, DHCPv6, process execution, remote admin, registry, database/backup, behavioral, fleet-wide, destructive | 100 |
| `DHCP-DNS-###` | DNS option redirection + dynamic DNS updates + update credential security | 12 |
| `DHCP-FO-###` | DHCP failover | 12 |
| `DHCP-NET-###` | Rogue DHCP, spoofing/MITM, snooping, relay, NAC correlation | 11 |
| `DHCP-PS-###` | PowerShell administration + netsh dhcp | 10 |
| `DHCP-AD-###` | Active Directory server authorization | 9 |
| `DHCP-AUD-###` | DHCP audit-logging tampering / anti-forensics | 9 |
| `DHCP-X-###` | Cross-platform correlations | 6 |

Every entry follows `schema/dhcp-detection.schema.json`. Per the spec's
own instruction that ATT&CK does not map cleanly onto every DHCP-specific
behavior: DHCP option redirection (DNS/gateway/route) uses `T1557`
(Adversary-in-the-Middle) as the closest fit; rogue DHCP servers use the
ATT&CK sub-technique built specifically for this, `T1557.003` (DHCP
Spoofing); and PXE boot-server/file redirection uses `T1542` (Pre-OS
Boot), consistent with the iDRAC/iLO catalogues' rationale.

The flagship attack chains named explicitly in the spec are all
implemented as full sequence/correlation detections: **DNS option
redirection → client resolution shift** (`DHCP-X-002`), **gateway
poisoning → new next-hop traffic** (`DHCP-X-003`), **PXE option change →
boot → provisioning activity** (`DHCP-X-004`), **rogue DHCP OFFER →
client ACK → rogue DNS/gateway use** (`DHCP-X-005`), and **DHCP
starvation → legitimate client failure** (`DHCP-X-006`), alongside an
AD-privilege-escalation-to-DHCP-manipulation chain (`DHCP-X-001`). See
[`docs/dhcp-detection-library.md`](docs/dhcp-detection-library.md) for
coverage matrices, Priority Detection Packs (Tier 1: 40 detections, 9
themed packs), an explicit table mapping all fourteen of the spec's named
priority patterns to their detection IDs, and the detection gap analysis.

This is a deliberately-scoped first release (169 detections against a
requested 250) for the same reason as the other large-master-prompt
catalogues in this library — every one of the specification's named
highest-value patterns has dedicated, full-depth coverage; remaining
breadth (exhaustive per-vendor switch DHCP-snooping syntax, NAC-vendor-
specific integration depth) is extendable in future batches.

## Windows RDP Threat Detection Library

`data/rdp-detections.json` is an eighth, independent catalogue: 94
Splunk SPL detections treating RDP as both a legitimate administrative
capability and a major post-compromise lateral-movement and access
mechanism.

| Namespace | Scope | Detections |
|---|---|---|
| `RDP-###` | Core: lateral movement (fan-out/fan-in/concurrent/impossible-travel), behavioral baselines, ransomware/exfiltration correlation, alternative-client classification | 18 |
| `RDP-TS-###` | Session lifecycle, reconnect, shadowing, hijacking (tscon.exe), mstsc, .rdp files, redirection | 16 |
| `RDP-CFG-###` | NLA/CredSSP/Restricted Admin, enablement, port, firewall, GPO, group membership | 14 |
| `RDP-AUTH-###` | Authentication failures, brute force, password spraying, success-after-failure, behavioral | 12 |
| `RDP-NET-###` | Internet exposure, port scanning, tunneling (SSH/portproxy/chisel/ligolo), certificates | 12 |
| `RDP-GW-###` | RD Gateway, RD Web Access, Connection Broker, RemoteApp | 10 |
| `RDP-PROC-###` | Process execution after RDP: discovery, credential access, persistence, defense evasion, lateral pivot | 6 |
| `RDP-X-###` | Cross-platform correlations | 6 |

Every entry follows `schema/rdp-detection.schema.json`. Every MITRE
technique cited (`T1021.001`, `T1078`/`T1078.002`, `T1110`/`T1110.003`,
`T1563`/`T1563.002` for session hijacking, and others) was already
present in the validated technique cache — no unmapped-technique
substitutions were needed for this catalogue.

The flagship attack chains named explicitly in the spec are all
implemented as full cross-platform correlations: **VPN compromise →
RDP fan-out** (`RDP-X-001`), **AD privilege escalation → RDP**
(`RDP-X-002`), **RDP compromise → credential theft** (`RDP-X-003`),
**RDP compromise → persistence** (`RDP-X-004`), **RDP compromise →
ransomware** (`RDP-X-005`), and **firewall exposure → brute force →
compromise** (`RDP-X-006`), alongside the flagship single-catalogue
session-hijacking chain (`RDP-TS-010`, tscon.exe redirecting into
another user's session — the technique behind SYSTEM-to-Domain-Admin
session takeover). See
[`docs/rdp-detection-library.md`](docs/rdp-detection-library.md) for
coverage matrices, Priority Detection Packs (Tier 1: 20 detections, 8
themed packs), an explicit table mapping the spec's named priority
patterns to their detection IDs, and the detection gap analysis.

This is a deliberately-scoped first release (94 detections against a
requested 300) for the same reason as the other large-master-prompt
catalogues in this library — every one of the specification's named
highest-value patterns has dedicated coverage; remaining breadth
(exhaustive RD Web/Broker/RemoteApp sub-scenarios, printer/smart-card/
audio redirection depth) is extendable in future batches.

## VMware Cloud Foundation Threat Detection Library

`data/vcf-detections.json` is a ninth, independent catalogue: 162
Splunk SPL detections covering the VCF-specific management and
automation planes — SDDC Manager, NSX, vSAN encryption/KMS, VCF
Operations, VCF Operations for Logs, VCF Automation, VCF Salt, HCX, and
Tanzu/Kubernetes — deliberately **not** re-covering vCenter/ESXi
hypervisor-layer detections already provided by `data/detections.json`
and the Aria growth batch (see the scope note in
[`docs/vcf-detection-library.md`](docs/vcf-detection-library.md)).

| Namespace | Scope | Detections |
|---|---|---|
| `NSX-###` | Authentication/RBAC, Distributed Firewall, Gateway Firewall, NAT, routing, segments, Edge, IDS/IPS, security groups, logging | 35 |
| `VCF-###` | SDDC Manager authentication/administration, workload domains, hosts, lifecycle management, software supply chain | 25 |
| `SALT-###` | Salt Master/Minion authentication, key management, remote execution, state management, reactor, trust | 20 |
| `AUTO-###` | VCF Automation credentials, blueprints, orchestration, deployments, governance, extensibility | 15 |
| `VCF-X-###` | Cross-platform correlations | 15 |
| `VSAN-###` | vSAN encryption, KMS, disk groups, storage policy, cluster, file services, iSCSI | 12 |
| `OPS-###` | VCF Operations authentication, alerting, adapters, RBAC | 10 |
| `LOGS-###` | VCF Operations for Logs ingestion, retention, forwarding, content packs | 10 |
| `HCX-###` | Site pairing, network extension, migration/exfiltration | 10 |
| `K8S-###` | Tanzu Supervisor/guest clusters: RBAC, workload security, secrets, admission control | 10 |

Every entry follows `schema/vcf-detection.schema.json`, which uses a
`vcf_product` field (not `platform`) to match the specification's own
terminology. Every MITRE technique cited was already present in the
validated technique cache except for "impaired security control"
detections, which cite `T1070` (Indicator Removal) rather than the
uncached `T1562` (Impair Defenses) — the same substitution used
throughout this library.

All six of the specification's named attack-path chains are implemented
as full cross-platform correlations: the **ransomware kill-chain**
(`VCF-X-001`), **management-plane-compromise chain** (`VCF-X-002`),
**NSX-segmentation-bypass chain** (`VCF-X-003`), **automation-compromise
chain** (`AUTO-015`, cross-referenced as `VCF-X-004`), and
**Salt-compromise chain** (`SALT-018`, cross-referenced as `VCF-X-005`),
plus additional named chains for **KMS compromise → encryption impact**
(`VCF-X-007`), **software supply chain** (`VCF-X-008`), **HCX-enabled
exfiltration** (`VCF-X-009`), **anti-forensics/logging impairment**
(`VCF-X-010`), and **fleet-wide simultaneous-anomaly correlation**
(`VCF-X-013`). See
[`docs/vcf-detection-library.md`](docs/vcf-detection-library.md) for
coverage matrices, Priority Detection Packs (Tier 1: 35 detections, 12
themed packs), the full VCF Attack-Path Matrix, and the detection gap
analysis explaining exactly what this catalogue depends on the base
ESXi/Aria catalogues to provide.

This is a deliberately-scoped release (162 detections against a
requested 500, and deliberately omitting the `VC-###`/`ESXI-###`
namespaces named in the specification) for the same reason as the other
large-master-prompt catalogues in this library — building genuinely new,
MITRE-validated detections in the areas not already covered, rather than
padding the count with restatements of the existing vCenter/ESXi
catalogues.

## Splunk Platform Threat Detection Library

`data/splunk-detections.json` is a tenth, independent catalogue: 337
Splunk SPL detections that flip this repo's usual direction — instead of
using Splunk to detect threats against some other platform, this
catalogue detects attacks against, abuse of, compromise of, or suspicious
administrative activity within **Splunk itself** (Splunk Cloud, Splunk
Enterprise, Splunk Enterprise Security, Splunk SOAR, forwarders, and the
management tier), treating Splunk as Tier-0/Tier-1 security
infrastructure whose compromise can suppress telemetry, alter or delete
detections, exfiltrate indexed data, or blind the SOC entirely.

| Namespace | Scope | Detections |
|---|---|---|
| `SPL-SEARCH-###` | Search abuse, sensitive-data discovery, export/exfiltration, resource abuse, real-time/scheduled searches | 30 |
| `SPL-AUTH-###` | Local/SAML/LDAP authentication, brute force, SSO bypass, break-glass, user management | 25 |
| `SPL-KO-###` | Knowledge objects: detection tampering, macros, lookups/allowlists, field extraction, data models, dashboards | 25 |
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
| `SPL-CONF-###` | High-risk configuration file tampering | 15 |
| `SPL-DS-###` | Deployment Server (fleet management plane) | 12 |
| `SPL-SH-###` | Search Head, Search Head Cluster, SHC Deployer | 12 |
| `SPL-IDX-###` | Indexers, indexer-cluster peer tampering | 12 |
| `SPL-CM-###` | Cluster Manager | 8 |
| `SPL-KV-###` | KV Store | 8 |

Every entry follows `schema/splunk-platform-detection.schema.json`, which
uses `platform` (Splunk Cloud / Splunk Enterprise / Hybrid / Enterprise
Security / SOAR / Forwarder / Management Tier) and
`deployment_applicability` fields — not ID prefix — as the authoritative
Cloud-vs-Enterprise signal, since the specification's `SPL-ENT-###`
namespace is folded into whichever namespace actually matches each
detection's subject rather than kept as a separate catch-all (see the
scope note in `docs/splunk-platform-detection-library.md`). Every MITRE
technique cited was validated against the cached technique corpus;
"impaired security control" detections cite `T1070` (Indicator Removal)
rather than the uncached `T1562` (Impair Defenses), the same substitution
used throughout this library.

All ten named attack paths from the specification's Attack-Path Matrix
are implemented as `SPL-X-###` correlations — Identity → Splunk Admin,
Splunk Admin → Detection Tampering, Splunk Admin → Sensitive Data, App →
Server Execution, Deployment Server → Forwarder Fleet, Heavy Forwarder →
Data Diversion, Search Head → Detection/Search Abuse, HEC → Data
Poisoning, Data Pipeline → Logging Blind Spot, and Enterprise Security →
SOC Defense Evasion — plus ten further named chains (hybrid Cloud/on-prem,
data exfiltration, log suppression, search resource exhaustion,
on-premises host compromise, multi-stack attacks, consolidated
persistence, a ransomware-style chain against Splunk itself, and a
fleet-wide top-level escalation correlation). See
[`docs/splunk-platform-detection-library.md`](docs/splunk-platform-detection-library.md)
for coverage matrices, the full Cloud-vs-Enterprise applicability matrix,
Priority Detection Packs (Tier 1: 55 detections, 11 themed packs), the
complete Attack-Path Matrix, and the detection gap analysis covering
exactly what Splunk Cloud does and does not expose to the customer.

This is a deliberately-scoped release (337 detections against a
requested 500) for the same reason as the other large-master-prompt
catalogues in this library — every one of the specification's 20
requested namespaces and every named attack-path chain has dedicated,
MITRE-validated coverage; padding toward 500 would have meant inventing
Splunk internal indexes, REST endpoints, or configuration files that
don't exist.

## Active Directory Threat Detection Library

`data/ad-detections.json` is an eleventh, independent catalogue: 332
Splunk SPL detections covering attacks against, abuse of, or suspicious
administrative activity within Active Directory Domain Services, treated
throughout as Tier-0 identity infrastructure — Kerberos, NTLM, LDAP,
Group Policy, domain/forest trusts and SIDHistory, privileged groups and
AdminSDHolder, delegation (unconstrained/constrained/RBCD), AD CS
certificate abuse, LAPS/gMSA managed-password access, and the domain
controllers themselves.

| Namespace | Scope | Detections |
|---|---|---|
| `AD-KRB-###` | Kerberos: TGT/service-ticket anomalies, Kerberoasting, AS-REP roasting, Golden/Silver Ticket, Pass-the-Ticket, Overpass-the-Hash, krbtgt integrity | 35 |
| `AD-AUTH-###` | Authentication: failed logons, password spray, lockouts, privileged-account logons, DC interactive logon | 30 |
| `AD-DC-###` | Domain controller integrity: promotion/demotion, DSRM, NTDS/LSASS access, service/process tampering, backup/restore, logging impairment | 30 |
| `AD-GPO-###` | Group Policy: CRUD, link scope, security filtering, SYSVOL/GPP tampering, fleet-wide chains | 25 |
| `AD-USER-###` | User accounts: creation, enable/disable, deletion, password reset, sensitive UAC flag changes | 20 |
| `AD-GRP-###` | Privileged groups: Domain/Enterprise/Schema Admins, Operators groups, nested-group abuse, AdminSDHolder/SDProp | 20 |
| `AD-ACL-###` | ACL/ACE and object-owner abuse: GenericAll/WriteDACL/WriteOwner/ResetPassword, DCSync-rights grant | 20 |
| `AD-CRED-###` | Credential access: SAM/SECURITY/SYSTEM hive dumping, LSASS memory access, DPAPI theft, ticket export | 20 |
| `AD-X-###` | Cross-platform identity correlation chains (VPN, RDP, vCenter, backup, iLO/iDRAC, DHCP, Fortinet, cloud identity) | 20 |
| `AD-NTLM-###` | NTLM: downgrade detection, relay indicators, machine-account abuse, pass-the-hash | 15 |
| `AD-COMP-###` | Computer accounts: MachineAccountQuota abuse, domain join/leave, RBCD staging | 15 |
| `AD-REPL-###` | Replication: DCSync (rights-use, kept separate from rights-grant), DCShadow indicators, FSMO | 15 |
| `AD-DELEG-###` | Kerberos delegation: unconstrained, constrained, resource-based constrained delegation, S4U2Self/S4U2Proxy chains | 15 |
| `AD-LDAP-###` | LDAP: unsigned binds, channel binding, anonymous binds, BloodHound-pattern enumeration | 15 |
| `AD-PERSIST-###` | Directory-level persistence: SSP/AP registration, WMI subscriptions, Shadow Credentials, AD CS abuse | 15 |
| `AD-TRUST-###` | Domain/forest trusts and SIDHistory: creation, SID-filtering weakening, cross-trust privileged authentication | 12 |
| `AD-LAPS-###` | LAPS and gMSA managed-password access: unauthorized reads, bulk reads, retrieval-delegation grants | 10 |

Every entry follows `schema/ad-detection.schema.json`, honors the
specification's explicit detection-limitation rules (4769 is never
treated as proof of Kerberoasting alone; Golden Ticket/Silver
Ticket/DCShadow detections are explicitly marked indirect/best-effort via
an `attack_mapping_note` field; DCSync rights-grant and rights-use are
tracked as two separate detections and correlated, never conflated), and
never surfaces credential material (passwords, hashes, ticket blobs,
LAPS/gMSA secrets) in any SPL output. As with every other catalogue in
this library, "impaired security control" detections cite `T1070`
(Indicator Removal) rather than the uncached `T1562` (Impair Defenses).

The full Attack-Path Matrix from the specification is implemented — User
→ Privileged Group, User → ACL Abuse, User → DCSync, User → RBCD,
MachineAccountQuota → RBCD, User → SPN → Kerberoast, GPO → Fleet,
AdminSDHolder → Persistent Privilege, Trust → Cross-Forest Privilege, AD
CS → Certificate Privilege, LAPS → Local Admin, gMSA → Service Account,
vCenter/Backup → NTDS Offline Access, VPN → Privileged AD, RDP → AD
Escalation, plus a ransomware-against-identity chain, a DC-destruction
chain, and virtualized-DC correlations — as `AD-X-###` cross-platform
correlations and same-domain chains embedded directly in their natural
namespace. See
[`docs/ad-detection-library.md`](docs/ad-detection-library.md) for
coverage matrices, Priority Detection Packs (Tier 1: 82 detections, 11
named themed packs), the complete Attack-Path Matrix with telemetry
requirements and blind spots, and the detection gap analysis covering
exactly which findings require Directory Service Access auditing,
Sysmon/EDR, CA-specific auditing, or integration with the companion
VMware Aria/iLO/iDRAC catalogues.

This is a deliberately-scoped release (332 detections against a
requested 500+) for the same reason as the other large-master-prompt
catalogues in this library — every one of the specification's 17
requested namespaces and every named attack-path chain has dedicated,
MITRE-validated coverage; padding toward 500 would have meant inventing
Windows Event IDs or AD schema attributes that don't exist.

## Splunk Security Content (ESCU) Catalogue

`data/splunk-escu-detections.json` is a twelfth catalogue, and a
structurally different one from the other eleven: it is not authored for
this project. It's a curated, schema-converted subset of 2,012 detections
from Splunk's own official, Apache-2.0-licensed
[`security_content`](https://github.com/splunk/security_content) project
(also known as Splunk Enterprise Security Content Updates, or ESCU) —
production SPL that ships in Splunk's own Splunkbase app, not this
library's own analysis. It draws from five upstream source directories in
eight batches: `detections/endpoint` contributed three — Windows-scoped
(265 entries, `component: "Windows Endpoint"`), Linux-scoped (185
entries, `component: "Linux"`, filtered on the project's own `linux_*.yml`
naming convention), and a third batch bringing in every remaining
qualifying file (1,014 entries, `component: "Windows Endpoint"` (965),
`"macOS"` (13), `"Cisco Isovalent"` (10), `"Cisco NVM"` (14), `"CrowdStrike"` (9,
`crowdstrike`-prefixed identity/alert-stream correlators), or `"Linux"`
(3)) — `detections/application` contributed
two — a first, hand-curated batch (29 entries, VMware ESXi syslog and
Splunk's own internal telemetry, `component: "ESXi"` or `"Splunk
Platform"`) and a second batch bringing in everything else the directory
has since grown to include (83 entries, identity-provider/Cisco-appliance/
AI-LLM-abuse telemetry, `component:` one of 12 named vendors — `"Okta"`,
`"Cisco Duo"`, `"Cisco ASA"`, `"AWS Bedrock"`, `"MCP"`, and others — or
generic `"Application"`) — `detections/network` (77 entries,
Cisco/network-perimeter and network-sensor telemetry, `component: "Cisco
Network"`, `"Windows Network Telemetry"`, `"F5 BIG-IP"`, or generic
`"Network"`), `detections/cloud` (283 entries, cloud-identity and
cloud-infrastructure telemetry, `component: "AWS"`, `"Azure"`,
`"Microsoft 365"`, `"Google Cloud Platform"`, `"Google Workspace"`,
`"Kubernetes"`, `"GitHub"`, or generic `"Cloud"`), and `detections/web`
(76 entries, web-application CVE-exploit-signature telemetry, `component:`
one of 14 named vendors — `"Ivanti"`, `"Citrix"`, `"Atlassian
Confluence"`, `"JetBrains TeamCity"`, `"Zscaler"`, and others — or generic
`"Web"`).

| Namespace | Primary MITRE tactic | Detections |
|---|---|---|
| `ESCU-STEALTH-###` | Stealth | 328 |
| `ESCU-IMPAIR-###` | Defense Impairment | 314 |
| `ESCU-EXEC-###` | Execution | 221 |
| `ESCU-CRED-###` | Credential Access | 198 |
| `ESCU-DISC-###` | Discovery | 180 |
| `ESCU-PERSIST-###` | Persistence | 173 |
| `ESCU-INIT-###` | Initial Access | 135 |
| `ESCU-PRIV-###` | Privilege Escalation | 116 |
| `ESCU-C2-###` | Command and Control | 78 |
| `ESCU-IMPACT-###` | Impact | 76 |
| `ESCU-COLL-###` | Collection | 62 |
| `ESCU-LM-###` | Lateral Movement | 58 |
| `ESCU-EXFIL-###` | Exfiltration | 41 |
| `ESCU-RECON-###` | Reconnaissance | 21 |
| `ESCU-RESDEV-###` | Resource Development | 11 |

**Why the Windows endpoint batch exists alongside the AD/RDP/DHCP
catalogues rather than duplicating them:** the existing Windows-scoped
catalogues in this library detect from the *domain controller's*
perspective (Security event log, Directory Service Access auditing) —
Kerberos ticket anomalies, LDAP binds, GPO tampering, and so on. ESCU's
Windows endpoint content detects from the *host's* perspective (Sysmon,
EDR telemetry, process execution) — credential-dumping tools actually
running, LOLBins being abused, C2 beacons on the wire. A targeted content
check against every candidate file (searching for Kerberoasting/DCSync/
Golden-Ticket/Silver-Ticket/AS-REP/krbtgt overlap) found only 16 genuinely
duplicative detections out of ~1,250 candidates, which were excluded from
the curated set; the rest is complementary telemetry, not a restatement of
the AD catalogue.

**Why the ESXi/Splunk application batch exists alongside this library's
own ESXi/Splunk catalogues rather than duplicating them:** the 23 ESXi
entries detect via forwarded **syslog** (`` `esxi_syslog` ``), while this
library's own 31-entry ESXi/Splunk catalogue detects via `shell.log`/
`hostd.log` pulled directly off the host — a different telemetry
dependency for many of the same behaviors (firewall disable, VIB
tampering, lockdown mode), useful to environments with only basic syslog
forwarding configured. The 6 Splunk entries are real exploit-signature
detections for specific, named Splunk CVEs (XSLT RCE, arbitrary file
write, debug-log information disclosure, user enumeration, dashboard XSS)
— an angle this library's own 337-entry Splunk Platform catalogue
deliberately doesn't cover (it's scoped to administrative/configuration
abuse and behavioral anomalies, not CVE-specific signatures).

**The network and Linux batches are different from the first two: no
topical-overlap curation was applied to either**, per explicit
instruction — every file that met this library's two hard, universal
bars (`status: production`, a validated non-empty MITRE technique
mapping) was brought in. For the network batch, 77 of 101 files in
`detections/network` qualified; a number are topically adjacent to
existing content (rogue-DHCP, RDP brute force) but read from a
network-sensor perspective (Zeek/Suricata/Splunk Stream watching the
wire) rather than the Windows-Event-Log perspective this library's own
DHCP/RDP catalogues use.

**The Linux batch needs a more direct caveat than "different telemetry
layer."** All 185 `linux_*.yml` files in `detections/endpoint` already
met both hard bars with zero exclusions, so all 185 were brought in. But
unlike the ESXi case, this batch shares the *same* telemetry mechanism
(Linux auditd) as significant parts of this library's own 171-entry Red
Hat catalogue — `RHEL-025` ("auditd Service Stopped or Failed"),
`RHEL-044` ("Crontab or /etc/cron.d Entry Added"), and `RHEL-017` ("SSH
authorized_keys Created or Modified") are genuine near-duplicates of
entries in this batch. This was called out plainly rather than papered
over with a telemetry-difference argument that doesn't actually apply
here; if deploying both catalogues, expect real overlap in the
auditd-based Linux/RHEL space and plan rule deconfliction yourself — see
`docs/splunk-escu-detection-library.md` for the specific overlapping IDs.

**The cloud batch, unlike the Linux batch, needs no overlap caveat at
all.** All 283 qualifying files from `detections/cloud` (of 318; 33
`experimental` and 2 with no MITRE mapping excluded) were brought in with
no topical curation, same as the network and Linux batches — but no
existing catalogue in this library covers AWS, Azure, Microsoft 365,
Google Cloud Platform, Google Workspace, Kubernetes, or GitHub as an
identity/infrastructure platform, so this is genuinely new ground, not a
second angle on something already here. Search-cost profile is also
notably different from every prior batch: cloud-provider audit-log
schemas (CloudTrail, Azure AD, the O365 Unified Audit Log, Kubernetes
audit events) don't map onto Splunk's CIM data models, so this batch is
mostly raw `search`/`stats` SPL rather than `| tstats`-accelerated.

**The web batch is mostly new vendor territory, with two complementary
exceptions.** 76 of 85 files in `detections/web` qualified (8
`experimental` and 1 with no MITRE mapping — `f5_tmui_authentication_
bypass.yml` — excluded), with no topical curation applied beyond the two
hard bars, same as the network/Linux/cloud batches. Unlike those batches,
`detections/web` is organized around individual vendor products with
known CVEs rather than a platform or telemetry source, so `component`
reflects the specific product (Ivanti, Citrix, Atlassian Confluence,
JetBrains TeamCity, Adobe ColdFusion, CrushFTP, ConnectWise ScreenConnect,
Apache Tomcat, Microsoft SharePoint, Microsoft Exchange) or Zscaler proxy
telemetry. No existing catalogue in this library covers any of those
vendors, so 66 of the batch's 76 entries are unambiguously new coverage.
The 2 Fortinet entries and 3 VMware entries are the exceptions, and both
resolve the same way the application batch's Splunk entries did: this
library's own 206-entry Fortinet catalogue explicitly documents that it
does not claim CVE-specific exploit-signature detection, and these 2
Fortinet CVE detections fill exactly that stated gap; the 3 VMware
entries detect specific vCenter/ESXi CVE exploitation rather than
post-compromise host behavior, distinct from both this library's own
31-entry ESXi/Splunk catalogue and the application batch's 23 ESXi
entries above.

**The second application batch returns to `detections/application`,
which has grown from 31 files (all ESXi/Splunk-named, the entirety of
the directory at the time of the first batch) to 140 — this batch brings
in every one of the 111 not-yet-imported files that qualifies (76
`experimental` and 7 with no MITRE mapping excluded, 83 kept), no
topical curation, same as the network/Linux/cloud/web batches.** Most of
it is new territory: Okta and PingID (17 + 4 entries) are this library's
first dedicated identity-provider coverage; AWS Bedrock, MCP, and
Microsoft 365 Copilot (7 + 5 + 4 entries) are its first coverage of
AI/LLM abuse at all (prompt injection, jailbreak attempts, model-inference
abuse, agent tool-call abuse); Cisco Duo (14 entries) is a genuinely new
product line (MFA), not represented anywhere else. The Cisco ASA/IOS
XE/SD-WAN entries (13 + 9 + 2) expand, rather than duplicate, this
library's existing 46-entry Cisco Network component — different product
lines (the older ASA firewall, IOS XE device-level CLI events, SD-WAN
vManage auth) from the network/web batches' Secure Firewall/Snort
IPS/Secure Access content, with zero duplicate `source_id`s. The one new
CrushFTP and one new Ivanti entry are complementary to their same-vendor
web-batch entries (different CVE/product — CrushFTP server-side template
injection vs. the web batch's authentication-bypass and
simultaneous-session entries; Ivanti VTM vs. the web batch's Ivanti
Connect Secure/Policy Secure). One thing worth flagging plainly: the
batch's generic `Application`-component password-spray entries
(`detect_password_spray_attempts.yml`,
`detect_distributed_password_spray_attempts.yml`) touch the same general
behavior as this library's own `AD-AUTH-003/004/005`, though via a
different mechanism — a 3-sigma statistical-anomaly search against
Splunk's generic CIM Authentication data model versus the AD catalogue's
static-threshold rules built around domain-controller Security-log
auditing. Complementary methodology, not a raw duplicate, but worth
knowing if deploying both — see `docs/splunk-escu-detection-library.md`
for the full writeup.

**The third endpoint batch closes out `detections/endpoint` entirely —
1,014 of the 1,050 files left after the first two endpoint batches, no
topical curation, matching every other "add all" batch.** 965 join the
existing 265 curated `Windows Endpoint` entries (1,230 total) — this is
simply the rest of the same ~1,250-candidate pool the first batch scored
and capped, now brought in uncapped, pushing the catalogue's
distinct-MITRE-technique count from 272 to 358 (the largest jump of any
batch, since the original per-tactic caps left most of that surface
unrepresented by design). **This batch reopens the first batch's own
16 AD-overlap exclusions, by design** — because no topical curation is
applied, some of the exact files the first batch excluded for
duplicating this library's own `AD-KRB`/`AD-ACL`/`AD-REPL` content are
now included, e.g. `kerberoasting_spn_request_with_rc4_encryption.yml`
(now `ESCU-CRED-120`, overlapping `AD-KRB-010`) and
`windows_ad_domain_replication_acl_addition.yml` (now `ESCU-IMPAIR-166`,
overlapping `AD-ACL-010`). Same situation as the Linux batch's Red Hat
overlap, handled the same way: called out plainly rather than silently
re-excluded, since re-applying the first batch's curation would
contradict this batch's explicit "bring in everything" instruction. The
13 `macOS`, 10 `Cisco Isovalent`, 14 `Cisco NVM`, and 9 `CrowdStrike`
(Identity Protection/Falcon Stream) entries are all new territory — no
existing catalogue in this library covers macOS at all, and each of the
other three is a distinct telemetry source from every other
Cisco/CrowdStrike-named component already in this catalogue. See
`docs/splunk-escu-detection-library.md` for the full component-assignment
methodology and overlap writeup.

**Curation methodology:** of the ~1,250 Windows-scoped files in
`security_content/detections/endpoint`, the first batch keeps only
`status: production` content (excluding `experimental`), removes the 16
AD-overlap detections above, then scores and caps per primary MITRE
tactic so the result covers the full kill chain rather than skewing toward
whichever tactic Splunk's own contributors happened to write the most
detections for. The much smaller `detections/application` directory
(reviewed file-by-file rather than algorithmically scored) contributed a
second batch filtered to ESXi- and Splunk-named files, same
`status: production` and MITRE-mapping requirements applied, with two
files excluded (one `experimental`, one with no MITRE technique mapping).
The third batch takes every qualifying file from `detections/network`
(101 files; 22 `experimental` and 2 with no MITRE mapping excluded, 77
kept) with no further curation. The fourth batch takes every `linux_*.yml`
file from `detections/endpoint` (185 files, 0 excluded — all already met
both hard bars) with no further curation. The fifth batch takes every
qualifying file from `detections/cloud` (318 files; 33 `experimental` and
2 with no MITRE mapping excluded, 283 kept) with no further curation. The
sixth batch takes every qualifying file from `detections/web` (85 files;
8 `experimental` and 1 with no MITRE mapping excluded, 76 kept) with no
further curation. The seventh batch takes every not-yet-imported
qualifying file from `detections/application` (111 files; 76
`experimental` and 7 with no MITRE mapping excluded, 83 kept) with no
further curation. The eighth batch takes every not-yet-imported
qualifying file from `detections/endpoint` (1,050 files; 32 `experimental`
and 4 with no MITRE mapping excluded, 1,014 kept) with no further
curation, closing out the directory entirely. See
[`docs/splunk-escu-detection-library.md`](docs/splunk-escu-detection-library.md)
for the full methodology, severity/confidence/false-positive distributions,
and the "SPL notes" section explaining why this catalogue's SPL looks
different from the rest of the library's (`security_content_summariesonly`/
`security_content_ctime` macros, `` `<name>_filter` `` macros, and
`tstats`-against-accelerated-CIM-data-model queries all require the ESCU
Splunkbase app or the equivalent data models — see the Disclaimer section
below).

Every entry follows `schema/splunk-escu-detection.schema.json`, a superset
of this library's usual detection fields with dedicated provenance fields
(`source_id`, `source_url`, `source_version`, `source_author`,
`source_creation_date`, `analytic_story[]`) tracing every entry back to its
original upstream file. Severity, confidence, and risk-scoring are
**derived, not copied** — the upstream project doesn't use this library's
1–5×1–5×1–5 model, so these fields were computed from the source's `type`
field and primary MITRE tactic, then spot-checked; treat them as this
library's own risk assessment layered on top of Splunk's detection logic,
not something Splunk itself asserts.

## Cisco Network Device Threat Detection Library

`data/cisco-detections.json` is a thirteenth catalogue, and a different
kind of "new" from every one before it: it wasn't built from a spec or a
platform description — it was built by diffing this library against
itself. The **ATT&CK Coverage** modal's Cisco tab (see below) already
tracks every technique MITRE ATT&CK scopes to its `Network Devices`
platform against this library's Cisco-scoped ESCU content; that
comparison found 68 uncovered techniques, 62 of which MITRE itself has
published a real Detection Analytic for. This catalogue is those 62 —
the same "MITRE-driven gap fill" methodology this library used once
before for the original ESXi catalogue's second batch, applied here for
the first time to build an entirely new, standalone catalogue rather than
extend an existing one.

Twelve of the 62 entries go a step further and cite a specific,
MITRE-documented Cisco-targeting threat by name — verified against that
malware/campaign object's own MITRE `uses` relationship to the technique,
not inferred from the technique name alone:

- **SYNful Knock** (`S0519`) — the covert Cisco IOS firmware implant
  first documented publicly in 2015.
- **ArcaneDoor** (`C0046`) and its malware **Line Dancer** (`S1186`) and
  **Line Runner** (`S1188`) — a 2023–24 campaign targeting Cisco ASA/FTD
  devices specifically.
- **Salt Typhoon**'s **JumbledPath** (`S1206`) — a custom Go-based
  utility the PRC state actor used to obscure its network-device-focused
  operations.
- **KV Botnet Activity** (`C0035`) — a campaign against end-of-life
  SOHO/edge network equipment.

Every entry follows `schema/cisco-detection.schema.json`, uses the same
`CSCO-<TAC>-###` namespace convention (one namespace per primary MITRE
tactic) the Splunk ESCU catalogue uses, and carries a `mitre_analytics[]`
field citing the exact official MITRE Detection Analytic ID it's grounded
in — every SPL search here follows what that analytic actually describes,
not an independent guess. `component` splits by device/feature area:
`"Cisco IOS/IOS XE"` for router/switch firmware-and-boot-specific
techniques, `"Cisco ASA/FTD"` for firewall-specific techniques,
`"Cisco Network Device"` for behavior that spans the family. See
[`docs/cisco-detection-library.md`](docs/cisco-detection-library.md) for
the full methodology, coverage matrices, and the named-threat
cross-reference table.

Regenerating `data/mitre-attack-cisco.json` after this catalogue was
added shows the Cisco tab's coverage jump from 32/100 to **94/100** —
the six techniques still uncovered are the ones without a real MITRE
Detection Analytic to ground a detection in (`covered_by_library: false`
but `has_platform_analytic: false`), a genuine gap in MITRE's own
published analytic coverage rather than one this library chose not to
fill.

## Windows Endpoint Threat Detection Library

`data/windows-endpoint-detections.json` is a fourteenth catalogue, and
the same "MITRE-driven gap fill" methodology as the Cisco catalogue,
applied to the Windows platform. It exists because investigating "which
ATT&CK techniques is this library missing" surfaced a real bug first:
`data/mitre-attack-windows.json` predates the Splunk ESCU catalogue and
had never been re-cross-referenced against it, so it was only checking
coverage against the three dedicated Windows catalogues (AD/RDP/DHCP)
and missing the 1,236 ESCU entries whose `component` is `"Windows
Endpoint"` or `"Windows Network Telemetry"` — undercounting true
coverage by 174 techniques (87/474 reported vs. the accurate 261/474).
That was fixed as its own standalone correction first, with no detection
content changed.

The *real*, corrected gap is 213 techniques, 211 with a real MITRE
Detection Analytic. This catalogue closes the first 73 of those —
covering the **Persistence**, **Credential Access**, **Discovery**,
**Stealth**, and **Defense Impairment** tactics in full or near-full,
the ones with the strongest genuine Windows Event Log/Sysmon signal.
It deliberately leaves out gap techniques whose real detection surface
is network/DNS/proxy telemetry, email-gateway/O365 content, or
physical/hardware layers rather than Windows endpoint logs, and a
handful of Stealth sub-techniques (static file-obfuscation analysis,
EDR-API-level behaviors) that standard Windows Event Log fields don't
carry enough signal for — writing a search against a log source that
can't actually detect the behavior would be false coverage, not real
coverage. The remaining ~138-technique gap (Execution, Privilege
Escalation, Lateral Movement, Collection, Command and Control,
Exfiltration, Impact, Initial Access) is a candidate for a future batch.

Every entry follows `schema/windows-endpoint-detection.schema.json`,
uses the same `WEND-<TAC>-###` namespace convention (one namespace per
primary MITRE tactic) the Splunk ESCU and Cisco catalogues use, and
carries a `mitre_analytics[]` field citing the exact official MITRE
Detection Analytic ID it's grounded in. `component` is a single value,
`"Windows Endpoint"`, since the whole catalogue's scope is generic
Windows OS endpoint telemetry — the same domain as ESCU's `"Windows
Endpoint"` component, whose gap it closes. SPL is hand-authored against
plain Sysmon/Windows Security Event Log field names, not the ESCU app's
`tstats`/CIM/`security_content_*` macro conventions, since this
catalogue doesn't depend on that app. See
[`docs/windows-endpoint-detection-library.md`](docs/windows-endpoint-detection-library.md)
for the full methodology, scoping rationale, and coverage matrices.

Regenerating `data/mitre-attack-windows.json` after this catalogue was
added shows the Windows tab's coverage jump from 261/474 to
**334/474**.

## Validations

Five catalogues back a third top-level page, **Validations**, alongside
Detections and Heat Coverage — this library's first entries in a new
content type, a **validation catalogue**, each converted from an
uploaded workbook of privileged-action test cases rather than
hand-authored:

- `data/rhel-privileged-action-validations.json` (204 entries, platform `RHEL`)
- `data/fortigate-privileged-admin-validations.json` (146 entries, platform `FortiGate`)
- `data/cisco-sdwan-privileged-admin-validations.json` (145 entries, platform `Cisco SD-WAN`)
- `data/rhel-ipa-privileged-admin-validations.json` (139 entries, platform `IdM/IPA/FreeIPA`)
- `data/windows-privileged-admin-validations.json` (146 entries, platform `Windows Endpoint`)

A validation catalogue entry isn't a detection rule. It's a
test-execution reference: the exact command to trigger one privileged
action once in a lab or on a controlled device (`test_step`), how to
undo it (`rollback_step`), the platform telemetry expected to result,
and a one-shot `validation_spl` presence check — confirming an
*existing* detection actually fires, not a new production rule of its
own. See [`docs/validations.md`](docs/validations.md) for the full
rationale, the conversion methodology, and the discoveries made while
resolving each workbook's MITRE ATT&CK mappings against the live STIX
corpus rather than trusting them as given: all five workbooks' tactic
columns still used the pre-split "Defense Evasion" name, and all five
used technique IDs from the `T1562`/`T1060`/`T1070.001` family of
revoked/renumbered IDs that turned out to be stale in the current MITRE
release — the same broad "renumbered technique" problem this library
has now hit five times across its history (Aria, RHEL, FortiGate, Cisco
SD-WAN, RHEL IdM/IPA), with the Windows catalogue's conversion also
having to handle rows that cite two technique IDs in one cell.

The Validations page reuses the Detections page's design end to end
(search, collapsible filter sidebar, card grid, shared detail overlay)
but is a fully independent view — its own toolbar, its own state, no
data sharing with the fourteen detection catalogues — so neither page's
filtering or search state leaks into the other. All five validation
catalogues share this one page, one card grid, and a `Platform` filter
facet to tell them apart, the same "many sources, one page" pattern the
Detections page uses for its fourteen catalogues.

## Repository layout

```
VERSION                        Single source of truth for the project's current semver version (see Versioning below); tools/build.py stamps it into index.html.
CHANGELOG.md                   What changed at each version, in Keep a Changelog style.
data/detections.json           Canonical source of truth for the ESXi/Splunk catalogue.
data/aria-detections.json      Canonical data for the Aria Operations for Logs catalogue (generated - see below).
data/redhat-detections.json    Canonical source of truth for the Red Hat (RHEL/IdM/AAP/Satellite) catalogue.
data/fortinet-detections.json  Canonical source of truth for the Fortinet Security Fabric catalogue.
data/idrac-detections.json     Canonical source of truth for the Dell iDRAC catalogue.
data/ilo-detections.json       Canonical source of truth for the HPE iLO catalogue.
data/dhcp-detections.json      Canonical source of truth for the Windows DHCP Server catalogue.
data/rdp-detections.json       Canonical source of truth for the Windows RDP catalogue.
data/vcf-detections.json       Canonical source of truth for the VMware Cloud Foundation catalogue.
data/splunk-detections.json    Canonical source of truth for the Splunk Platform (self-protection) catalogue.
data/ad-detections.json        Canonical source of truth for the Active Directory catalogue.
data/splunk-escu-detections.json  Curated, schema-converted subset of splunk/security_content's Windows endpoint detections.
data/cisco-detections.json     Canonical source of truth for the Cisco Network Device catalogue (MITRE ATT&CK-driven gap fill).
data/windows-endpoint-detections.json  Canonical source of truth for the Windows Endpoint catalogue (MITRE ATT&CK-driven gap fill).
data/rhel-privileged-action-validations.json  Canonical data for the RHEL Privileged Action Validation catalogue — a distinct content type (validations, not detections; see docs/validations.md), shown on its own Validations page.
data/fortigate-privileged-admin-validations.json  Canonical data for the FortiGate Privileged Admin Action Validation catalogue — a second validation catalogue sharing the Validations page with the RHEL one, disambiguated by the platform field.
data/cisco-sdwan-privileged-admin-validations.json  Canonical data for the Cisco SD-WAN Privileged Admin Action Validation catalogue — a third validation catalogue sharing the Validations page, disambiguated by the platform field.
data/rhel-ipa-privileged-admin-validations.json  Canonical data for the RHEL IdM/IPA Privileged Admin Action Validation catalogue — a fourth validation catalogue sharing the Validations page, disambiguated by the platform field.
data/windows-privileged-admin-validations.json  Canonical data for the Windows Privileged Admin Action Validation catalogue — a fifth validation catalogue sharing the Validations page, disambiguated by the platform field.
data/mitre-attack-esxi.json    MITRE ATT&CK ESXi techniques + official Detection Analytics, coverage computed across the ESXi/Splunk and Aria catalogues.
data/mitre-attack-windows.json  MITRE ATT&CK Windows techniques + official Detection Analytics, coverage computed across the AD/RDP/DHCP catalogues, the ESCU catalogue's Windows Endpoint/Windows Network Telemetry entries, and the dedicated Windows Endpoint catalogue.
data/mitre-attack-cisco.json    MITRE ATT&CK "Network Devices" platform techniques + official Detection Analytics, coverage computed across the ESCU catalogue's Cisco Network/ASA/IOS XE/SD-WAN entries and the dedicated Cisco Network Device catalogue.
data/mitre-attack-universe.json  Full ATT&CK Enterprise technique/tactic universe (all platforms, parent-technique level) backing the Heat Coverage tab.
docs/aria-catalogue-source.md  Human-authored source markdown for the Aria catalogue.
docs/redhat-audit-policy.md    Consolidated auditd ruleset the Red Hat catalogue's RHEL detections depend on, by category.
docs/redhat-detection-library.md  Coverage matrices, Priority Detection Packs, and field-schema reference for the Red Hat catalogue.
docs/fortinet-logging-requirements.md  Logging architecture, CIM mapping, normalized field schema, and gap analysis for the Fortinet catalogue.
docs/fortinet-detection-library.md  Coverage matrices and Priority Detection Packs for the Fortinet catalogue.
docs/idrac-detection-library.md  Coverage matrices, Priority Detection Packs, and gap analysis for the Dell iDRAC catalogue.
docs/ilo-detection-library.md  Coverage matrices, Priority Detection Packs, and gap analysis for the HPE iLO catalogue.
docs/dhcp-detection-library.md  Coverage matrices, Priority Detection Packs, and gap analysis for the Windows DHCP Server catalogue.
docs/rdp-detection-library.md  Coverage matrices, Priority Detection Packs, and gap analysis for the Windows RDP catalogue.
docs/vcf-detection-library.md  Coverage matrices, Priority Detection Packs, VCF Attack-Path Matrix, and gap analysis for the VMware Cloud Foundation catalogue.
docs/splunk-platform-detection-library.md  Coverage matrices, Cloud-vs-Enterprise matrix, Priority Detection Packs, Attack-Path Matrix, and gap analysis for the Splunk Platform catalogue.
docs/ad-detection-library.md  Coverage matrices, Priority Detection Packs, Attack-Path Matrix, and gap analysis for the Active Directory catalogue.
docs/splunk-escu-detection-library.md  Curation methodology, coverage matrices, and attribution/license notes for the Splunk ESCU catalogue.
docs/cisco-detection-library.md  MITRE-gap-fill methodology, coverage matrices, and named-threat cross-references for the Cisco Network Device catalogue.
docs/windows-endpoint-detection-library.md  MITRE-gap-fill methodology, scoping rationale, and coverage matrices for the Windows Endpoint catalogue.
docs/validations.md            Why a validation catalogue is a distinct content type, source/conversion methodology, and MITRE ATT&CK resolution notes for the RHEL, FortiGate, Cisco SD-WAN, RHEL IdM/IPA, and Windows validation catalogues.
schema/detection.schema.json   JSON Schema for data/detections.json entries.
schema/aria-detection.schema.json  JSON Schema for data/aria-detections.json entries.
schema/redhat-detection.schema.json  JSON Schema for data/redhat-detections.json entries.
schema/fortinet-detection.schema.json  JSON Schema for data/fortinet-detections.json entries.
schema/idrac-detection.schema.json  JSON Schema for data/idrac-detections.json entries.
schema/ilo-detection.schema.json  JSON Schema for data/ilo-detections.json entries.
schema/dhcp-detection.schema.json  JSON Schema for data/dhcp-detections.json entries.
schema/rdp-detection.schema.json  JSON Schema for data/rdp-detections.json entries.
schema/vcf-detection.schema.json  JSON Schema for data/vcf-detections.json entries.
schema/splunk-platform-detection.schema.json  JSON Schema for data/splunk-detections.json entries.
schema/ad-detection.schema.json  JSON Schema for data/ad-detections.json entries.
schema/splunk-escu-detection.schema.json  JSON Schema for data/splunk-escu-detections.json entries.
schema/cisco-detection.schema.json  JSON Schema for data/cisco-detections.json entries.
schema/windows-endpoint-detection.schema.json  JSON Schema for data/windows-endpoint-detections.json entries.
schema/rhel-privileged-action-validation.schema.json  JSON Schema for data/rhel-privileged-action-validations.json entries.
schema/fortigate-privileged-admin-validation.schema.json  JSON Schema for data/fortigate-privileged-admin-validations.json entries.
schema/cisco-sdwan-privileged-admin-validation.schema.json  JSON Schema for data/cisco-sdwan-privileged-admin-validations.json entries.
schema/rhel-ipa-privileged-admin-validation.schema.json  JSON Schema for data/rhel-ipa-privileged-admin-validations.json entries.
schema/windows-privileged-admin-validation.schema.json  JSON Schema for data/windows-privileged-admin-validations.json entries.
index.template.html            Combined-library page shell (CSS/JS) with markers for all fourteen detection data files plus the validation data file.
index.html                     Generated: template + all fourteen detection data files plus the validation data file. The primary, combined, filterable page — the only page in the repo, since the standalone Aria-only page was removed.
tools/build.py                 Regenerates index.html from all fourteen detection data/*.json files plus data/rhel-privileged-action-validations.json.
tools/fetch_mitre_platform.py  Regenerates data/mitre-attack-<platform>.json from the official MITRE ATT&CK dataset.
tools/fetch_mitre_universe.py  Regenerates data/mitre-attack-universe.json (the full technique/tactic universe behind the Heat Coverage tab).
tools/import_aria_catalogue.py Regenerates data/aria-detections.json from docs/aria-catalogue-source.md.
```

`index.html` is generated, not hand-edited — see **Adding a new batch**
below. Whenever you touch any data file, re-run `tools/build.py` so the
combined page picks up the change.

### MITRE ATT&CK coverage data — Analytics, Detection Strategies, and Data Sources

The **ATT&CK Coverage** button in the header opens a per-platform coverage
browser backed by `data/mitre-attack-<platform>.json` files (currently
`esxi`, `windows`, `cisco`, `saas`, `identity-provider`, `containers`, `linux`, `iaas`, `office-suite`, and `macos`), each fetched independently at runtime —
they are *not* baked into the page, so any one can be refreshed without a
full rebuild. Each is built straight from MITRE's official STIX corpus
([mitre/cti](https://github.com/mitre/cti)) and contains, for that
platform:

- every non-deprecated **technique** MITRE scopes to the platform, its
  tactic(s), and whether this library currently has a detection for it
  (`covered_by_library`) — a live gap list for planning the next batch.
  For `esxi`, coverage is computed across `data/detections.json` and
  `data/aria-detections.json`; for `windows`, across
  `data/ad-detections.json`, `data/rdp-detections.json`, and
  `data/dhcp-detections.json` — the three dedicated Windows catalogues —
  plus the 1,236 `data/splunk-escu-detections.json` entries whose
  `component` is `"Windows Endpoint"` or `"Windows Network Telemetry"`,
  plus the dedicated 73-entry `data/windows-endpoint-detections.json`
  catalogue built specifically to close part of the gap this file
  identified. That ESCU cross-reference was missing for a long stretch of
  this project's history (the `windows` coverage file predates the ESCU
  catalogue and was never re-cross-referenced against it), which
  undercounted true coverage by 174 techniques — 87/474 reported vs. the
  accurate 261/474 before the Windows Endpoint catalogue closed a further
  73, landing coverage at 334/474 as a result (see the
  [Windows Endpoint Threat Detection Library](#windows-endpoint-threat-detection-library)
  section above for how the remaining 140 break down). Fixing the ESCU
  cross-reference was a standalone correction rather than folded into the
  detection-authoring batch, since it changed no detection content, only
  what the coverage file measures; for `cisco`, across the 70
  `data/splunk-escu-detections.json` entries whose
  `component` is `"Cisco Network"`, `"Cisco ASA"`, `"Cisco IOS XE"`, or
  `"Cisco SD-WAN"`, plus the entire 62-entry `data/cisco-detections.json`
  catalogue that was built specifically to close the gap this file
  identified — deliberately excluding the ESCU catalogue's other
  Cisco-branded components (`"Cisco Duo"`, `"Cisco Isovalent"`, `"Cisco
  NVM"`), which are genuinely Cisco products but not **Network Devices**
  platform telemetry (MFA/identity, container/eBPF, and a Windows
  endpoint agent, respectively) — including them would inflate the
  coverage count with techniques this library doesn't actually detect via
  network-device telemetry. Coverage stands at 94/100 as a result (see
  the [Cisco Network Device Threat Detection Library](#cisco-network-device-threat-detection-library)
  section above for how the remaining 6 break down). **MITRE has no
  dedicated "Cisco" platform** — `Network Devices` is the closest ATT&CK
  platform value (the one router/switch/firewall techniques are scoped
  to), so the `cisco` file's own `platform` metadata field and in-modal
  heading say "Network Devices" even though the tab is labeled "Cisco"
  for consistency with this library's own component naming. For `saas`,
  across the 157 `data/splunk-escu-detections.json` entries whose
  `component` is `"Microsoft 365"`, `"Microsoft 365 Copilot"`, `"Okta"`,
  `"PingID"`, `"Zscaler"`, `"GitHub"`, `"Google Workspace"`, or `"Cisco
  Duo"` — the entries that genuinely detect cloud-delivered,
  browser/API-accessed application telemetry — deliberately excluding
  this catalogue's self-hosted/on-premises-appliance components (Ivanti,
  Citrix, Atlassian Confluence, JetBrains TeamCity, Adobe ColdFusion,
  CrushFTP, Apache Tomcat, ConnectWise ScreenConnect, Microsoft
  SharePoint/Exchange, VMware, PTC Windchill) even though several share a
  broadly-scoped technique ID (e.g. T1078 Valid Accounts) with genuine
  SaaS techniques; including them naively raises the covered count from
  27/70 to a misleading 40/70 without those entries actually detecting
  SaaS-application telemetry. Unlike `cisco`, **"SaaS" is a real, distinct
  MITRE platform value** (`x_mitre_platforms: "SaaS"`) — no naming
  workaround was needed — though MITRE gives some major SaaS vendors
  (Google Workspace, GitHub) no dedicated platform tag of their own, so
  their techniques fall under this generic "SaaS" value alongside
  Microsoft 365, which additionally carries its own separate "Office 365"
  platform tag. Coverage stands at 27/70. For `identity-provider`, across
  the 259 `data/splunk-escu-detections.json` entries whose `component` is
  `"Okta"`, `"PingID"`, `"Cisco Duo"`, `"Azure"`, `"Microsoft 365"`,
  `"AWS"`, or `"Google Cloud Platform"` — the entries that detect
  identity-provider-layer events (sign-in, MFA/SSO, federation,
  directory/service-principal, and consent/authorization activity),
  as distinct from the SaaS/IaaS *applications* that rely on those
  identity providers — deliberately excluding this catalogue's
  endpoint-OS and generic-infrastructure components (Windows Endpoint,
  Linux, macOS, Cisco Network/ASA/IOS XE, Kubernetes, and others) even
  where a shared, broadly-applicable technique ID (e.g. T1078 Valid
  Accounts) would otherwise inflate the coverage count; including them
  naively raises the covered count from 27/48 to a misleading 37/48
  without those entries actually detecting identity-provider telemetry.
  Note that `"Azure"` and `"Microsoft 365"` are each shared, in part,
  with the `saas` file above — the same ESCU component can contain both
  genuinely SaaS-application detections (email/collaboration) and
  genuinely identity-provider detections (Entra ID sign-in/MFA/consent),
  since MITRE itself scopes many of the underlying techniques (e.g.
  T1621 Multi-Factor Request Generation) to multiple platforms
  simultaneously — the filtering here is by individual technique/entry
  relevance to the target platform, not an assumption that a component
  belongs to exactly one platform. For `containers`, across the 28
  `data/splunk-escu-detections.json` entries whose `component` is
  `"Kubernetes"` or `"Cisco Isovalent"` — genuine container-orchestration
  (Kubernetes API/pod/workload events) and container-runtime
  (eBPF/Cilium-based host-escape, kprobe, and offensive-tool-in-pod
  detection) telemetry — deliberately excluding this catalogue's host-OS,
  cloud-control-plane, and network-appliance components (Windows Endpoint,
  Linux, Cisco Network/ASA/IOS XE, AWS, Azure, Microsoft 365, and many
  others) even where a shared, broadly-applicable technique ID (e.g.
  T1078 Valid Accounts, T1190 Exploit Public-Facing Application) would
  otherwise inflate the coverage count; the effect here is the largest of
  any platform batch so far — including them naively raises the covered
  count from 8/48 to a wildly misleading 36/48 without those entries
  actually detecting container-orchestration or container-runtime
  telemetry. Coverage stands at 8/48, the widest gap of any platform in
  this coverage set — a candidate for a future dedicated container
  detection catalogue. For `linux`, across the 188
  `data/splunk-escu-detections.json` entries whose `component` is
  `"Linux"`, plus the entire 171-entry `data/redhat-detections.json`
  catalogue (RHEL, Red Hat IdM/IPA/FreeIPA, Ansible Automation Platform,
  Satellite — all built on Linux/RHEL, so genuinely Linux-platform-scoped)
  — deliberately excluding this catalogue's other components (Windows
  Endpoint, Cisco, cloud-identity, macOS, and the rest) even where a
  shared, broadly-applicable technique ID (e.g. T1059 Command and
  Scripting Interpreter, T1078 Valid Accounts) would otherwise inflate
  the coverage count; the naive, unfiltered whole-ESCU cross-reference
  would report 194/355 covered — the curated, genuinely-Linux-scoped
  set gives the accurate figure: 99/355. Linux and macOS are each nearly
  as large as the entire Windows platform (355/356 techniques vs.
  Windows' 474) and were, until this batch, complete blind spots in this
  library's coverage view — see the `macos` bullet below for how thin
  that platform's coverage turned out to be. For `iaas`, across the 140
  `data/splunk-escu-detections.json` entries whose `component` is
  `"AWS"`, `"Azure"`, or `"Google Cloud Platform"` — cloud
  infrastructure control-plane and resource telemetry (compute, storage,
  networking, and identity/IAM management within those clouds), as
  distinct from the SaaS applications or Identity Provider services that
  also run on top of the same clouds — deliberately excluding this
  catalogue's endpoint-OS, network-appliance, and non-cloud-provider
  SaaS/identity components (Windows Endpoint, Cisco Network/ASA/IOS XE,
  Microsoft 365, Okta, PingID, and others) even where a shared,
  broadly-applicable technique ID (e.g. T1078 Valid Accounts) would
  otherwise inflate the coverage count; the naive, unfiltered whole-ESCU
  cross-reference would report 62/104 covered — the curated,
  genuinely-IaaS-scoped set gives the accurate figure: 31/104. As with
  `identity-provider`, `"AWS"`, `"Azure"`, and `"Google Cloud Platform"`
  are each shared, in part, with the `saas`/`identity-provider` coverage
  files — the same component can legitimately contain IaaS-control-plane
  detections (S3/storage, CloudTrail, security-group changes) alongside
  identity-layer detections (sign-in, MFA), since MITRE itself scopes
  many underlying techniques to multiple platforms simultaneously. For
  `office-suite`, across the 91 `data/splunk-escu-detections.json`
  entries whose `component` is `"Microsoft 365"`, `"Microsoft 365
  Copilot"`, or `"Microsoft SharePoint"` — desktop and cloud-hosted
  office-productivity application behavior (Outlook/Exchange mailbox
  and mail-flow rules, SharePoint, OAuth application access to
  mailbox/document content, AI-copilot usage) as distinct from the
  broader SaaS/Identity Provider scope of the same underlying Microsoft
  365 tenant — deliberately excluding this catalogue's non-Office
  components (Windows Endpoint, AWS/Azure/GCP, Okta/PingID, and the
  rest) even where a shared, broadly-applicable technique ID (e.g.
  T1078 Valid Accounts) would otherwise inflate the coverage count; the
  naive, unfiltered whole-ESCU cross-reference would report 48/78
  covered — the curated, genuinely-Office-Suite-scoped set gives the
  accurate figure: 26/78. As with iaas/identity-provider, `"Microsoft
  365"` and `"Microsoft 365 Copilot"` are each shared, in part, with
  the `saas`/`identity-provider` coverage files, for the same reason.
  For `macos`, across the 13 `data/splunk-escu-detections.json`
  entries whose `component` is `"macOS"` — the only genuinely
  macOS-scoped content in this catalogue — deliberately excluding
  every other component even where a shared, broadly-applicable
  technique ID (e.g. T1059 Command and Scripting Interpreter, T1078
  Valid Accounts) would otherwise inflate the coverage count; the
  naive, unfiltered whole-ESCU cross-reference here is the most
  extreme example yet of the pattern this library has documented for
  every platform — it would report a wildly misleading 191/356
  covered, 148 of those "covered" via Windows Endpoint content alone,
  which has zero macOS applicability. The curated, genuinely-scoped
  set gives the accurate figure: **13/356** — the thinnest coverage of
  any platform this library tracks, and a real blind spot: macOS is
  nearly as large a platform as Windows (356 vs. 474 techniques) with
  essentially no dedicated content here, a strong candidate for a
  future detection-authoring batch (the same "MITRE-driven gap fill"
  pattern used for the Cisco and Windows Endpoint catalogues).
- every official MITRE **Detection Analytic** scoped to the platform
  (MITRE's newer Analytics/Detection Strategy/Data Source STIX object
  model — `x-mitre-analytic`, `x-mitre-detection-strategy`,
  `x-mitre-data-component` — distinct from and complementary to this
  library's own detections), each resolved to its parent **Detection
  Strategy** and the **Data Source**/Data Component log sources it
  depends on.

In the modal, click a technique row that shows an analytic count to expand
it and see the actual Analytic ID/name, its Detection Strategy, description,
and the specific log sources (with data component) it's grounded in — not
just a bare count. When more than one platform's data file has loaded, a
small tab switcher at the top of the modal lets you flip between them
without closing it; the header's stats line and the coverage button's
tooltip report each loaded platform's `covered/total` count.

Because these are fetched with `fetch()`, the coverage button only works
when the page is served over http(s) (e.g. GitHub Pages,
`python3 -m http.server`) — browsers block `fetch` of local files, so it
degrades to a toast message when opened via `file://`, same as the rest of
the page's data does.

Regenerate a platform's file after a new MITRE ATT&CK release, or after
adding detections to a catalogue scoped to that platform, with:

```bash
python3 tools/fetch_mitre_platform.py --platform ESXi
# cross-references data/detections.json + data/aria-detections.json by default;
# pass --detections explicitly (repeatable) to override which file(s) to check.

python3 tools/fetch_mitre_platform.py --platform Windows \
  --detections data/ad-detections.json \
  --detections data/rdp-detections.json \
  --detections data/dhcp-detections.json \
  --detections /path/to/a/filtered-windows-endpoint-only-escu-detections.json \
  --detections data/windows-endpoint-detections.json
# The fourth --detections file must be filtered down to just the ESCU
# entries whose component is "Windows Endpoint" or "Windows Network
# Telemetry" -- passing the full, multi-platform
# data/splunk-escu-detections.json unfiltered would inflate the coverage
# count with non-Windows-endpoint entries that happen to share a
# technique ID. The dedicated data/windows-endpoint-detections.json
# catalogue needs no such filtering -- it's 100% Windows Endpoint-scoped
# by construction.

python3 tools/fetch_mitre_platform.py --platform "Network Devices" \
  --detections /path/to/a/filtered-cisco-only-escu-detections.json \
  --detections data/cisco-detections.json \
  --output data/mitre-attack-cisco.json
# MITRE has no "Cisco" platform value -- "Network Devices" is the closest
# match, so --platform must be the MITRE name while --output picks the
# vendor-facing filename/tab label. The first --detections file must be
# filtered down to just the ESCU entries that are genuinely Network
# Devices telemetry first (see the Cisco bullet above) -- passing the
# full, multi-platform data/splunk-escu-detections.json unfiltered would
# inflate the coverage count with techniques detected by unrelated
# (non-Cisco) entries that happen to share a technique ID. The dedicated
# data/cisco-detections.json catalogue needs no such filtering -- it's
# 100% Network Devices-scoped by construction. Re-run this after editing
# either --detections file to keep covered_by_library accurate; the
# metadata.title/description get overwritten by the generator's generic
# wording each time, so re-apply the Cisco-specific framing afterward
# (see the git history for the exact text) if you want it back.

python3 tools/fetch_mitre_platform.py --platform SaaS \
  --detections /path/to/a/filtered-saas-only-escu-detections.json \
  --output data/mitre-attack-saas.json
# "SaaS" is MITRE's own platform name, so no --output workaround is
# needed there -- it's passed only for an explicit, predictable filename.
# The --detections file must first be filtered down to just the ESCU
# entries that are genuinely SaaS-application telemetry (Microsoft 365,
# Microsoft 365 Copilot, Okta, PingID, Zscaler, GitHub, Google Workspace,
# Cisco Duo -- see the saas bullet above); passing the full,
# multi-platform data/splunk-escu-detections.json unfiltered would
# inflate the coverage count with self-hosted/on-prem entries that
# happen to share a technique ID. Re-run after editing that filtered set
# to keep covered_by_library accurate; the metadata.title/description
# get overwritten by the generator's generic wording each time, so
# re-apply the SaaS-specific framing afterward (see the git history for
# the exact text) if you want it back.

python3 tools/fetch_mitre_platform.py --platform "Identity Provider" \
  --detections /path/to/a/filtered-identity-provider-only-escu-detections.json \
  --output data/mitre-attack-identity-provider.json
# "Identity Provider" is MITRE's own platform name (quote it -- it
# contains a space); --output picks the vendor-facing filename. The
# --detections file must first be filtered down to just the ESCU
# entries that genuinely detect identity-provider-layer events (Okta,
# PingID, Cisco Duo, Azure, Microsoft 365, AWS, Google Cloud Platform --
# see the identity-provider bullet above); passing the full,
# multi-platform data/splunk-escu-detections.json unfiltered would
# inflate the coverage count with endpoint-OS/infrastructure entries
# that happen to share a technique ID. Re-run after editing that
# filtered set to keep covered_by_library accurate; the
# metadata.title/description get overwritten by the generator's generic
# wording each time, so re-apply the identity-provider-specific framing
# afterward (see the git history for the exact text) if you want it
# back.

python3 tools/fetch_mitre_platform.py --platform Containers \
  --detections /path/to/a/filtered-containers-only-escu-detections.json \
  --output data/mitre-attack-containers.json
# "Containers" is MITRE's own platform name; --output picks the
# vendor-facing filename. The --detections file must first be filtered
# down to just the ESCU entries that genuinely detect container-
# orchestration/runtime telemetry (Kubernetes, Cisco Isovalent -- see
# the containers bullet above); passing the full, multi-platform
# data/splunk-escu-detections.json unfiltered would inflate the
# coverage count with host-OS/cloud-control-plane entries that happen
# to share a technique ID (this platform has the largest naive-vs-
# curated gap of any batch so far: 36/48 vs. the accurate 8/48). Re-run
# after editing that filtered set to keep covered_by_library accurate;
# the metadata.title/description get overwritten by the generator's
# generic wording each time, so re-apply the containers-specific
# framing afterward (see the git history for the exact text) if you
# want it back.

python3 tools/fetch_mitre_platform.py --platform Linux \
  --detections data/redhat-detections.json \
  --detections /path/to/a/filtered-linux-only-escu-detections.json
# The second --detections file must be filtered down to just the ESCU
# entries whose component is "Linux" (see the linux bullet above);
# passing the full, multi-platform data/splunk-escu-detections.json
# unfiltered would inflate the coverage count with non-Linux entries
# that happen to share a technique ID (naive 194/355 vs. the accurate
# 99/355). data/redhat-detections.json needs no such filtering -- it's
# 100% Linux/RHEL-scoped by construction. Re-run after editing either
# file to keep covered_by_library accurate; the metadata.title/
# description get overwritten by the generator's generic wording each
# time, so re-apply the Linux-specific framing afterward (see the git
# history for the exact text) if you want it back.

python3 tools/fetch_mitre_platform.py --platform IaaS \
  --detections /path/to/a/filtered-iaas-only-escu-detections.json \
  --output data/mitre-attack-iaas.json
# "IaaS" is MITRE's own platform name; --output picks the vendor-facing
# filename. The --detections file must first be filtered down to just
# the ESCU entries that genuinely detect cloud-infrastructure
# control-plane telemetry (AWS, Azure, Google Cloud Platform -- see the
# iaas bullet above); passing the full, multi-platform
# data/splunk-escu-detections.json unfiltered would inflate the
# coverage count with non-cloud-provider entries that happen to share a
# technique ID (naive 62/104 vs. the accurate 31/104). Re-run after
# editing that filtered set to keep covered_by_library accurate; the
# metadata.title/description get overwritten by the generator's
# generic wording each time, so re-apply the IaaS-specific framing
# afterward (see the git history for the exact text) if you want it
# back.

python3 tools/fetch_mitre_platform.py --platform "Office Suite" \
  --detections /path/to/a/filtered-office-suite-only-escu-detections.json \
  --output data/mitre-attack-office-suite.json
# "Office Suite" is MITRE's own platform name (quote it -- it contains
# a space); --output picks the vendor-facing filename. The
# --detections file must first be filtered down to just the ESCU
# entries that genuinely detect office-productivity-application
# telemetry (Microsoft 365, Microsoft 365 Copilot, Microsoft
# SharePoint -- see the office-suite bullet above); passing the full,
# multi-platform data/splunk-escu-detections.json unfiltered would
# inflate the coverage count with non-Office entries that happen to
# share a technique ID (naive 48/78 vs. the accurate 26/78). Re-run
# after editing that filtered set to keep covered_by_library accurate;
# the metadata.title/description get overwritten by the generator's
# generic wording each time, so re-apply the Office-Suite-specific
# framing afterward (see the git history for the exact text) if you
# want it back.

python3 tools/fetch_mitre_platform.py --platform "macOS" \
  --detections /path/to/a/filtered-macos-only-escu-detections.json \
  --output data/mitre-attack-macos.json
# The --detections file must first be filtered down to just the ESCU
# entries whose component is "macOS" (see the macos bullet above) --
# passing the full, multi-platform data/splunk-escu-detections.json
# unfiltered would produce a wildly misleading result here in
# particular: 191/356 vs. the accurate 13/356, since 148 of those
# false "covered" techniques would come from Windows Endpoint content
# alone. Re-run after editing that filtered set to keep
# covered_by_library accurate; the metadata.title/description get
# overwritten by the generator's generic wording each time, so
# re-apply the macOS-specific framing afterward (see the git history
# for the exact text) if you want it back.
```

Every real MITRE ATT&CK Detection-Analytics platform is now tracked
except `PRE` (Reconnaissance/Resource Development against
attacker-controlled infrastructure -- verified unobservable via any of
this library's internal telemetry, see the git history around the
platform-research session that ruled it out). To add a future one
anyway, or to re-add a platform after a MITRE taxonomy change, run the
script with `--platform <MitreName> --detections <filtered
platform-scoped detections>`, then add `{ id: "<Id>", label:
"<Label>", file: "data/mitre-attack-<slug>.json" }` to the
`COVERAGE_PLATFORMS` array near the top of the MITRE coverage section
in `index.template.html` and rebuild. If the platform's MITRE name and
this library's preferred label don't match 1:1 (as with Cisco/Network
Devices above), `id`/`file` should reflect the vendor-facing name you
want as the tab label and filename, while the `--platform` flag passed
to the fetch script stays MITRE's own vocabulary.

### Heat Coverage tab

Alongside **Detections**, the page's second top-level tab is **Heat
Coverage**: a technique × tactic matrix in the style of ATT&CK Navigator,
except each cell is shaded by how many of this library's detections —
summed across all fourteen catalogues and every platform, not scoped to one
the way the ATT&CK Coverage modal is — actually reference that technique.
It answers a different question than the coverage modal: not "does MITRE
have an official analytic for this," but "how much of *this library's own*
detection weight sits on each technique," so you can see at a glance where
coverage is deep (Indicator Removal, Account Manipulation, Valid Accounts —
unsurprising, since those are this library's documented cross-catalogue
patterns) versus where it's a single detection or a true gap.

- **Universe**: every non-deprecated Enterprise ATT&CK technique across
  *all* platforms (not filtered to this library's actual scope), rolled up
  to parent-technique level (sub-techniques fold into their parent — hover
  or focus a cell to see the sub-technique and per-catalogue breakdown).
  Loaded at runtime from `data/mitre-attack-universe.json`, same
  not-baked-into-the-page convention as the coverage modal's per-platform
  files — regenerate it after a new MITRE ATT&CK release with
  `python3 tools/fetch_mitre_universe.py`.
- **Counts**: computed client-side from the `DATA` array already in memory
  (every catalogue), not stored in the universe file — so the tab always
  reflects the current data files with no extra regeneration step when a
  batch changes.
- **Color scale**: a 13-step sequential ramp built from the page's own
  `--accent` (the crimson/coral used everywhere else in the UI) rather than
  an unrelated hue — the hottest step is the literal `--accent` value in
  each theme. Defaults to a square-root transform so an outlier like T1070
  (236 detections, mostly this library's `T1562`→`T1070` substitution
  pattern) doesn't wash every other cell to near-white; toggle "Linear
  scale" for raw proportional intensity. Gap cells (zero detections) get a
  dashed border instead of a color, so an absence of coverage reads as an
  absence of fill, not just a lighter shade.
- Search by technique name or ID, or toggle "Gaps only" to isolate the
  dashed cells.

Because a chunk of the full ATT&CK universe is techniques with no
realistic footprint on this library's actual scope (mobile, cloud-native
SaaS, etc.), treat a dashed cell as "worth checking," not automatically
"should build a detection" — the tab's own intro text says the same.

## Detection schema

Every entry in `data/detections.json` follows `schema/detection.schema.json`.
The key fields:

- `id` — stable, kebab-case slug (never rename once published; other entries
  reference each other by id via `related_detections`)
- `title`, `description`, `type`, `status`, `severity`, `confidence`
- `platform`, `product_version`, `method` — what's being detected and how
- `mitre_attack.tactics[]` / `mitre_attack.techniques[]` — ATT&CK mapping
- `mitre_analytics[]` *(optional)* — provenance link(s) to the official
  MITRE ATT&CK Detection Analytic(s) this entry is grounded in (see
  `data/mitre-attack-esxi.json`)
- `data_sources[]` — log/telemetry source name, path, and what it captures
- `detection_logic` — plain-English description of the detection
- `spl` — an illustrative Splunk search; sourcetypes/fields are written to be
  adapted to whatever TA/forwarding setup you actually run (VMware log
  formats and field names vary by ESXi build)
- `cli_reference` — the exact command(s)/API call(s) that generate the
  evidence
- `how_to_implement`, `known_false_positives`, `investigation_steps[]`
- `references[]` — supporting sources (CISA, VMware/Broadcom, vendor blogs)
- `related_detections[]` — ids of other entries in this library
- `author`, `created`, `modified`, `version`

### Schema differences across catalogues

The fourteen catalogues do **not** share one schema — each has its own file
under `schema/`, and the combined `index.html` view normalizes what it can
(`_component`, `_tool`) but does not paper over every field difference.
Three are worth knowing about if you're consuming this data programmatically
rather than through the UI:

- **False-positive guidance is represented two different ways.** ESXi and
  Aria use `known_false_positives` — free-text narrative guidance (e.g.
  "baseline your backup service accounts before enabling this in
  production"). The other twelve catalogues (Red Hat, Fortinet, Dell iDRAC,
  HPE iLO, Windows DHCP, Windows RDP, VCF, Splunk Platform, Active
  Directory, Splunk ESCU, Cisco Network Device, Windows Endpoint — 3,821
  entries) instead use `false_positive_rating`, a three-value category
  (`Low` / `Medium` / `High`) plus prose guidance spread across
  `tuning_guidance` and `investigation_steps[]`. Don't assume
  `known_false_positives` is present outside ESXi/Aria, or that
  `false_positive_rating` exists on those two.
- **`type` / `status` / `method` are effectively ESXi/Aria-only.** ESXi
  populates all three; Aria populates `type`/`status` but not `method`;
  none of the other twelve catalogues populate any of the three (they use
  `detection_type` and `detection_maturity` instead, which serve a similar
  role but aren't the same field or vocabulary). Filtering the *combined*
  view by these fields will only ever surface ESXi/Aria results — this is
  expected, not a bug, but worth knowing before building a facet or export
  on top of them.
- **The Splunk ESCU, Cisco Network Device, and Windows Endpoint
  catalogues' `detection_type` vocabulary is shared, and different from
  the rest.** Every other catalogue that populates `detection_type` uses
  this library's locally-defined values; ESCU instead preserves the
  upstream project's
  own `type` field verbatim (`TTP` / `Anomaly` / `Hunting` /
  `Correlation`), and the Cisco and Windows Endpoint catalogues reuse that
  same four-value vocabulary (inferred from each search's own structure)
  since they're built from the same MITRE Detection Analytic source
  material, so a `detection_type` facet spanning ESCU/Cisco/Windows
  Endpoint plus the rest of the library will show two different
  vocabularies side by side.

`query field` (`spl` vs `aria_query`) is the one difference that's
intentional and not drift — Aria genuinely uses a different query language
than the other eleven Splunk SPL catalogues.

### Performance note: `transaction`-based correlations

A number of the cross-platform correlation detections (the `*-X-###`
namespaces — `RH-X`, `FNT-X`, `DELL-X`, `HPE-X`, `DHCP-X`, `RDP-X`, `VCF-X`,
`SPL-X`, `AD-X`, and similarly-purposed entries elsewhere) use SPL's
`transaction` command with `startswith`/`endswith` to stitch together a
multi-stage sequence for one entity. `transaction` is correct and reads
clearly, but it's memory-heavy and doesn't distribute well across indexers;
at high event volume it can be slow or hit `maxopentxn`/`maxopenevents`
limits. Where a correlation only needs "event A then event B for the same
entity within N hours" (the common case for these detections), a
`stats … by <entity>` pattern with `earliest`/`latest` `eval`s and a span
check, or a `tstats`-accelerated prefilter, is usually cheaper at scale.
Treat the `transaction`-based SPL in this library as a correct, readable
reference implementation — worth revisiting for cost if you're running one
of these at high volume in production, not something to fix reflexively.

## Adding a new batch

1. Append new detection objects to `data/detections.json` (ESXi/Splunk),
   `data/aria-detections.json` (Aria), `data/redhat-detections.json`
   (RHEL/IdM/AAP/Satellite), `data/fortinet-detections.json` (Fortinet
   Security Fabric), `data/idrac-detections.json` (Dell iDRAC),
   `data/ilo-detections.json` (HPE iLO), `data/dhcp-detections.json`
   (Windows DHCP Server), `data/rdp-detections.json` (Windows RDP),
   `data/vcf-detections.json` (VMware Cloud Foundation),
   `data/splunk-detections.json` (Splunk Platform self-protection),
   `data/ad-detections.json` (Active Directory),
   `data/splunk-escu-detections.json` (Splunk ESCU — see the note below
   before adding to this one), `data/cisco-detections.json` (Cisco
   Network Device — MITRE-gap-fill methodology, see
   `docs/cisco-detection-library.md`), or
   `data/windows-endpoint-detections.json` (Windows Endpoint —
   MITRE-gap-fill methodology, see
   `docs/windows-endpoint-detection-library.md`), validating against the matching
   schema file in `schema/`. Detection IDs must be unique **across all
   fourteen files**, not just within one — `tools/build.py` enforces this
   at build time (see the `HREDFISH-###` vs. `REDFISH-###` note in the HPE
   iLO section above for why this matters with cross-vendor standards
   like Redfish).
2. If you need to change the combined page itself (layout, filters,
   styling), edit `index.template.html` — leave all fourteen
   `__..._JSON__` markers in place.
3. Regenerate the static page:

   ```bash
   python3 tools/build.py
   ```

4. Commit the data file(s) and the regenerated `index.html`.

**Note on `data/splunk-escu-detections.json` specifically:** unlike the
other thirteen catalogues, this one is sourced content, not hand-authored —
every entry's `source_id`/`source_url`/`source_version`/`source_author`
fields trace it back to a specific file in `splunk/security_content`. Don't
hand-add entries to this file that don't have real upstream provenance;
pull a new batch from `splunk/security_content` and run it back through the
same curation/conversion approach documented in
[`docs/splunk-escu-detection-library.md`](docs/splunk-escu-detection-library.md)
instead.

**Note on `data/rhel-privileged-action-validations.json`,
`data/fortigate-privileged-admin-validations.json`,
`data/cisco-sdwan-privileged-admin-validations.json`,
`data/rhel-ipa-privileged-admin-validations.json`, and
`data/windows-privileged-admin-validations.json` specifically:**
none of these files is one of the fourteen detection catalogues above and
none follows the same process — they're a different content type (a
validation catalogue; see [Validations](#validations) and
[`docs/validations.md`](docs/validations.md)), shown on their own shared
Validations page rather than the Detections page, each validated against
its own schema (`schema/rhel-privileged-action-validation.schema.json` /
`schema/fortigate-privileged-admin-validation.schema.json` /
`schema/cisco-sdwan-privileged-admin-validation.schema.json` /
`schema/rhel-ipa-privileged-admin-validation.schema.json` /
`schema/windows-privileged-admin-validation.schema.json`) rather than
`schema/detection.schema.json`, and none has a `COVERAGE_PLATFORMS`
entry in the ATT&CK Coverage browser since none is a set of production
detection rules to compute technique coverage over. Their IDs still
count toward `tools/build.py`'s cross-catalogue uniqueness check (step 1
above) alongside the fourteen detection files, since all these content
types share the same URL-hash deep-linking. Adding another validation
catalogue means: its own schema, its own data file, a new
marker/constant/`check_ids` call in `tools/build.py`, and a new entry in
`index.template.html`'s `VALIDATIONS` array concatenation — plus a new
telemetry field group in `validationDetailHtml`'s
`VALIDATION_TELEMETRY_GROUPS` if its raw telemetry fields don't match an
existing platform's.

## Versioning

This project follows [Semantic Versioning](https://semver.org/)
(`MAJOR.MINOR.PATCH`), tracked starting at `1.0.0`. [`VERSION`](VERSION)
at the repo root is the single source of truth — `tools/build.py` reads
it and stamps it into `index.html`'s header (the small version badge
next to the page title), so the version shown in the running page is
always the one in that file, never hand-edited in the template. See
[`CHANGELOG.md`](CHANGELOG.md) for what changed at each version and the
increment rule (MINOR for new catalogues/platforms/features, PATCH for
fixes and documentation, MAJOR reserved for breaking changes).

Bumping the version is part of finishing a batch, not a separate step:
update `VERSION`, add a dated entry to `CHANGELOG.md`, then rebuild
(`python3 tools/build.py`) so `index.html` picks up the new number
before committing.

## Disclaimer

These detections are provided as-is for detection engineering and security
research. Log field names, sourcetypes, and even VOB event IDs vary across
ESXi versions and TA/forwarding configurations — validate every search
against your own environment before relying on it operationally. The Aria
catalogue's generated description/false-positive/investigation-step text is
templated from each entry's component and MITRE tactic rather than
individually authored — treat it as a reasonable starting point, not a
substitute for reviewing the underlying Aria query and tuning it to your
environment. The Red Hat catalogue's SPL assumes specific log sources are
onboarded (in particular Linux `auditd` EXECVE/SYSCALL telemetry — see
`docs/redhat-audit-policy.md` for the ruleset each detection needs; 55 of
171 detections are marked `requires_auditd: true` and will not fire
without it) — check each entry's `telemetry_requirement` and `data_sources`
fields against what you actually collect before deploying it, and never run
any of these searches in a way that would surface plaintext credentials,
private keys, or secrets in shared dashboards or alert output. The
Fortinet catalogue's SPL uses illustrative sourcetype names
(`fgt_event`, `fgt_traffic`, `fmg_event`, etc.) that will not match your
TA's actual field extractions out of the box — see
`docs/fortinet-logging-requirements.md` for the real per-product log-type
requirements, and note that this catalogue does **not** claim to reliably
detect exploitation of specific Fortinet or Dell iDRAC CVEs by signature
(see `fortinet-logging-requirements.md` §6 and iDRAC detections
`FNT-X-012`/`DELL-X-008`) — where a vendor's own telemetry cannot expose
an exploit primitive, this library says so rather than fabricating a
signature that would give false confidence. The iDRAC catalogue's SPL is
similarly illustrative against `idrac_audit`/`idrac_lc`/`idrac_redfish`/
etc. sourcetypes that will need to match your actual iDRAC/Lifecycle Log
forwarding setup; 12 entries use a documented closest-fit MITRE ATT&CK
technique (see each entry's `attack_mapping_note`) since ATT&CK has no
dedicated technique for out-of-band virtual media or boot-configuration
tampering. The HPE iLO catalogue's SPL is likewise illustrative against
an `ilo_security`/`ilo_iml`/`ilo_redfish`/`oneview_audit` sourcetype
convention that will need to match your actual iLO/IML/OneView
forwarding setup; 6 entries use a documented closest-fit MITRE ATT&CK
technique (`attack_mapping_note`) for the same out-of-band/firmware
reason, and several anti-forensics-themed entries cite `T1070` rather
than the more intuitive `T1562` because `T1562` was absent from this
library's validated MITRE technique cache at authoring time — treat
that substitution as a reasonable adjacent fit, not a claim that
`T1562` doesn't exist in ATT&CK generally. The Windows DHCP Server
catalogue's SPL uses `<dhcp_index>`/`<windows_index>`/`<ad_index>`/
`<network_index>` and similar bracketed placeholders throughout (per the
spec's own instruction to use logical placeholders rather than invent a
specific TA's field names) — every placeholder needs mapping to your
actual DHCP audit-log, Windows Event Log, Active Directory, and network-
telemetry sourcetypes before use; several entries (`DHCP-NET-###`
rogue-server detections in particular) explicitly depend on Zeek/
Suricata/switch-DHCP-snooping telemetry and this library does not claim
Windows DHCP Server logs alone can reliably detect a rogue DHCP server.
The Windows RDP catalogue's SPL relies on standard Windows Security
event codes (4624/4625/4648/4688/etc.) plus the TerminalServices
operational channels, Sysmon, and — for several entries — network/VPN/
firewall telemetry; this library does not claim Security 4624/4625
alone can detect session hijacking, RD Gateway abuse, tunneling, or any
of the `RDP-X-###` cross-platform chains — see each entry's
`telemetry_requirement` and `data_sources` fields, and
`docs/rdp-detection-library.md` §10, before assuming a given detection
will fire from your actual log collection. The VMware Cloud Foundation
catalogue's SPL uses `<vcf_index>` plus bracketed sourcetype
placeholders (`<sddc_audit_sourcetype>`, `<nsx_audit_sourcetype>`,
`<salt_master_sourcetype>`, `<k8s_audit_sourcetype>`, etc.) throughout —
every placeholder needs mapping to your actual SDDC Manager, NSX
Manager, vCenter, Salt Master, VCF Automation, VCF Operations for Logs,
and Kubernetes API-server audit-log sourcetypes before use. This
catalogue deliberately does not duplicate the base ESXi/Aria
catalogues' vCenter/ESXi coverage (see the scope note in
`docs/vcf-detection-library.md`), and several detections — the
segmentation-intent-matrix flow correlation (`NSX-031`, `VCF-X-003`),
sensitive-VM/namespace tag lookups, and the `VCF-X-###` multi-platform
correlations generally — depend on maintained reference lookups this
library cannot ship for you; see `docs/vcf-detection-library.md` §10 for
the full list of what each correlation assumes is in place before it can
fire as designed. The Splunk Platform catalogue's SPL relies primarily on
`_audit` and `_internal` — Splunk's own internal indexes — for the
majority of its detections, but a substantial subset (every `SPL-CONF`
configuration-file-tampering entry that isn't already captured by
`_audit`, the on-premises-only `SPL-IDX`/`SPL-CM`/`SPL-DS` host-compromise
detections, and `SPL-APP-006`/`SPL-X-004`/`SPL-X-015`'s execution
confirmation) depend on OS-level file-integrity monitoring or process
telemetry (Sysmon/auditd) that **Splunk Cloud customers cannot deploy**
against provider-managed infrastructure — every such entry says so
explicitly in its `tuning_guidance` field, and `docs/splunk-platform-detection-library.md`
§2 and §11 give the full Cloud-vs-Enterprise applicability matrix and gap
analysis rather than presenting Cloud-inaccessible telemetry as available.
This catalogue also does not claim visibility into Splunk Cloud's own
provider-managed operations (the underlying OS, indexer hardware, or
internal platform-support tooling) beyond what the customer-visible ACS
API and `_audit`/`_internal` expose — see `SPL-CLOUD-012`'s explicit
caveat about support-access visibility varying by Splunk Cloud offering.
Several `Ingest Processor`/`Edge Processor`/`SOAR` detections
(`SPL-DATA-017` through `SPL-DATA-022`, `SPL-ES-025`) use bracketed
sourcetype placeholders and explicitly flag that the exact audit-event
schema is product/version-dependent and should be validated against your
specific deployment before relying on the literal field names shown.
The Active Directory catalogue's SPL relies primarily on the DC Security
event log (4624/4625/4662/4720-4776/5136/5137/5141, etc.), but a
substantial share of detections require Directory Service Access
auditing specifically (a distinct Advanced Audit Policy subcategory,
not on by default) — every entry that needs it says so via its
`telemetry_requirement`/`tuning_guidance` fields, and
`docs/ad-detection-library.md` §11 gives the full gap analysis. A number
of entries additionally depend on telemetry this repository cannot
assume is present: Sysmon/EDR for LSASS-access and process-creation
detections (`AD-DC-006/007/008/020/021`, all of `AD-CRED-###`'s
tool-based entries), Certification Authority role-specific auditing for
`AD-PERSIST-007/009/014`, SYSVOL file-system SACL auditing for the
GPO-content-tampering entries, and the LDAP Interface Events diagnostic
logging level for all of `AD-LDAP-###`. The `AD-X-###` cross-platform
correlations are explicitly illustrative — they reference companion
catalogues' log sources (VMware vCenter events for `AD-X-003/016`, HPE
iLO/Dell iDRAC events for `AD-X-005`, Fortinet/VPN/backup-platform logs
for the remainder) with vendor-specific field names and sourcetypes that
will need mapping to your actual deployment; several (`AD-X-003/004/005`)
depend on maintained VM-to-DC-hostname or physical-host-to-DC inventory
lookups this library does not ship. Golden Ticket, Silver Ticket, and
DCShadow detections (`AD-KRB-016` through `020`, `AD-REPL-005/006/015`)
are explicitly marked indirect/best-effort in their `attack_mapping_note`
field per the specification's own instruction not to claim direct
single-event detection of these techniques — Microsoft Defender for
Identity or equivalent network-level Kerberos/replication visibility is
the more reliable control where available, and this library says so
rather than overclaiming. As with the HPE iLO catalogue, several
"impaired security control" entries cite `T1070` rather than the more
intuitive `T1562` because `T1562` and its sub-techniques are absent from
this library's validated MITRE technique cache — the same documented
substitution used throughout this repository. Finally, none of this
catalogue's lookups (`tier0_privileged_accounts.csv`,
`domain_controllers.csv`, `sidhistory_inventory.csv`, and dozens more
referenced by name in `tuning_guidance` fields) are shipped as actual
files — populate them from your own asset inventory or identity-
governance platform before relying on the detections that depend on them
(see `docs/ad-detection-library.md` §12 for the full list). The Splunk
ESCU catalogue is different from the rest of this library in one important
way: it is a curated subset of **Splunk's own** `security_content` project
(Apache License 2.0), not content authored for this repository — this
library did not modify the underlying detection logic, only added the
provenance/schema/risk-scoring layer described in
`docs/splunk-escu-detection-library.md`; see each entry's
`source_id`/`source_url`/`source_author` fields for full attribution to
the original author and file. Its SPL is Splunk's actual production
search code, not this library's usual house style, and depends on the
`security_content`/ESCU Splunkbase app for several macros
(`` `security_content_summariesonly` ``, `` `security_content_ctime(...)` ``,
`` `drop_dm_object_name(...)` ``, and per-detection `` `<name>_filter` ``
macros) — searches using these macros will not run as-is without that app
installed, or without manually resolving each macro yourself. A large
share of entries also use `| tstats` against the CIM-accelerated
`Endpoint.Processes` data model rather than a raw index search, so they
additionally require the Splunk Common Information Model add-on with
Endpoint data model acceleration enabled; see each entry's
`cim_data_model`/`telemetry_requirement` fields and
`docs/splunk-escu-detection-library.md` for the full dependency list
before assuming a given ESCU detection will run unmodified in your
environment.
