# Fortinet Threat Detection Library — Logging Architecture & Data Quality

Companion reference to `data/fortinet-detections.json` (206 Splunk SPL
detections spanning FortiGate, FortiManager, FortiAnalyzer,
FortiAuthenticator, FortiClient/EMS, FortiEDR, FortiWeb, FortiMail,
FortiProxy, FortiSandbox, and cross-product `FNT-X-###` Security Fabric
correlations). See
[`fortinet-detection-library.md`](fortinet-detection-library.md) for
coverage matrices and Priority Detection Packs.

## 1. Telemetry requirement summary

| Requirement | Count | Meaning |
|---|---:|---|
| Essential | 99 | The detection cannot function without this log source enabled |
| Recommended | 101 | Meaningfully improves coverage/precision; has partial substitutes or is a lower-severity enrichment |
| Optional | 6 | Enrichment/hunting value only |

**Do not assume every Fortinet product uses identical fields or log
types.** The SPL in this catalogue is written against each product's own
sourcetype/field conventions (see §5, Normalized Field Schema, for how
they're mapped together) — a search written for `fgt_event` will not run
unmodified against `fmg_event` or `fedr_event`.

## 2. Required log type by product

| Product | Log types this catalogue depends on |
|---|---|
| FortiGate | Traffic (`type=traffic`), Event/System (`type=event subtype=system`), VPN (`subtype=vpn`), UTM: IPS / Antivirus / Application Control / Web Filter / DNS Filter / DLP / SSL (`type=utm subtype=...`), Admin |
| FortiManager | Event/System log covering administrator, device, policy-package, script, and revision activity |
| FortiAnalyzer | Event/System log covering administrator, device/log-source, log-management, and detection-content (event handler/IOC/report) activity |
| FortiAuthenticator | Authentication (RADIUS/LDAP/local/OTP), Admin, identity/token management events |
| FortiClient / FortiClient EMS | Endpoint (policy, isolation, telemetry heartbeat, vulnerability scan, local AV/web-filter/app-control), Admin |
| FortiEDR | Endpoint (process, memory-access, driver-load, network, persistence, policy-management events) |
| FortiWeb | WAF (attack log by signature category), Admin, API protection log, bot mitigation log |
| FortiMail | Email (history log with disposition/authentication-alignment results), DLP, quarantine, Admin |
| FortiProxy | Traffic/Web Filter (proxy access log), Authentication, Admin |
| FortiSandbox | FortiAnalyzer-forwarded verdict/job log (submission, verdict, behavioral report, extracted IOCs) |

## 3. Splunk CIM mapping

**206 / 206 detections (100%) are CIM-compatible** — every entry carries
`cim_compatible: true` and a `cim_data_model` field.

| CIM Data Model | Detections |
|---|---:|
| Change | 83 |
| Authentication | 38 |
| Malware | 23 |
| Network_Traffic | 26 |
| Intrusion_Detection | 16 |
| Endpoint | 9 |
| Web | 6 |
| Data_Access | 5 |

`Change` dominates because the large majority of the FortiGate,
FortiManager, and FortiAnalyzer sections are configuration-integrity
detections (administrator changes, policy edits, logging/security-profile
weakening) — the same pattern the Red Hat catalogue's auditd-backed
detections follow.

## 4. Normalized field schema

Recommended search-time aliases for consolidating across Fortinet
sourcetypes, per §41 of the specification:

| Normalized field | Fortinet-native fields aliased | Applies to |
|---|---|---|
| `src` / `src_ip` | `srcip` | all |
| `dest` / `dest_ip` | `dstip`, `backend_ip` (FortiWeb) | all |
| `src_port` / `dest_port` | `srcport`, `dstport` | Traffic, WAF |
| `user` | `user`, `admin` | all |
| `action` | `action` | all |
| `result` | `status`, `verdict`, `disposition` | Authentication, Malware |
| `device` / `device_id` | `devname`, `devid`, `hostname` (endpoint products) | all |
| `vdom` | `vd` | FortiGate |
| `policy_id` / `policy_name` | `policyid`, `policyname`, `pkgname` (FortiManager) | FortiGate, FortiManager |
| `application` | `app`, `appcat` | FortiGate |
| `service` / `protocol` | `service`, `proto` | Traffic |
| `url` / `domain` | `url`, `http_url`, `domain` | Web Filter, WAF, DNS Filter |
| `bytes_in` / `bytes_out` | `rcvdbyte`, `sentbyte` | Traffic |
| `session_id` | `sessionid` | Traffic |
| `configuration_object` | `cfgobj`, `pkgname`, `scriptname`, `profile_name` | Change events |
| `configuration_action` | `cfgattr`, `action` | Change events |
| `vpn_type` | derived from `subtype=vpn` + tunnel mode fields | VPN |
| `threat` / `signature` | `virus`, `attack`, `malware_name`, `classification` | IPS, Antivirus, WAF, Endpoint |
| `severity` | `severity` | IPS, WAF, FortiSandbox |

`fgt_event` and `fgt_traffic`/`fgt_utm` are treated as related but
distinct sourcetypes throughout the catalogue's SPL — traffic-layer
fields (`srcip`, `dstip`, `sentbyte`) live on the traffic/UTM
sourcetypes, while `cfgpath`/`cfgobj`/`cfgattr` configuration-change
fields live on the event sourcetype. Detections that need both (e.g.
FGT-039, FGT-083) explicitly join across them.

## 5. Detection gap analysis

Per specification §44 — an honest accounting of what this catalogue can
and cannot see, organized by how directly the underlying telemetry
supports detection:

### Threats observable directly (single log event, no inference required)
Administrator authentication and account changes, firewall policy
edits, VPN authentication, IPS/antivirus/web-filter/DNS-filter verdicts,
WAF signature matches, FortiMail message disposition, FortiSandbox
verdicts, FortiManager/FortiAnalyzer administrative and device-management
events. This is the majority of the catalogue's Level 1–2 detections.

### Threats inferable behaviorally (require a baseline or statistical model)
Beaconing/periodic C2 (FGT-072), impossible travel / new-source anomalies
(FGT-005, FGT-055), off-hours activity (FGT-007, FGT-098), unusual data
volume (FGT-071, FML-007), DNS tunneling volume/entropy (FGT-077, FGT-099).
These require either a maintained baseline lookup or a statistical
computation (z-score, coefficient of variation) over a rolling window —
explicitly called out in each entry's `tuning_guidance`.

### Threats requiring FortiEDR (invisible to network-only or signature-only telemetry)
Process injection/hollowing (FEDR-006), LSASS credential dumping
(FEDR-003), fileless/living-off-the-land execution (FEDR-002), kernel
driver/BYOVD abuse (FEDR-007), and ransomware behavioral detection on
the endpoint itself (FEDR-004) — none of these produce a distinguishing
FortiGate network-layer event. **A network-only Fortinet deployment
(FortiGate without FortiEDR/FortiClient) cannot detect this entire class
of technique** — this is the same limitation the Red Hat catalogue notes
for `requires_auditd` detections, applied to the endpoint layer.

### Threats requiring FortiWeb (invisible to generic IPS)
Application-layer web attacks (SQLi, XSS, SSRF, XXE, web shell upload,
API/IDOR abuse) require FortiWeb's HTTP-aware signature and behavioral
engines. FortiGate's generic IPS sensor may catch some overlapping
network-layer exploit signatures but is not a substitute for a
web-application firewall sitting in front of the application.

### Threats requiring endpoint logs beyond FortiEDR
FortiClient EMS's own telemetry (vulnerability scan results, ZTNA
posture tags, local protection status) is necessary for the EMS-###
detections; FortiEDR alone does not cover endpoint compliance/posture
management.

### Threats requiring DNS-specific telemetry
DNS tunneling, DGA/NXDOMAIN-burst detection, and dynamic-DNS C2 use
(FGT-077, FGT-078, FGT-074) require the DNS Filter log specifically —
they will not appear in the general traffic log at the fidelity needed
(query name, response code) unless DNS filtering/logging is explicitly
enabled.

### Threats requiring SSL/TLS inspection
Any detection that needs to see *inside* an encrypted session — malware
delivered over HTTPS, C2 traffic patterns beyond connection metadata,
DLP matches on an encrypted upload — requires SSL deep inspection to be
enabled and not exempted (FGT-095/FPX-005 track exactly this control).
**Without SSL inspection, this catalogue can only see connection
metadata (destination, byte counts, duration, SNI) for encrypted
sessions, not payload content** — the byte-volume, beaconing, and
first-seen-destination detections (FGT-071/072/073) work on metadata
alone and remain valid without SSL inspection; anything reading `url`,
`filename`, or DLP pattern matches inside an HTTPS session does not.

### Threats invisible due to encryption regardless of inspection
End-to-end encrypted channels the organization does not control the
keys for (e.g. an attacker's own TLS-wrapped C2 using certificate
pinning that defeats MITM inspection, or traffic tunneled inside an
already-encrypted VPN the organization cannot decrypt) fall back entirely
to metadata-based behavioral detection (beaconing, volume, rare
destination) — there is no configuration that restores payload
visibility here.

### Threats requiring external threat intelligence
Tor/anonymizer node identification (FGT-075), dynamic-DNS provider
matching (FGT-074), known-vulnerable-driver watchlists (FEDR-007), and
sandbox-extracted C2 indicator lookups (FSB-006, FNT-X-009) all depend on
a maintained external feed (`fgt_tor_nodes.csv`, `fgt_dyndns_providers.csv`,
`fedr_vulnerable_drivers.csv`, `fsb_c2_iocs.csv` in the illustrative SPL) —
these detections degrade silently to zero results if the feed goes stale,
which is called out in each entry's `tuning_guidance`.

**FortiGate traffic logs do not provide endpoint process telemetry.**
Repeated throughout this catalogue's `tuning_guidance` and explicitly
here: a network-layer detection can tell you *that* a host connected
somewhere unusual, never *which process* did it, what command line was
used, or whether a file was actually written to disk. Every claim in
this catalogue that needs process-level attribution is sourced from
FortiEDR or FortiClient endpoint telemetry, never inferred from FortiGate
traffic/IPS/UTM logs alone.

## 6. Known-vulnerability detection posture

Per specification §32: this catalogue does **not** claim to reliably
detect exploitation of specific Fortinet CVEs by signature. FNT-X-012 is
explicit about this limitation — it is a low-confidence, high-false-positive
*hunting* search for post-exploitation behavior (unattributed admin-interface
recon followed by account creation), meant to be run during a declared
PSIRT advisory window against your deployed version, not a standing
production alert. Authentication-bypass and memory-corruption
vulnerabilities reached via crafted requests to a management interface
frequently do not generate a log event that distinguishes them from
normal traffic — where Fortinet's own telemetry cannot expose the exploit
primitive itself, this catalogue says so rather than fabricating a
signature that would give false confidence.
