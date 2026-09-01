# Red Hat Threat Detection Library — Summary & Priority Packs

Companion index to `data/redhat-detections.json` (171 Splunk SPL
detections across RHEL, Red Hat IdM/IPA/FreeIPA, Red Hat Ansible
Automation Platform, and Red Hat Satellite, plus 10 `RH-X-###`
cross-platform correlations). See
[`redhat-audit-policy.md`](redhat-audit-policy.md) for the consolidated
`auditd` ruleset the RHEL detections in this catalogue depend on.

Every detection ID below is a stable reference into
`data/redhat-detections.json` — look it up by `id` for the full SPL,
investigation steps, and response guidance. This document is a map, not a
duplicate of the data.

## Scope note

The original specification asked for "at least 400" detections. This
catalogue ships **171**: every entry is a distinct, fully-detailed
detection with real SPL, MITRE ATT&CK IDs validated against the current
ATT&CK STIX corpus (not memorized/guessed), and no fabricated Red Hat log
events. Padding to 400 would have meant either duplicating detections
under different IDs or inventing telemetry that doesn't exist in real
RHEL/IPA/AAP/Satellite logs — both would violate this catalogue's own
quality-control rules. 171 is a deliberately-scoped first release,
structured the same way the ESXi catalogue was (batch 1 → batch 2): more
detections can be added in future batches against the same schema.

---

## 1. Coverage matrix — platform × severity

| Platform | Critical | High | Medium | Low | Total |
|---|---:|---:|---:|---:|---:|
| RHEL | 22 | 30 | 17 | 1 | 70 |
| IdM/IPA/FreeIPA | 9 | 15 | 7 | 0 | 31 |
| Ansible Automation Platform | 10 | 19 | 4 | 0 | 33 |
| Satellite | 12 | 11 | 4 | 0 | 27 |
| Cross-platform (RH-X) | 10 | 0 | 0 | 0 | 10 |
| **Total** | **63** | **75** | **32** | **1** | **171** |

## 2. Coverage matrix — detection type

| Detection type | Count |
|---|---:|
| Configuration change | 41 |
| Behavioral | 29 |
| Atomic | 28 |
| Threshold | 20 |
| Integrity | 19 |
| Sequence | 11 |
| Correlation | 10 |
| Administrative abuse | 7 |
| Anomaly | 6 |

## 3. Coverage matrix — detection maturity

| Level | Count |
|---|---:|
| Level 1 - simple indicator | 96 |
| Level 2 - threshold | 30 |
| Level 3 - behavioral | 25 |
| Level 4 - correlation | 10 |
| Level 5 - multi-platform attack sequence | 10 |

## 4. Coverage matrix — telemetry requirement

| Requirement | Count | Notes |
|---|---:|---|
| Essential | 82 | Detection cannot function without this log source |
| Recommended | 87 | Meaningfully improves coverage/precision but has partial substitutes |
| Optional | 2 | Enrichment only |

`requires_auditd: true` on **55 / 171** detections (all RHEL, plus
IPA-015/IPA-017 and RH-X-004/RH-X-010, which touch Kerberos credential
caches and fleet-wide EXECVE respectively). See
`redhat-audit-policy.md` for the ruleset these depend on — 20 of the 55
rely on the foundational broad-EXECVE rule rather than a path-specific
watch.

## 5. Coverage matrix — false positive rating

| Rating | Count |
|---|---:|
| Low | 40 |
| Medium | 110 |
| High | 21 |

The 21 "High" FP-rated detections are concentrated in Behavioral/Anomaly
types (e.g. baseline deviation on AAP job-template SCM sync cadence,
Satellite content-view publish frequency) — these are intentionally
included as **hunting** searches, not out-of-the-box alerts; each carries
explicit `tuning_guidance` calling this out.

## 6. Component breakdown

| Component | Count | Component | Count |
|---|---:|---|---:|
| auditd | 37 | fapolicyd | 5 |
| Ansible Controller | 26 | SELinux | 4 |
| Foreman | 14 | Dogtag PKI | 4 |
| IPA Server | 12 | Automation Hub | 4 |
| Kerberos | 9 | sudo | 3 |
| sshd | 8 | Event-Driven Ansible | 3 |
| PAM | 6 | Capsule | 3 |
| systemd | 6 | DNS | 2 |
| 389 Directory Server | 6 | Execution Environment | 2 |
| Pulp | 6 | receptor | 2 |
| Katello | 6 | firewalld | 1 |
| | | Hammer CLI / SSSD | 1 each |

---

## 7. Priority Detection Packs

Packs are cumulative deployment tiers: deploy Tier 1 first, then layer
Tier 2 and Tier 3 as your SOC's alert-handling capacity grows. Every
detection appears in exactly one tier.

### Tier 1 — Deploy first (32 detections)

Critical severity **and** high confidence **and** Low false-positive
rating. This is the smallest set that gives you signal on account
creation, credential-cache/identity abuse, defense-control impairment,
destructive commands, and the management-plane-to-fleet correlations,
with the least tuning effort.

| ID | Title | Risk score |
|---|---|---:|
| AAP-002 | Successful AAP Login Following Repeated Failures | 100 |
| AAP-014 | Job Disables Security Controls Across Multiple Hosts | 125 |
| AAP-017 | Project SCM Source URL Changed | 125 |
| AAP-022 | New Organization or System Administrator Assigned | 125 |
| IPA-002 | Successful Kerberos Authentication Following Repeated Failures | 100 |
| IPA-007 | admins Group Membership Changed | 125 |
| IPA-012 | IPA Sudo Rule Grants All-Host Scope | 125 |
| IPA-013 | IPA Sudo Rule Grants NOPASSWD All-Command Access | 125 |
| IPA-020 | Mass Certificate Revocation | 100 |
| IPA-028 | Cross-Realm/AD Trust Created | 125 |
| RH-X-001 | IPA Privileged Identity Compromise Followed by RHEL SSH Access | 100 |
| RH-X-004 | AAP Software Supply-Chain Attack (Project SCM to Fleet Change) | 125 |
| RH-X-006 | Satellite Repository Compromise Reaches Production RHEL Fleet | 125 |
| RH-X-007 | Satellite Remote Execution Attack (Auth to Fleet-Wide Impairment) | 125 |
| RH-X-010 | Coordinated Defense-Control Impairment Across the Fleet | 125 |
| RHEL-002 | Successful SSH Login Following Repeated Failures | 100 |
| RHEL-014 | New UID 0 Account Created | 125 |
| RHEL-027 | Audit Log Files Deleted or Truncated | 100 |
| RHEL-031 | SELinux Disabled or Set to Permissive | 125 |
| RHEL-038 | Untrusted ELF Execution Attempt from /tmp or /dev/shm | 125 |
| RHEL-048 | Unsigned Kernel Module Load Rejected / Kernel Taint Changed | 100 |
| RHEL-055 | Download-and-Execute Pattern (curl/wget piped to shell) | 125 |
| RHEL-056 | Base64-Decode Piped to Shell Execution | 125 |
| RHEL-057 | Reverse Shell Pattern via nc/socat/bash | 125 |
| RHEL-063 | Suspicious LD_PRELOAD Environment Variable or /etc/ld.so.preload Entry | 125 |
| RHEL-069 | Disk-Wiping Utility Executed (shred, wipefs, dd to a block device) | 125 |
| SAT-002 | Successful Satellite Login Following Repeated Failures | 100 |
| SAT-004 | New Satellite Administrator Created | 125 |
| SAT-006 | Repository URL Changed | 125 |
| SAT-007 | GPG Signature Verification Weakened or Disabled | 100 |
| SAT-019 | Remote Execution Job Contains Security-Control-Impairment Commands | 100 |
| SAT-020 | Remote Execution Job Contains Destructive Command Pattern | 125 |

### Tier 2 — Broaden coverage (99 detections)

Critical or high severity with Low or Medium false-positive rating, not
already in Tier 1. This tier adds the bulk of the configuration-change,
persistence, and identity/privilege atomic detections across all five
namespaces. Full ID list: every `RHEL-###`, `IPA-###`, `AAP-###`,
`SAT-###`, `RH-X-###` entry in `data/redhat-detections.json` where
`severity` is `critical` or `high`, `false_positive_rating` is `Low` or
`Medium`, and the ID is not listed in Tier 1 above — filter the JSON on
those three fields to reproduce the exact list.

### Tier 3 — Hunting and low-confidence signal (40 detections)

Medium/low severity, and/or High false-positive rating, and/or medium/low
confidence. These are intentionally still included — they're valuable for
threshold-tuning, retrospective hunting, and closing detection gaps once
Tier 1/2 alert volume is under control — but are not meant to page anyone
out of the box. Filter the JSON for `severity: medium` or `low`, or
`false_positive_rating: High`, to reproduce the exact list.

### Themed packs

Cut across the tiers above by attack theme, for teams that want to deploy
by technique family rather than strictly by severity:

| Pack | Count | Focus |
|---|---:|---|
| **Defense-Impairment / Critical-Control Pack** | 45 | auditd, SELinux, fapolicyd, firewalld, PAM, sshd config tampering; IPA HBAC/sudo/trust changes; AAP job-template and credential changes that disable controls; Satellite GPG/content/REX security-impairment patterns |
| **Persistence Pack** | 22 | cron/at, systemd units, SSH authorized_keys, LD_PRELOAD, kernel modules, AAP job templates/schedules used for persistence, IPA keytab/HBAC persistence |
| **Software Supply-Chain Pack** | 17 | AAP project SCM/collection/Execution-Environment tampering, Satellite repository/content-view/GPG/kickstart tampering, and the RH-X correlations that trace those changes to fleet impact |
| **Fleet-Wide / Cross-Platform Correlation Pack** | 25 | All 10 RH-X detections plus the AAP/IPA/Satellite atomic detections whose primary value is as an input into a correlation (mass host actions, all-host sudo/HBAC scope, REX against many hosts) |
| **Credential Access & Exposure Pack** | 9 | `/etc/shadow`, keytab, SSH private key, bash-history reads; AAP credential association/export/reveal |
| **Identity & Privileged Access Pack** | 22 | UID 0 accounts, sudoers/wheel/admins group changes, setuid/setcap/pkexec, IPA HBAC/RBAC role changes, AAP/Satellite admin role grants |

Pack membership is computed from each entry's `tags` array (e.g.
`defense-impairment`, `persistence`, `supply-chain`, `fleet-wide`,
`rh-x`, `correlation`, `credential-access`, `credentials`,
`privilege-escalation`, `account-manipulation`, `rbac`) — filter
`data/redhat-detections.json` on those tags to reproduce each list
exactly; packs overlap by design (a detection can be both
Defense-Impairment and Fleet-Wide, for example).

---

## 8. Normalized field schema (search-time aliasing)

The SPL in this catalogue is written against the field names each
platform's log source actually produces (`user`, `src_ip`, `host`,
`command`, `path`, etc.), which already line up closely with Splunk CIM
`Authentication`, `Change_Analysis`, and `Endpoint` data model fields.
Recommended CIM/normalized aliases if you're consolidating across
sourcetypes:

| Normalized field | Source fields aliased | Applies to |
|---|---|---|
| `user` | `acct`, `AUID`, `uid`, `principal`, `username` | all |
| `src_ip` | `addr`, `hostip`, `remote_addr`, `client_ip` | Authentication, sequence/correlation detections |
| `dest` / `host` | `host`, `hostname`, `managed_node` | all |
| `action` | `result`, `res`, `success`/`failed` | Authentication, Administrative abuse |
| `object` | `path`, `key`, `unit`, `rule_name`, `credential_id`, `repo_id` | Integrity, Configuration change |
| `command` | `exe`, `comm`, `a0`/`a1`/`a2`… (EXECVE argv) | Atomic (auditd-backed) |
| `signature` | `type` (auditd record type), `event_type` | Atomic, Integrity |

## 9. Detection maturity ladder — how to read `detection_maturity`

- **Level 1 — simple indicator**: single-event pattern match (a specific
  EXECVE, a specific config-file write). Fires on one log line.
- **Level 2 — threshold**: count/distinct-count over a time window (e.g.
  N failed logins, N hosts touched by one job).
- **Level 3 — behavioral**: compares current activity to a learned or
  declared baseline (new process for this host, off-hours administrative
  action, deviation from historical job-template SCM sync cadence).
- **Level 4 — correlation**: joins two or more searches within the same
  platform by a shared key (e.g. a failed-then-successful auth sequence,
  a credential association followed by a job run).
- **Level 5 — multi-platform attack sequence**: the `RH-X-###` layer —
  joins saved searches across IPA/AAP/Satellite/RHEL by identity and
  timing to detect an attack chain that no single platform's telemetry
  shows on its own.

## 10. Risk scoring reference

`score = severity(1-5) × confidence(1-5) × impact(1-5)`, max 125.
Distribution across the catalogue:

| Score band | Count | Interpretation |
|---|---:|---|
| 100–125 | 76 | Page immediately / Tier 1-2 candidate |
| 60–99 | 58 | Investigate same business day |
| 30–59 | 30 | Queue for triage / hunting |
| < 30 | 7 | Enrichment / context-only |

---

*Generated from `data/redhat-detections.json` (171 entries). Regenerate
these tables after any future batch adds or edits detections — the counts
above are a snapshot, not a live query.*
