# Consolidated Linux auditd Rule Catalogue
## CIS RHEL 9 v2.0.0 · DISA STIG RHEL 9 · ACSC ISM Outcome Alignment · SCAP/ComplianceAsCode

> **Purpose:** A comprehensive Linux/RHEL `auditd` security-monitoring catalogue combining CIS Benchmark, DISA STIG and ACSC Information Security Manual (ISM) objectives with production-oriented rules, descriptions, priorities and Splunk/security-monitoring considerations.
>
> **Compliance interpretation:** CIS and DISA STIG references in this catalogue identify concrete RHEL 9 audit requirements where an exact mapping is available from the supplied baseline material. ACSC ISM references are **security-outcome alignments**, not claims that the ISM mandates the exact Linux syscall/watch syntax shown. SCAP/ComplianceAsCode profile mappings are implementation aids and must not be treated as authoritative substitutes for the CIS Benchmark, DISA STIG, or ACSC ISM. Exact control identifiers and profile availability must be validated against the approved framework release and the installed SCAP content.
>
> **Deployment:** Prefer `/etc/audit/rules.d/*.rules` and load with `augenrules --load`. Use `UID_MIN` from `/etc/login.defs` rather than assuming `1000` where possible. On systems that execute 32-bit binaries, retain appropriate `arch=b32` rules alongside `arch=b64`.
>
> **Rule-path note:** Binary and configuration paths vary by RHEL/Linux release and installed packages. Validate them with `command -v`, package manifests and host testing before deployment.

---

## Framework Legend

### CIS RHEL 9 Benchmark v2.0.0 — Section 6.3.3 Reference

The following exact CIS references are used throughout this catalogue where the control aligns directly with an existing rule:

- **6.3.3.1** — Changes to system administration scope (`sudoers`)
- **6.3.3.2** — Actions performed as another user (`user_emulation`)
- **6.3.3.3** — Changes to the sudo log file
- **6.3.3.4** — Date and time changes
- **6.3.3.5** — Network environment changes
- **6.3.3.6** — Privileged command execution
- **6.3.3.7** — Unsuccessful file access attempts
- **6.3.3.8** — User/group information changes
- **6.3.3.9** — Discretionary access control permission changes
- **6.3.3.10** — Successful filesystem mounts
- **6.3.3.11** — Session initiation
- **6.3.3.12** — Login/logout events
- **6.3.3.13** — File deletion events
- **6.3.3.14** — Mandatory Access Control changes
- **6.3.3.15–6.3.3.19** — Additional execution / module / permission-related audit controls
- **6.3.3.20 / Finalize** — Immutable audit configuration

Related CIS requirements:
- **6.3.1** — `auditd` installed and enabled
- **6.3.2** — Audit log retention and failure-action configuration in `/etc/audit/auditd.conf`
- **Boot-time auditing** — `audit=1` and sufficient `audit_backlog_limit`



### DISA STIG for Red Hat Enterprise Linux 9 — Auditd Reference

The following DISA RHEL 9 STIG references are used throughout this catalogue where they align directly with an existing rule or security objective.

**Recommended starting point from the audit package:**

```bash
cd /usr/share/audit/sample-rules/
cp 10-base-config.rules 30-stig.rules 31-privileged.rules 99-finalize.rules /etc/audit/rules.d/
augenrules --load
```

**Common STIG rule-file load order:**

```text
10-base-config.rules
30-stig.rules
31-privileged.rules
99-finalize.rules
```

Selected RHEL 9 STIG rule IDs incorporated into this catalogue:

- **RHEL-09-654010** — privileged execution / effective-ID mismatch (`execpriv`)
- **RHEL-09-654097** — cron job configuration auditing
- **RHEL-09-654145** — `/usr/bin/su` execution
- **RHEL-09-654150** — `/usr/bin/sudo` execution
- **RHEL-09-654180** — `/usr/bin/mount` execution
- **RHEL-09-654195** — `/usr/sbin/reboot` execution
- **RHEL-09-654200** — `/usr/sbin/shutdown` execution
- **RHEL-09-654215** — `/etc/sudoers` modification
- **RHEL-09-654220 / 654225 / 654230 / 654235 / 654240 / 654245** — identity/account database modifications
- **RHEL-09-654250** — `/var/log/faillock`
- **RHEL-09-654255** — `/var/log/lastlog`
- **RHEL-09-654265** — audit failure mode (`-f 2`)
- **RHEL-09-654275** — immutable audit configuration (`-e 2`)

> Exact STIG IDs and rule wording are release-specific. Validate against the authoritative current DISA RHEL 9 STIG release used by the system accreditation boundary.


| Framework | Use in this catalogue |
|---|---|
| CIS Benchmark | Hardened system configuration and audit coverage. Exact control numbering varies by distribution and benchmark version. |
| DISA STIG | High-assurance audit, accountability and system-security requirements. Exact rule IDs vary by OS/STIG release. |
| ACSC ISM | Australian Government security outcomes for event logging, monitoring, authentication, privileged activity, system integrity, security configuration and investigation. |
| Essential Eight | Relevant where audit telemetry supports application control, patching, administrative privilege restrictions, MFA, hardening and incident investigation. |

---


## Compliance Reference Alignment Model

Use the references in this catalogue according to the following hierarchy:

| Reference type | Meaning | Compliance weight |
|---|---|---|
| **CIS exact** | Exact CIS RHEL 9 v2.0.0 Section 6.3.3 control supplied for the rule/control objective. | Authoritative only when verified against the licensed CIS Benchmark used by the organisation. |
| **DISA STIG exact** | Exact RHEL-09-654xxx identifier supplied for the rule/control objective. | Authoritative only when verified against the approved DISA RHEL 9 STIG release. |
| **DISA sample-rule alignment** | Rule appears in or aligns with the upstream/audit-package `30-stig.rules` or `31-privileged.rules` pattern. | Implementation reference; not equivalent to a STIG ID by itself. |
| **ACSC ISM outcome alignment** | The audit rule supports an ISM security objective such as event logging, privileged-action accountability, authentication monitoring, system integrity, or investigation. | Outcome mapping only; **not** an assertion that ISM prescribes the exact auditd rule. |
| **SCAP / ComplianceAsCode mapping** | XCCDF/SSG profile or rule implementation maps technical checks to a framework. | Automation/evaluation aid; confirm profile and mappings in the installed content version. |
| **Threat-detection enhancement** | Additional rule added for SOC/detection value beyond a strict compliance minimum. | No compliance claim unless separately mapped. |

### Alignment rule

A single audit rule may carry **multiple compliance and assurance references** when each reference genuinely applies to the same control objective. For example, one rule may simultaneously map to:

- a CIS RHEL 9 v2.0.0 control,
- one or more DISA RHEL 9 STIG IDs,
- an ACSC ISM security outcome or verified ISM control,
- one or more SCAP / ComplianceAsCode XCCDF rules,
- and a threat-detection use case.

References are additive, not mutually exclusive.

Exact CIS or STIG references are attached only when the supplied baseline explicitly associates that control with the rule objective. Broader or enhanced rules retain all applicable references but are labelled as an **extension** when their syscall set, path coverage, audit key, or operational scope goes beyond the canonical framework form.


## 1. Base / Audit Control Rules

**DISA STIG RHEL 9:** RHEL-09-654265 — use `-f 2` for critical audit failure handling; RHEL-09-654275 — use `-e 2` to make the audit configuration immutable.

These controls govern the audit subsystem itself and should normally be separated into ordered rule files, with finalisation loaded last.

| Title | Typical rule | Framework relevance | Description |
|---|---|---|---|
| Delete existing rules before managed load | `-D` | CIS / STIG / deployment practice | Clears previously loaded rules so the managed ruleset starts from a known state. Use carefully when other tooling also owns audit rules. |
| Audit backlog buffer | `-b 8192` | CIS / STIG / logging resilience | Increases audit queue capacity. Size should be performance-tested for the workload. |
| Failure mode | `-f 1` or framework-required value | CIS / STIG / operational assurance | Base/sample configurations may use different values. For the supplied DISA RHEL 9 STIG mapping, **RHEL-09-654265 requires `-f 2`**. Do not treat `-f 1` as STIG-equivalent. |
| Ignore optional rule errors | `-i` | Deployment-dependent | Allows loading to continue when optional paths/rules are not valid. Useful for heterogeneous fleets, but may hide unintended coverage gaps if not monitored. |
| Immutable finalisation | `-e 2` | CIS / STIG / high assurance | Makes the active audit configuration immutable until reboot. Must be the final rule and should only be enabled after testing. |


### STIG canonical failure/finalisation controls

```text
-f 2
-e 2
```

For DISA STIG-aligned systems, `-f 2` is the stricter preference for critical audit failure handling, while `-e 2` makes the rule set immutable until reboot. Place finalisation controls in the last rule file.

### Boot-time auditing

To capture processes that execute before `auditd` userspace startup, configure kernel auditing at boot where required:

```text
audit=1
audit_backlog_limit=8192
```

Exact bootloader/kernel parameters should be validated against the OS release and applicable benchmark/STIG.

### Recommended ordered rule-file pattern

```text
/etc/audit/rules.d/10-base-config.rules
/etc/audit/rules.d/20-identity.rules
/etc/audit/rules.d/30-security-config.rules
/etc/audit/rules.d/31-privileged.rules
/etc/audit/rules.d/40-file-access.rules
/etc/audit/rules.d/50-platform.rules
/etc/audit/rules.d/99-finalize.rules
```

---

## 2. Audit Subsystem Protection

| Title | Auditd rule | Description | ACSC / ISM outcome alignment |
|---|---|---|---|
| Audit configuration changes | `-w /etc/audit/ -p wa -k audit_config` | Detect modification of audit rules and configuration. | Event logging integrity; security configuration |
| auditd configuration | `-w /etc/audit/auditd.conf -p wa -k audit_config` | Detect changes to audit daemon configuration. | Event logging integrity |
| Audit rules directory | `-w /etc/audit/rules.d/ -p wa -k audit_rules` | Detect rule additions, changes or deletion. | Audit control protection |
| Loaded audit rules | `-w /etc/audit/audit.rules -p wa -k audit_rules` | Monitor generated/legacy audit rule file. | Audit configuration integrity |
| Audit log directory | `-w /var/log/audit/ -p wa -k audit_logs` | Detect modification/deletion of audit logs. May be noisy depending on configuration. | Protection of event logs |
| auditctl execution | `-w /sbin/auditctl -p x -k audit_tools` | Detect manual manipulation of audit subsystem. | Administrative activity |
| ausearch execution | `-w /sbin/ausearch -p x -k audit_tools` | Detect use of audit investigation utility. | Audit administration |
| aureport execution | `-w /sbin/aureport -p x -k audit_tools` | Detect generation of audit reports. | Audit administration |
| augenrules execution | `-w /sbin/augenrules -p x -k audit_tools` | Detect loading/regeneration of audit rules. | Audit configuration |

---

## 3. System Identity

**DISA STIG RHEL 9:** aligns with `30-stig.rules` system-locale/network auditing for hostname, issue files, hosts and NetworkManager changes.

| Title | Auditd rule | Description | ACSC / ISM outcome alignment |
|---|---|---|---|
| Hostname changes | `-a always,exit -F arch=b64 -S sethostname,setdomainname -k system_identity` | Detect changes to system hostname/domain. | System configuration changes |
| Hostname file | `-w /etc/hostname -p wa -k system_identity` | Detect persistent hostname modification. | System integrity |
| Hosts file | `-w /etc/hosts -p wa -k network_config` | Detect local DNS/host mapping modification. | Network/security configuration |
| Network identity | `-w /etc/sysconfig/network -p wa -k network_config` | Detect legacy RHEL network configuration modification. | Network configuration |
| Machine ID | `-w /etc/machine-id -p wa -k system_identity` | Detect manipulation of machine identity. | Asset/system identity integrity |
| Login banner (`/etc/issue`) | `-w /etc/issue -p wa -k system_locale` | Detect changes to local login/security banner. | System configuration; administrative control |
| Remote login banner (`/etc/issue.net`) | `-w /etc/issue.net -p wa -k system_locale` | Detect changes to remote login/security banner. | System configuration; administrative control |

---

## 4. Date and Time

**DISA STIG RHEL 9:** aligns with `30-stig.rules` time-change auditing (`adjtimex`, `settimeofday`, `clock_settime`, `/etc/localtime`).

**CIS RHEL 9 v2.0.0:** 6.3.3.4 — Ensure events that modify date and time information are collected.

**Framework cross-reference:** CIS audit time-change controls; DISA STIG audit time-change requirements; ACSC/ISM event logging and timestamp integrity.

```text
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time_change
-a always,exit -F arch=b64 -S clock_settime -F a0=0 -k time_change
-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time_change
-a always,exit -F arch=b32 -S clock_settime -F a0=0 -k time_change
-w /etc/localtime -p wa -k time_change
```

| Title | Description | ACSC / ISM outcome alignment |
|---|---|---|
| System clock change | Detect manual/kernel time changes. | Accurate timestamps |
| Hardware/realtime clock change | Detect clock manipulation. | Audit integrity |
| Timezone change | Detect `/etc/localtime` modification. | Timestamp integrity |

Additional time synchronization monitoring:

```text
-w /etc/chrony.conf -p wa -k time_sync
-w /etc/chrony.keys -p wa -k time_sync
```

For systems using NTP:

```text
-w /etc/ntp.conf -p wa -k time_sync
```

---


CIS canonical form:

```text
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
```

The broader rules in this catalogue are equivalent in security intent but may use a different audit key (`time_change`) or split syscalls for compatibility/clarity.


### DISA STIG canonical form — time changes

```text
-a always,exit -F arch=b32 -S adjtimex,settimeofday,stime -F key=time-change
-a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=time-change
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -F key=time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -F key=time-change
-a always,exit -F arch=b32 -F path=/etc/localtime -F perm=wa -F key=time-change
-a always,exit -F arch=b64 -F path=/etc/localtime -F perm=wa -F key=time-change
```


## 5. User and Group Account Management

**DISA STIG RHEL 9:** RHEL-09-654220 / 654225 / 654230 / 654235 / 654240 / 654245 — audit changes to passwd/group/shadow/gshadow/opasswd identity stores.

**CIS RHEL 9 v2.0.0:** 6.3.3.8 — Ensure events that modify user/group information are collected.

**Framework cross-reference:** CIS identity-change auditing; DISA STIG account-change auditing; ACSC/ISM identity, authentication and privileged-access monitoring.

```text
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
```

| Title | Description | ACSC / ISM outcome alignment |
|---|---|---|
| User account database changes | Creation/deletion/modification of local accounts. | Identity and access management |
| Password database changes | Detect password/hash modification. | Authentication security |
| Group membership changes | Detect privilege/group modifications. | Privileged access management |
| Password history changes | Detect tampering with password history. | Authentication policy |

Account-management binaries:

```text
-w /usr/sbin/useradd -p x -k account_management
-w /usr/sbin/userdel -p x -k account_management
-w /usr/sbin/usermod -p x -k account_management
-w /usr/sbin/groupadd -p x -k account_management
-w /usr/sbin/groupdel -p x -k account_management
-w /usr/sbin/groupmod -p x -k account_management
-w /usr/bin/passwd -p x -k account_management
-w /usr/bin/chage -p x -k account_management
-w /usr/bin/gpasswd -p x -k account_management
```

---


### DISA STIG canonical form — identity/account databases

```text
-a always,exit -F arch=b32 -F path=/etc/group -F perm=wa -F key=identity
-a always,exit -F arch=b64 -F path=/etc/group -F perm=wa -F key=identity
-a always,exit -F arch=b32 -F path=/etc/passwd -F perm=wa -F key=identity
-a always,exit -F arch=b64 -F path=/etc/passwd -F perm=wa -F key=identity
-a always,exit -F arch=b32 -F path=/etc/gshadow -F perm=wa -F key=identity
-a always,exit -F arch=b64 -F path=/etc/gshadow -F perm=wa -F key=identity
-a always,exit -F arch=b32 -F path=/etc/shadow -F perm=wa -F key=identity
-a always,exit -F arch=b64 -F path=/etc/shadow -F perm=wa -F key=identity
-a always,exit -F arch=b32 -F path=/etc/security/opasswd -F perm=wa -F key=identity
-a always,exit -F arch=b64 -F path=/etc/security/opasswd -F perm=wa -F key=identity
```


## 6. Authentication Configuration

**Framework cross-reference:** CIS/STIG authentication configuration protection; ACSC/ISM authentication and access-control security objectives.

```text
-w /etc/pam.d/ -p wa -k authentication
-w /etc/security/ -p wa -k authentication
-w /etc/login.defs -p wa -k authentication
-w /etc/nsswitch.conf -p wa -k authentication
```

For modern RHEL authselect:

```text
-w /etc/authselect/ -p wa -k authentication
```

Covers changes to:

- password requirements
- MFA integration
- account lockout
- authentication sources
- PAM restrictions
- identity-provider configuration

**ACSC / ISM outcome alignment:** authentication controls, privileged access, security configuration.

---

## 7. SSH Security

```text
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/ssh/sshd_config.d/ -p wa -k ssh_config
-w /etc/ssh/ssh_config -p wa -k ssh_config
-w /etc/ssh/ssh_config.d/ -p wa -k ssh_config
```

Root SSH keys:

```text
-w /root/.ssh/ -p wa -k ssh_keys
```

Useful executable monitoring:

```text
-w /usr/bin/ssh -p x -k remote_access
-w /usr/bin/scp -p x -k remote_access
-w /usr/bin/sftp -p x -k remote_access
```

---

## 8. sudo and Privilege Escalation

**DISA STIG RHEL 9:** RHEL-09-654145 — `/usr/bin/su`; RHEL-09-654150 — `/usr/bin/sudo`; RHEL-09-654215 — `/etc/sudoers`; RHEL-09-654010 — privileged execution/effective-ID mismatch.

**CIS RHEL 9 v2.0.0:** 6.3.3.1 — sudoers scope changes; 6.3.3.3 — sudo log file changes.

```text
-w /etc/sudoers -p wa -k sudo_config
-w /etc/sudoers.d/ -p wa -k sudo_config
```

Execution:

```text
-w /usr/bin/sudo -p x -k privilege_escalation
-w /usr/bin/su -p x -k privilege_escalation
```

Optional sudo I/O logs:

```text
-w /var/log/sudo-io/ -p wa -k sudo_activity
```

**ACSC / ISM outcome alignment:** privileged access, administrative activity, accountability.

---


### DISA STIG canonical form — sudoers / admin actions

```text
-a always,exit -F arch=b32 -F path=/etc/sudoers -F perm=wa -F key=actions
-a always,exit -F arch=b64 -F path=/etc/sudoers -F perm=wa -F key=actions
-a always,exit -F arch=b32 -F dir=/etc/sudoers.d/ -F perm=wa -F key=actions
-a always,exit -F arch=b64 -F dir=/etc/sudoers.d/ -F perm=wa -F key=actions
```

Selected privileged-command STIG rules:

```text
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=unset -k privileged-mount
-a always,exit -F path=/usr/sbin/reboot -F perm=x -F auid>=1000 -F auid!=unset -k privileged-reboot
-a always,exit -F path=/usr/sbin/shutdown -F perm=x -F auid>=1000 -F auid!=unset -k privileged-shutdown
```

Special escalation helpers from the STIG sample rules:

```text
-a always,exit -F arch=b32 -F path=/usr/bin/systemd-run -F perm=x -F auid!=unset -F key=maybe-escalation
-a always,exit -F arch=b64 -F path=/usr/bin/systemd-run -F perm=x -F auid!=unset -F key=maybe-escalation
-a always,exit -F arch=b32 -F path=/usr/bin/pkexec -F perm=x -F key=maybe-escalation
-a always,exit -F arch=b64 -F path=/usr/bin/pkexec -F perm=x -F key=maybe-escalation
```


## 9. UID/GID and Credential Manipulation

**CIS RHEL 9 v2.0.0:** aligns with 6.3.3.2 when `execve` is used with `-C euid!=uid` to capture actions performed as another user.

64-bit:

```text
-a always,exit -F arch=b64 -S setuid,setreuid,setresuid -k credential_change
-a always,exit -F arch=b64 -S setgid,setregid,setresgid -k credential_change
-a always,exit -F arch=b64 -S setfsuid,setfsgid -k credential_change
```

32-bit:

```text
-a always,exit -F arch=b32 -S setuid,setreuid,setresuid -k credential_change
-a always,exit -F arch=b32 -S setgid,setregid,setresgid -k credential_change
-a always,exit -F arch=b32 -S setfsuid,setfsgid -k credential_change
```

---

## 10. Login and Session Tracking

**DISA STIG RHEL 9:** RHEL-09-654250 — `/var/log/faillock`; RHEL-09-654255 — `/var/log/lastlog`.

**CIS RHEL 9 v2.0.0:** 6.3.3.11 — session initiation; 6.3.3.12 — login/logout events.

```text
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/lastlog -p wa -k session
-w /var/log/faillog -p wa -k session
-w /var/run/faillock -p wa -k logins
```

Covers:

- interactive login history
- failed login history
- current sessions
- user session records

---

## 11. Failed File Access

**DISA STIG RHEL 9:** aligns with `30-stig.rules` failed-access auditing using EACCES/EPERM and key `access`.

CIS uses audit key `access`; this catalogue may use `access_denied`. Modern implementations may additionally include `openat2` and/or `open_by_handle_at` where supported.

**CIS RHEL 9 v2.0.0:** 6.3.3.7 — unsuccessful file access attempts.

64-bit:

```text
-a always,exit -F arch=b64 -S open,openat,openat2,open_by_handle_at,creat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access_denied
-a always,exit -F arch=b64 -S open,openat,openat2,open_by_handle_at,creat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access_denied
```

32-bit:

```text
-a always,exit -F arch=b32 -S open,openat,open_by_handle_at,creat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access_denied
-a always,exit -F arch=b32 -S open,openat,open_by_handle_at,creat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access_denied
```

**Security value:** High.  
**Volume risk:** Potentially high.

---


### DISA STIG canonical form — unauthorized file access

```text
-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,openat2,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b32 -S open,creat,truncate,ftruncate,openat,openat2,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,openat2,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -F key=access
-a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat,openat2,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -F key=access
```


## 12. File Deletion and Rename

**DISA STIG RHEL 9:** aligns with `30-stig.rules` delete/rename auditing using key `delete`.

CIS uses audit key `delete` for rename/unlink/rmdir deletion activity.

**CIS RHEL 9 v2.0.0:** 6.3.3.13 — file deletion events by users.

```text
-a always,exit -F arch=b64 -S rmdir,unlink,unlinkat,rename,renameat,renameat2 -F auid>=1000 -F auid!=unset -k file_delete
-a always,exit -F arch=b32 -S rmdir,unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k file_delete
```

Use cases include:

- destructive activity
- anti-forensics
- ransomware
- attacker cleanup
- configuration replacement

---


### DISA STIG canonical form — delete / rename

```text
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -F key=delete
```

This catalogue's broader rule may additionally include `renameat2` and `rmdir`.


## 13. Permission and Ownership Changes

**DISA STIG RHEL 9:** aligns with `30-stig.rules` DAC permission modification auditing using key `perm_mod`.

CIS uses audit key `perm_mod` for chmod/chown/xattr-related discretionary access-control changes.

**CIS RHEL 9 v2.0.0:** 6.3.3.9 — discretionary access control permission modification events.

```text
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k permissions
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -k ownership
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k permissions
-a always,exit -F arch=b32 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -k ownership
```

---


### DISA STIG canonical form — DAC modifications

```text
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat,fchmodat2,file_setattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat,fchmodat2,file_setattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat,file_setattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat,file_setattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,file_setattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,file_setattr -F auid>=1000 -F auid!=unset -F key=perm_mod
```

`fchmodat2` and `file_setattr` availability is kernel/audit-tool dependent; validate before deployment.


## 14. Extended Attributes

**DISA STIG RHEL 9:** aligns with `30-stig.rules` extended-attribute DAC change auditing using key `perm_mod`.

```text
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k xattr
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k xattr
```

Useful for detecting:

- SELinux label manipulation
- capabilities manipulation
- metadata tampering
- security attribute manipulation

Additional discretionary-access-control administration utilities:

```text
-w /usr/bin/chcon -p x -k permissions
-w /usr/bin/setfacl -p x -k permissions
-w /usr/bin/chacl -p x -k permissions
```

Only enable paths that exist on the host.

---

## 15. Linux Capabilities

```text
-a always,exit -F arch=b64 -S capset -k capabilities
-a always,exit -F arch=b32 -S capset -k capabilities
```

Tools:

```text
-w /usr/sbin/setcap -p x -k capabilities
-w /usr/sbin/getcap -p x -k capabilities
```

---

## 16. SUID/SGID and Privileged Execution

**DISA STIG RHEL 9:** RHEL-09-654010 and `31-privileged.rules` — audit privileged/setuid command execution.

**CIS RHEL 9 v2.0.0:** 6.3.3.6 — ensure use of privileged commands is collected.

```text
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k privileged_exec
```

Discover SUID/SGID files dynamically:

```bash
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f
```

CIS remediation-style dynamic rule generation:

```bash
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | \
  awk -v UID_MIN="$UID_MIN" '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=" UID_MIN " -F auid!=unset -k privileged"}'
```


Example explicit rule:

```text
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged
```

---

## 17. Kernel Module Activity

**DISA STIG RHEL 9:** aligns with `30-stig.rules` module loading/unloading audit coverage.

**CIS RHEL 9 v2.0.0:** 6.3.3.15–6.3.3.19 — additional common audit controls, including kernel module loading/unloading.

```text
-w /usr/sbin/insmod -p x -k kernel_module
-w /usr/sbin/rmmod -p x -k kernel_module
-w /usr/sbin/modprobe -p x -k kernel_module
```

Syscalls:

```text
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k kernel_module
-a always,exit -F arch=b32 -S init_module,delete_module -k kernel_module
```

---

## 18. Kernel Configuration

```text
-w /etc/sysctl.conf -p wa -k kernel_config
-w /etc/sysctl.d/ -p wa -k kernel_config
-w /usr/lib/sysctl.d/ -p wa -k kernel_config
-w /usr/sbin/sysctl -p x -k kernel_config
```

---

## 19. Bootloader Configuration

```text
-w /boot/grub2/grub.cfg -p wa -k boot_config
-w /etc/default/grub -p wa -k boot_config
```

UEFI example:

```text
-w /boot/efi/EFI/redhat/grub.cfg -p wa -k boot_config
```

Monitor regeneration:

```text
-w /usr/sbin/grub2-mkconfig -p x -k boot_config
```

---

## 20. SELinux Security Controls

**DISA STIG RHEL 9:** aligns with `30-stig.rules` MAC-policy auditing for `/etc/selinux/`.

CIS uses audit key `MAC-policy` and explicitly watches both `/etc/selinux` and `/usr/share/selinux`.

**CIS RHEL 9 v2.0.0:** 6.3.3.14 — ensure events that modify Mandatory Access Controls are collected.

```text
-w /etc/selinux/ -p wa -k selinux
-w /etc/selinux/config -p wa -k selinux
-w /usr/share/selinux/ -p wa -k selinux
-w /usr/sbin/setenforce -p x -k selinux
-w /usr/sbin/semanage -p x -k selinux
-w /usr/sbin/semodule -p x -k selinux
```

---


### DISA STIG canonical form — MAC policy

```text
-a always,exit -F arch=b32 -F dir=/etc/selinux/ -F perm=wa -F key=MAC-policy
-a always,exit -F arch=b64 -F dir=/etc/selinux/ -F perm=wa -F key=MAC-policy
```


## 21. Firewall Configuration

Firewalld:

```text
-w /etc/firewalld/ -p wa -k firewall
-w /usr/bin/firewall-cmd -p x -k firewall
```

iptables:

```text
-w /usr/sbin/iptables -p x -k firewall
-w /usr/sbin/ip6tables -p x -k firewall
```

nftables:

```text
-w /usr/sbin/nft -p x -k firewall
-w /etc/nftables/ -p wa -k firewall
-w /etc/sysconfig/nftables.conf -p wa -k firewall
```

---

## 22. Network Configuration

```text
-w /etc/NetworkManager/ -p wa -k network_config
-w /etc/resolv.conf -p wa -k dns_config
-w /etc/hosts -p wa -k network_config
-w /etc/host.conf -p wa -k network_config
-w /usr/sbin/ip -p x -k network_admin
-w /usr/bin/nmcli -p x -k network_admin
```

---

## 23. Route Manipulation

```text
-w /usr/sbin/ip -p x -k route_change
-w /usr/bin/nmcli -p x -k route_change
```

---

## 24. Mounting Filesystems

**DISA STIG RHEL 9:** RHEL-09-654180 — audit `/usr/bin/mount`; `30-stig.rules` also audits mount-related syscalls with key `export`.

CIS canonical control focuses on successful `mount` syscalls by interactive users; this catalogue additionally includes unmount visibility as a threat-detection enhancement.

**CIS RHEL 9 v2.0.0:** 6.3.3.10 — ensure successful filesystem mounts are collected.

```text
-a always,exit -F arch=b64 -S mount,umount2 -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=b32 -S mount,umount,umount2 -F auid>=1000 -F auid!=unset -k mounts
-w /usr/bin/mount -p x -k mounts
-w /usr/bin/umount -p x -k mounts
```

---


### DISA STIG canonical form — media export / mount

```text
-a always,exit -F arch=b32 -S mount,mount_setattr -F auid>=1000 -F auid!=unset -F key=export
-a always,exit -F arch=b64 -S mount,mount_setattr -F auid>=1000 -F auid!=unset -F key=export
```

`mount_setattr` support depends on kernel/audit tooling.


## 25. Removable Media

```text
-w /media/ -p wa -k removable_media
-w /run/media/ -p wa -k removable_media
```

Use with care on workstations due to event volume.

---

## 26. Cron Configuration

**DISA STIG RHEL 9:** RHEL-09-654097 — audit changes to `/etc/cron.d/` and `/var/spool/cron/`.

**Framework cross-reference:** CIS/STIG scheduled-task protection; ACSC/ISM persistence and administrative-change monitoring.

```text
-w /etc/crontab -p wa -k scheduled_tasks
-w /etc/cron.d/ -p wa -k scheduled_tasks
-w /etc/cron.hourly/ -p wa -k scheduled_tasks
-w /etc/cron.daily/ -p wa -k scheduled_tasks
-w /etc/cron.weekly/ -p wa -k scheduled_tasks
-w /etc/cron.monthly/ -p wa -k scheduled_tasks
-w /var/spool/cron/ -p wa -k scheduled_tasks
```

---


### DISA STIG canonical form — cron jobs

**RHEL-09-654097**

```text
-w /etc/cron.d/ -p wa -k cronjobs
-w /var/spool/cron/ -p wa -k cronjobs
```


## 27. systemd Service Persistence

```text
-w /etc/systemd/system/ -p wa -k systemd
-w /usr/lib/systemd/system/ -p wa -k systemd
-w /usr/bin/systemctl -p x -k service_management
```

High-value activity includes:

- service creation
- enable/disable
- mask/unmask
- daemon-reload
- security service stop/start

---

## 28. Legacy Startup Persistence

```text
-w /etc/rc.d/rc.local -p wa -k persistence
-w /etc/rc.local -p wa -k persistence
```

---

## 29. Shell Profile Persistence

```text
-w /etc/profile -p wa -k shell_config
-w /etc/profile.d/ -p wa -k shell_config
-w /etc/bashrc -p wa -k shell_config
```

---

## 30. Dynamic Linker Manipulation

```text
-w /etc/ld.so.preload -p wa -k library_injection
-w /etc/ld.so.conf -p wa -k library_config
-w /etc/ld.so.conf.d/ -p wa -k library_config
```

---

## 31. Package Management

```text
-w /usr/bin/rpm -p x -k software_install
-w /usr/bin/dnf -p x -k software_install
-w /usr/bin/yum -p x -k software_install
-w /etc/yum.repos.d/ -p wa -k repository_config
-w /etc/dnf/ -p wa -k repository_config
```

---

## 32. RPM Database

```text
-w /var/lib/rpm/ -p wa -k package_database
```

Verify database location on the installed RHEL release.

---

## 33. Security Software Changes

AIDE:

```text
-w /etc/aide.conf -p wa -k security_tools
```

fapolicyd:

```text
-w /etc/fapolicyd/fapolicyd.conf -p wa -k fapolicyd
-w /etc/fapolicyd/fapolicyd.rules -p wa -k fapolicyd
-w /etc/fapolicyd/rules.d/ -p wa -k fapolicyd
-w /usr/sbin/fapolicyd -p x -k fapolicyd
-w /usr/sbin/fapolicyd-cli -p x -k fapolicyd
```

---

## 34. AIDE Integrity Configuration

```text
-w /etc/aide.conf -p wa -k file_integrity
-w /etc/aide.conf.d/ -p wa -k file_integrity
```

---

## 35. Logging Configuration

rsyslog:

```text
-w /etc/rsyslog.conf -p wa -k logging_config
-w /etc/rsyslog.d/ -p wa -k logging_config
```

journald:

```text
-w /etc/systemd/journald.conf -p wa -k logging_config
-w /etc/systemd/journald.conf.d/ -p wa -k logging_config
```

logrotate:

```text
-w /etc/logrotate.conf -p wa -k logging_config
-w /etc/logrotate.d/ -p wa -k logging_config
```

---

## 36. Anti-Forensics Utilities

```text
-w /usr/bin/shred -p x -k anti_forensics
-w /usr/bin/truncate -p x -k anti_forensics
```

Avoid broad execution auditing of `rm`, `mv`, or `cp` without volume testing.

---

## 37. Process Execution

```text
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=unset -k user_exec
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=unset -k user_exec
```

**Security value:** High.  
**Volume:** Very high in some environments.

---

## 38. Root Command Execution

```text
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k root_command
```

High-value SOC rule for tracking:

> logged-in user → command executing as root

---

## 39. Direct Root Sessions

```text
-a always,exit -F arch=b64 -S execve -F auid=0 -k root_session
```

---

## 40. Process Tracing / Debugging

```text
-a always,exit -F arch=b64 -S ptrace -k process_injection
-a always,exit -F arch=b32 -S ptrace -k process_injection
```

---

## 41. Process Memory Access

```text
-a always,exit -F arch=b64 -S process_vm_readv,process_vm_writev -k process_memory
```

---

## 42. Namespace Creation

```text
-a always,exit -F arch=b64 -S unshare,setns -F auid>=1000 -F auid!=unset -k namespace
```

---

## 43. chroot

```text
-a always,exit -F arch=b64 -S chroot -F auid>=1000 -F auid!=unset -k chroot
-a always,exit -F arch=b32 -S chroot -F auid>=1000 -F auid!=unset -k chroot
```

---

## 44. Reboot and Shutdown

**DISA STIG RHEL 9:** RHEL-09-654195 — `/usr/sbin/reboot`; RHEL-09-654200 — `/usr/sbin/shutdown`.

```text
-w /usr/sbin/reboot -p x -k system_shutdown
-w /usr/sbin/shutdown -p x -k system_shutdown
-w /usr/sbin/poweroff -p x -k system_shutdown
```

---

## 45. Service Management and Splunk Forwarder

```text
-w /usr/bin/systemctl -p x -k service_management
```

For Splunk Universal Forwarder:

```text
-w /opt/splunkforwarder/etc/ -p wa -k splunk_config
-w /opt/splunkforwarder/bin/splunk -p x -k splunk_admin
```

---

## 46. Kernel Log Manipulation

```text
-w /usr/bin/dmesg -p x -k kernel_logs
```

---

## 47. Persistent `/proc`-Relevant Security Configuration

Prefer monitoring:

```text
/etc/sysctl.conf
/etc/sysctl.d/
```

instead of broad `/proc` watches.

---

## 48. DNS Configuration

```text
-w /etc/resolv.conf -p wa -k dns_config
-w /etc/hosts -p wa -k dns_config
-w /etc/nsswitch.conf -p wa -k dns_config
```

---

## 49. PKI and Trusted Certificates

```text
-w /etc/pki/ca-trust/ -p wa -k trusted_certificates
-w /etc/pki/tls/ -p wa -k certificates
-w /etc/pki/ca-trust/source/anchors/ -p wa -k trusted_certificates
```

---

## 50. SSH Host Keys

```text
-w /etc/ssh/ssh_host_rsa_key -p wa -k ssh_host_keys
-w /etc/ssh/ssh_host_ecdsa_key -p wa -k ssh_host_keys
-w /etc/ssh/ssh_host_ed25519_key -p wa -k ssh_host_keys
```

---

## 51. Broad `/etc` Changes

Possible broad rule:

```text
-w /etc/ -p wa -k etc_changes
```

**Recommendation:** Usually avoid as the primary production rule because of noise. Prefer targeted monitoring.

---

## 52. Docker

```text
-w /usr/bin/docker -p x -k container_admin
-w /etc/docker/ -p wa -k docker_config
-w /etc/docker/daemon.json -p wa -k docker_config
```

Avoid broad `/var/lib/docker/` monitoring without testing.

---

## 53. Podman

```text
-w /usr/bin/podman -p x -k container_admin
-w /etc/containers/ -p wa -k container_config
```

---

## 54. Container Runtime

```text
-w /usr/bin/crun -p x -k container_runtime
-w /usr/bin/runc -p x -k container_runtime
```

Use only if binaries exist.

---

## 55. Kubernetes / OpenShift Node Security

```text
-w /etc/kubernetes/ -p wa -k kubernetes
-w /etc/kubernetes/manifests/ -p wa -k kubernetes
```

Adjust paths for OpenShift.

---

## 56. Sensitive File Access

Example:

```text
-w /etc/shadow -p rwa -k sensitive_file
```

For lower volume, prefer:

```text
-w /etc/shadow -p wa -k identity
```

---

## 57. `/etc/security`

```text
-w /etc/security/ -p wa -k security_policy
```

---

## 58. Password Policy

```text
-w /etc/security/pwquality.conf -p wa -k password_policy
-w /etc/security/pwquality.conf.d/ -p wa -k password_policy
-w /etc/login.defs -p wa -k password_policy
```

---

## 59. Account Lockout

```text
-w /etc/security/faillock.conf -p wa -k authentication_policy
```

---

## 60. Crypto Policy

```text
-w /etc/crypto-policies/ -p wa -k crypto_policy
-w /usr/bin/update-crypto-policies -p x -k crypto_policy
```

---

## 61. FIPS Configuration

```text
-w /etc/system-fips -p wa -k crypto_policy
```

Verify against the installed RHEL release.

---

## 62. Environment Configuration

```text
-w /etc/environment -p wa -k environment_config
```

---

## 63. Proxy Configuration

```text
-w /etc/profile.d/ -p wa -k proxy_config
-w /etc/environment -p wa -k proxy_config
```

Prefer targeted files where possible.

---

## 64. Downloader Execution

```text
-w /usr/bin/curl -p x -k network_tools
-w /usr/bin/wget -p x -k network_tools
```

---

## 65. Network Reconnaissance Utilities

```text
-w /usr/bin/nc -p x -k network_tools
-w /usr/bin/ncat -p x -k network_tools
-w /usr/bin/ssh -p x -k remote_access
-w /usr/bin/nmap -p x -k network_scan
```

---

## 66. Compiler Execution

```text
-w /usr/bin/gcc -p x -k compiler
-w /usr/bin/cc -p x -k compiler
-w /usr/bin/make -p x -k compiler
```

---

## 67. Script Interpreter Execution

```text
-w /usr/bin/python3 -p x -k interpreter
-w /usr/bin/perl -p x -k interpreter
```

Use asset-specific policy due to potential volume.

---

## 68. File Transfer Utilities

```text
-w /usr/bin/scp -p x -k file_transfer
-w /usr/bin/sftp -p x -k file_transfer
-w /usr/bin/rsync -p x -k file_transfer
```

---

## 69. Archive Utilities

```text
-w /usr/bin/tar -p x -k archive
-w /usr/bin/zip -p x -k archive
```

---

## 70. Base64 Execution

```text
-w /usr/bin/base64 -p x -k encoding_tool
```

---

## 71. Scheduled `at` Jobs

```text
-w /var/spool/at/ -p wa -k scheduled_tasks
-w /etc/at.allow -p wa -k scheduled_tasks
-w /etc/at.deny -p wa -k scheduled_tasks
```

---

## 72. Root Home Configuration

```text
-w /root/.bashrc -p wa -k root_config
-w /root/.bash_profile -p wa -k root_config
-w /root/.profile -p wa -k root_config
-w /root/.ssh/ -p wa -k root_ssh
```

---

## 73. Shell History Manipulation

```text
-w /root/.bash_history -p wa -k shell_history
```

Audit syscall execution is generally more trustworthy than shell history.

---

## 74. Immutable File Attributes

```text
-w /usr/bin/chattr -p x -k file_attributes
-w /usr/bin/lsattr -p x -k file_attributes
```

---

## 75. Filesystem Creation

```text
-w /usr/sbin/mkfs -p x -k filesystem_admin
```

Add filesystem-specific executables as required.

---

## 76. LVM / Storage Administration

```text
-w /usr/sbin/lvcreate -p x -k storage_admin
-w /usr/sbin/lvremove -p x -k storage_admin
-w /usr/sbin/vgcreate -p x -k storage_admin
-w /usr/sbin/vgremove -p x -k storage_admin
```

---

## 77. Swap Manipulation

```text
-w /usr/sbin/swapon -p x -k memory_admin
-w /usr/sbin/swapoff -p x -k memory_admin
```

---

## 78. Host Access Controls

```text
-w /etc/hosts.allow -p wa -k access_control
-w /etc/hosts.deny -p wa -k access_control
```

Primarily relevant to legacy TCP wrappers environments.

---

## 79. Kerberos Configuration

```text
-w /etc/krb5.conf -p wa -k kerberos
-w /etc/krb5.conf.d/ -p wa -k kerberos
```

---

## 80. SSSD Configuration

```text
-w /etc/sssd/ -p wa -k identity_provider
-w /etc/sssd/sssd.conf -p wa -k identity_provider
```

High-value for AD / IPA / RHEL IdM environments.

---

## 81. Red Hat IPA / IdM Client Configuration

```text
-w /etc/ipa/ -p wa -k ipa_config
-w /etc/krb5.conf -p wa -k ipa_config
-w /etc/sssd/ -p wa -k ipa_config
```

---

## 82. LDAP Configuration

```text
-w /etc/openldap/ -p wa -k ldap_config
```

---

## 83. Splunk Universal Forwarder Protection

```text
-w /opt/splunkforwarder/etc/system/local/ -p wa -k splunk_config
-w /opt/splunkforwarder/etc/apps/ -p wa -k splunk_config
```

High-value files include:

- `inputs.conf`
- `outputs.conf`
- `server.conf`
- `deploymentclient.conf`

---

## 84. Security Service Actions

Detect attempts to stop or disable critical security/logging services such as:

```text
auditd
rsyslog
systemd-journald
splunkforwarder
fapolicyd
firewalld
```

Use service-management telemetry plus targeted process/service alerts.

---

## 85. BPF / eBPF Activity

Where supported, consider syscall auditing for:

```text
-S bpf
```

Test carefully before deployment because volume may be significant on systems using:

- observability agents
- EDR
- Kubernetes
- networking software

---

## 86. Key Management

Examples:

```text
-w /etc/krb5.keytab -p wa -k credentials
```

For high-value systems:

```text
-w /etc/krb5.keytab -p rwa -k credentials
```

---

## 87. Sensitive Credential Material

Potential targeted locations:

```text
/etc/shadow
/etc/gshadow
/etc/krb5.keytab
/root/.ssh/
```

Avoid broad credential-path auditing without testing volume and operational impact.

---

## 88. Audit Rule Finalisation

**DISA STIG RHEL 9:** RHEL-09-654275 — `-e 2`; STIG preference also includes RHEL-09-654265 — `-f 2`.

**CIS RHEL 9 v2.0.0:** 6.3.3.20 / Finalize — ensure the audit configuration is immutable.

After rule testing and validation:

```text
-e 2
```

This makes the active audit configuration immutable until reboot.

> Do not enable `-e 2` while developing or troubleshooting rules.

---

# Recommended ACSC / ISM Priority Model

| Priority | Audit category |
|---|---|
| Critical | Audit configuration modification |
| Critical | Audit log deletion/tampering |
| Critical | User/account creation/deletion |
| Critical | Privileged-group membership |
| Critical | sudo/root command execution |
| Critical | Direct root sessions |
| Critical | Authentication policy changes |
| Critical | SSH configuration |
| Critical | SSH privileged key changes |
| Critical | Security-control disablement |
| Critical | SELinux modification |
| Critical | fapolicyd/application-control modification |
| Critical | Firewall modification |
| Critical | Kernel module loading |
| Critical | Logging configuration modification |
| Critical | Splunk/log-forwarder configuration modification |
| High | Failed file access |
| High | Privileged executable execution |
| High | File permission changes |
| High | File ownership changes |
| High | SUID/SGID activity |
| High | Linux capability modification |
| High | Time changes |
| High | cron/systemd persistence |
| High | Package installation/removal |
| High | Trusted CA changes |
| High | Crypto-policy changes |
| High | Kernel/sysctl modification |
| High | Bootloader modification |
| High | Mount/removable-media activity |
| High | SSSD/IPA/Kerberos changes |
| High | Process injection/ptrace |
| High | Dynamic linker/LD preload |
| Medium | General file deletion |
| Medium | Network administration |
| Medium | Container administration |
| Medium | File-transfer utilities |
| Medium | Archive tools |
| Medium | Compiler execution |
| Medium | Downloader execution |
| Medium | General user `execve` |
| Contextual | All `/etc` changes |
| Contextual | All shell execution |
| Contextual | General read access monitoring |

---

# ACSC / ISM Outcome-Aligned Audit Taxonomy

```text
ACSC / ISM Outcome-Aligned Audit Taxonomy
│
├── Event Logging & Monitoring
│   ├── Audit generation
│   ├── Audit integrity
│   ├── Logging configuration
│   ├── Log forwarding
│   ├── Timestamp integrity
│   └── Audit availability
│
├── Authentication
│   ├── Successful authentication
│   ├── Failed authentication
│   ├── Authentication configuration
│   ├── Credential modification
│   └── Authentication bypass
│
├── Identity & Account Management
│   ├── Account creation
│   ├── Account deletion
│   ├── Account modification
│   ├── Group modification
│   └── Password modification
│
├── Privileged Access
│   ├── sudo
│   ├── su
│   ├── root sessions
│   ├── privileged execution
│   ├── SUID / SGID
│   └── Linux capabilities
│
├── Security Configuration
│   ├── SELinux
│   ├── fapolicyd
│   ├── Firewall
│   ├── Kernel
│   ├── Bootloader
│   ├── Crypto policy
│   └── Authentication policy
│
├── System Administration
│   ├── Services
│   ├── Software
│   ├── Packages
│   ├── Networking
│   ├── Storage
│   └── Filesystems
│
├── Persistence
│   ├── systemd
│   ├── cron
│   ├── at
│   ├── Shell profile
│   ├── SSH keys
│   └── Dynamic linker
│
├── File & Data Access
│   ├── Permission denied
│   ├── Sensitive file access
│   ├── File deletion
│   ├── Ownership
│   ├── Permissions
│   └── Extended attributes
│
├── Defence Evasion
│   ├── Log deletion
│   ├── Audit manipulation
│   ├── Security control disablement
│   ├── Timestamp manipulation
│   ├── Kernel manipulation
│   └── Process manipulation
│
├── Network Security
│   ├── Firewall changes
│   ├── DNS changes
│   ├── Route changes
│   └── Network configuration
│
├── Removable Media
│   ├── Device insertion
│   ├── Filesystem mount
│   └── Data transfer
│
└── Platform-specific
    ├── SSSD
    ├── IPA / IdM
    ├── Kerberos
    ├── Containers
    ├── Kubernetes / OpenShift
    └── Splunk Forwarder
```

---

# Recommended Catalogue Fields

```text
Rule ID
Title
Description
Auditd Rule
Audit Key
Category
Subcategory
Priority
Default Enabled
RHEL 8
RHEL 9
Server
Workstation
High Value Asset
Potential Volume
Performance Impact
Security Value
ACSC / ISM Relevance
Essential Eight Relevance
MITRE ATT&CK Technique
Expected Event Type
Splunk Sourcetype
Detection Use Cases
False Positive Considerations
Validation Command
Rollback
Notes
```

---

# Implementation Notes

- Verify all executable paths using `command -v`.
- Test rules before deployment across the fleet.
- Measure event volume before enabling broad `execve`, read-access, or directory-wide rules.
- Keep audit keys consistent because they are extremely useful for Splunk categorisation and detection.
- Generate host-specific SUID/SGID rules rather than assuming an identical privileged-binary list on every system.
- Treat RHEL 8 and RHEL 9 as separate validation targets where syscall, binary path, package, or configuration behaviour differs.
- Keep rule source files under `/etc/audit/rules.d/` and use `augenrules` where appropriate.
- Use immutable audit configuration only after testing is complete.

---



## Multi-Reference Mapping Example

One rule can legitimately have several references:

```text
Rule:
-w /etc/sudoers -p wa -k scope

References:
- CIS RHEL 9 v2.0.0: 6.3.3.1
- DISA RHEL 9 STIG: RHEL-09-654215
- ACSC ISM outcome alignment: privileged administration, access-control change monitoring, event logging
- SCAP / ComplianceAsCode: applicable XCCDF rule(s), where verified in the installed content
- Threat detection: privilege-policy tampering / sudo configuration modification
```

The important distinction is not the number of references, but the **mapping type**:

```text
Exact
Sample-rule alignment
Security-objective alignment
SCAP implementation mapping
Threat-detection enhancement
```


# Aligned Compliance Crosswalk — Core auditd Controls

| Control objective | Canonical / representative audit coverage | CIS RHEL 9 v2.0.0 | DISA RHEL 9 STIG | ACSC ISM alignment | SCAP status |
|---|---|---|---|---|---|
| Sudoers scope changes | `/etc/sudoers`, `/etc/sudoers.d` write/attribute monitoring | **6.3.3.1** | **RHEL-09-654215** for `/etc/sudoers`; STIG sample also covers sudoers.d | Privileged administration; access-control changes; event logging | Framework profile mapping must be verified in installed SSG |
| Actions as another user | `execve` with `euid!=uid` and attributable `auid` | **6.3.3.2** | Related to **RHEL-09-654010** privileged execution; do not treat as identical syntax | Privileged activity accountability | Verify installed SSG rule |
| Sudo log modification | configured sudo log file, commonly `/var/log/sudo.log` | **6.3.3.3** | Related privileged/admin logging; no exact STIG ID asserted here | Administrative activity and log integrity | Verify installed SSG rule |
| Date/time changes | `adjtimex`, `settimeofday`, `clock_settime`, `/etc/localtime` | **6.3.3.4** | STIG `30-stig.rules` alignment | Timestamp integrity; event correlation | CIS/STIG profiles commonly implement checks; inspect installed content |
| Network/system locale | hostname/domain syscalls and system network identity files | **6.3.3.5** | STIG `30-stig.rules` alignment | Security configuration and system identity | Verify installed SSG profile/rules |
| Privileged commands | dynamically discovered SUID/SGID executables | **6.3.3.6** | `31-privileged.rules`; selected exact IDs include **654145**, **654150**, **654180**, **654195**, **654200** | Privileged activity monitoring | Verify generated/fix content |
| Failed file access | EACCES/EPERM on open/create/truncate families | **6.3.3.7** | STIG `30-stig.rules` alignment | Access-control violations; investigation | Verify installed SSG rule |
| Identity database changes | passwd, group, shadow, gshadow, opasswd | **6.3.3.8** | **RHEL-09-654220–654245** as supplied | Identity/account management; event logging | Verify exact SSG rule IDs |
| DAC modifications | chmod/chown/xattr families | **6.3.3.9** | STIG `30-stig.rules` alignment | Access-control/security configuration changes | Verify installed SSG rule |
| Filesystem mounts | `mount`; STIG extension may include `mount_setattr` | **6.3.3.10** | **RHEL-09-654180** for `/usr/bin/mount`; sample rule key `export` for syscall activity | Removable media/data transfer; privileged activity | Verify installed SSG rule |
| Session initiation | utmp, wtmp, btmp | **6.3.3.11** | STIG sample-rule alignment | Authentication/session monitoring | Verify installed SSG rule |
| Login/logout | lastlog, faillock | **6.3.3.12** | **RHEL-09-654250 / 654255** | Authentication monitoring | Verify installed SSG rule |
| File deletion | rename/unlink/rmdir family | **6.3.3.13** | STIG `30-stig.rules` alignment | Destructive activity and anti-forensics visibility | Verify installed SSG rule |
| MAC policy changes | SELinux policy/config paths | **6.3.3.14** | STIG `30-stig.rules` alignment | Mandatory access-control/security-policy integrity | Verify installed SSG rule |
| Additional audit controls | helper utilities, modules and related controls | **6.3.3.15–6.3.3.19 group**; exact sub-control must be verified | STIG sample + platform-specific STIG rules | System integrity and security-control administration | Verify exact profile mapping |
| Audit failure behaviour | audit failure mode | Related audit configuration requirement; exact CIS subsection must be verified | **RHEL-09-654265 → `-f 2`** | Logging availability/resilience | Verify installed SSG rule |
| Immutable rules | `-e 2` loaded last | **6.3.3.20 / Finalize** as supplied | **RHEL-09-654275** | Audit configuration integrity | Verify installed SSG rule |
| auditd installed/enabled | package and service state | **6.3.1** | Applicable STIG service requirements; exact ID not asserted here | Event logging capability | Strong SCAP candidate; verify profile |
| Audit retention/failure actions | `auditd.conf` retention and disk-space actions | **6.3.2** | Applicable STIG audit storage requirements; exact IDs not asserted here | Log retention, availability and investigation | Strong SCAP candidate; verify profile |
| Boot-time auditing | kernel `audit=1`, backlog sizing | Related CIS requirement | Applicable STIG boot-audit requirements | Complete event capture | Verify profile/rule in installed content |

### Important syntax differences that are intentionally preserved

- **CIS versus STIG audit keys:** equivalent security objectives may use different keys such as `scope` vs `actions`, `mounts` vs `export`, or catalogue keys such as `access_denied`. Audit keys are labels; compliance should be assessed against required event capture, not merely key spelling unless the benchmark explicitly tests it.
- **Watch syntax versus syscall/path filters:** `-w /path -p wa` and `-a always,exit ... -F path=/path -F perm=wa` can represent similar monitoring intent but are not textually identical. Keep the canonical framework form when performing automated compliance validation.
- **Extended syscalls:** `openat2`, `open_by_handle_at`, `renameat2`, `fchmodat2`, `mount_setattr`, and `file_setattr` can extend coverage beyond older canonical forms. Their availability depends on kernel and audit userspace support.
- **32-bit rules:** use `arch=b32` only where the platform/kernel supports 32-bit syscall execution and the benchmark/profile requires it.
- **`UID_MIN`:** use the system's configured `UID_MIN` rather than hard-coding `1000` when generating policy programmatically.


# CIS / STIG / ACSC-ISM Crosswalk Summary

| Security outcome | Representative audit coverage | CIS | DISA STIG | ACSC / ISM |
|---|---|---|---|---|
| Audit subsystem protection | `/etc/audit`, audit tools, `-f 2`, immutable rules | Yes | RHEL-09-654265 / 654275 | Event logging integrity |
| Time integrity | `adjtimex`, `settimeofday`, `clock_settime`, `/etc/localtime` | Yes | Yes | Reliable timestamps and investigation |
| Identity changes | passwd, shadow, group, gshadow, opasswd, account tools | Yes | RHEL-09-654220–654245 | Identity/account management |
| Authentication policy | PAM, authselect, faillock, SSSD | Yes | Yes | Authentication/access control |
| Login/session records | lastlog, faillock, utmp, wtmp, btmp | Yes | RHEL-09-654250 / 654255 | Authentication monitoring |
| MAC policy | SELinux configuration and policy | Yes | Yes | System/security-control integrity |
| DAC changes | chmod/chown/xattr, ACL utilities | Yes | Yes | Access-control changes |
| Unauthorized access | EACCES/EPERM open/create/truncate failures | Yes | Yes | Security event monitoring |
| Privileged execution | SUID/SGID, sudo, su, euid=0 execution | Yes | RHEL-09-654010 / 654145 / 654150 | Privileged-access accountability |
| File deletion | unlink/rmdir/rename family | Yes | Yes | Destructive/anti-forensic activity |
| Mount activity | mount/umount, mount syscall | Yes | RHEL-09-654180 | Removable media/data transfer |
| Kernel modules | module syscalls and tools | Yes | Yes | System integrity |
| Scheduled persistence | cron, at, systemd | Common | RHEL-09-654097 | Administrative/persistence monitoring |
| Logging configuration | auditd, rsyslog, journald, Splunk UF | Best practice | Strongly relevant | Event logging and monitoring |
| Firewall/network changes | firewalld/nftables/network config | Hardening relevant | Relevant | Network security configuration |
| Cryptographic policy | crypto-policies, FIPS settings | Hardening relevant | Relevant | Cryptographic/security configuration |
| Platform identity | SSSD, IPA/IdM, Kerberos | Environment-specific | Environment-specific | Identity/security monitoring |
| Container administration | Podman/Docker/runtime/Kubernetes config | Environment-specific | Environment-specific | Platform security monitoring |

---


# Related CIS RHEL 9 v2.0.0 Audit Requirements

## CIS 6.3.1 — auditd Installed and Enabled

This is not an audit rule, but it is a prerequisite for the rule catalogue. Confirm the audit package/service is installed, enabled and operational according to the applicable RHEL 9 benchmark profile.

## CIS 6.3.2 — Audit Data Retention and Failure Behaviour

Review `/etc/audit/auditd.conf` settings including, as applicable:

```text
max_log_file
max_log_file_action
space_left
space_left_action
admin_space_left
admin_space_left_action
disk_full_action
disk_error_action
```

The required values are benchmark/profile-specific and should be validated against the authoritative CIS RHEL 9 v2.0.0 document.

## Boot-Time Auditing

Ensure kernel auditing begins early enough to capture processes that start before the `auditd` userspace service:

```text
audit=1
audit_backlog_limit=<sufficient tested value>
```

The backlog value must be sized for the workload and benchmark requirement.



# SCAP / ComplianceAsCode Integration

SCAP can be used to evaluate and generate remediation content for RHEL 9. It is an **implementation and assessment mechanism**, not a replacement for the authoritative CIS, DISA STIG, or ACSC ISM publications.

## Install

```bash
dnf install -y openscap-scanner scap-security-guide
```

Typical RHEL 9 datastream location:

```text
/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

Confirm the actual path and available profiles on the target host:

```bash
oscap info /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

## Profile discovery

Do **not** assume a profile identifier exists because it appears in another SSG release or online guide. Enumerate the installed content first:

```bash
oscap info /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

Common profile families may include CIS and STIG profiles. If an ACSC/ISM-oriented profile such as an `ism_o` profile is present in the installed ComplianceAsCode content, treat it as a **ComplianceAsCode mapping to ISM outcomes**, not as the ACSC ISM itself.

Candidate profile IDs seen in ComplianceAsCode ecosystems include forms such as:

```text
xccdf_org.ssgproject.content_profile_cis
xccdf_org.ssgproject.content_profile_cis_server_l1
xccdf_org.ssgproject.content_profile_cis_server_l2
xccdf_org.ssgproject.content_profile_stig
xccdf_org.ssgproject.content_profile_ism_o
```

**Validate every profile ID using `oscap info` before use.**

## Evaluate

STIG example, only if the profile exists:

```bash
oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_stig \
  --results results-stig.xml \
  --report report-stig.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

CIS Level 2 example, only if present:

```bash
oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis_server_l2 \
  --results results-cis.xml \
  --report report-cis.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

ISM-oriented ComplianceAsCode profile example, **only if `oscap info` confirms the profile exists**:

```bash
oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_ism_o \
  --results results-ism-profile.xml \
  --report report-ism-profile.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

The resulting report demonstrates evaluation against that SSG profile version; it does not by itself prove whole-of-system ACSC ISM compliance.

## Generate remediation

Example:

```bash
oscap xccdf generate fix \
  --profile xccdf_org.ssgproject.content_profile_stig \
  --fix ansible \
  results-stig.xml > stig-remediation.yml
```

Review generated remediation before deployment. Generated fixes can alter authentication, audit, boot, crypto, filesystem, and service configuration.

## Inspect installed sample audit rules

```bash
ls -l /usr/share/audit/sample-rules/
```

Typical sample files may include:

```text
10-base-config.rules
30-stig.rules
31-privileged.rules
99-finalize.rules
```

Presence and content are package-version dependent.

## SCAP evidence to retain

For accreditation or assurance evidence, retain:

- datastream filename and package version
- profile ID and profile title
- evaluation timestamp
- XCCDF results XML
- HTML report
- generated remediation, if used
- tailoring file, if used
- exceptions/waivers
- benchmark/STIG/ISM release used for authoritative governance
- mapping record showing which SCAP rule satisfies which authoritative control


# Validation and Operational Commands

Load rules:

```bash
augenrules --load
```

List active rules:

```bash
auditctl -l
```

Check audit status:

```bash
auditctl -s
```

Search by audit key:

```bash
ausearch -k time_change
ausearch -k time-change
ausearch -k identity
ausearch -k privileged_exec
ausearch -k priv_cmd
ausearch -k access
ausearch -k perm_mod
```

Generate summary reports:

```bash
aureport --summary
aureport --auth
aureport --login
```

Check configured UID minimum:

```bash
awk '/^\s*UID_MIN/{print $2}' /etc/login.defs
```

Discover privileged executables for rule generation:

```bash
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -print
```

---

# Production Design Guidance

- Use **stable audit keys** as a taxonomy. They become valuable fields in Splunk for routing, dashboards, detection and health checking.
- Separate **compliance-minimum rules** from **threat-detection enhancement rules** so operators understand why each rule exists.
- Treat broad `execve`, read-access and whole-directory watches as high-volume controls that require performance and ingestion-volume testing.
- Monitor for **rule coverage failures** as well as successful audit events: missing expected audit keys can itself be a security/operational signal.
- Build SUID/SGID rules dynamically from the actual host rather than maintaining a universal hard-coded list.
- Validate 32-bit syscall rules only where the architecture/kernel supports them and the system can execute 32-bit code.
- Keep `-e 2` in a dedicated finalisation rule and deploy it only after the preceding rules are verified.
- Validate exact compliance mappings against the **specific CIS Benchmark version**, **specific DISA STIG release**, and **current ACSC ISM** used by the accreditation boundary.

---



> **STIG-source note:** The supplied STIG rules align with the upstream `linux-audit` sample `30-stig.rules` / `31-privileged.rules` pattern and common RHEL 9 STIG checks. The authoritative DISA STIG release and its rule IDs remain the compliance source of truth.


> **Authoritative-source note:** The official CIS Benchmark document is authoritative. These rules reflect the standard remediation forms commonly seen in CIS material and implementations such as ansible-lockdown/RHEL9-CIS, OpenSCAP CIS profiles and Tenable CIS audits. Always validate against the exact benchmark release and test in non-production before deployment.



# Recommended Rule-Level Compliance Metadata

For a machine-readable catalogue, store compliance mappings separately from the rule text:

```text
Rule ID
Title
Description
Auditd Rule
Audit Key
Category
Subcategory
Priority
Canonical Framework Form
CIS RHEL 9 Version
CIS Control IDs            # one or more references
CIS Mapping Types           # Exact / Objective / Extension / None
DISA STIG Release
DISA STIG IDs               # one or more references
STIG Mapping Types          # Exact / Sample-rule / Objective / Extension / None
ACSC ISM Release
ACSC ISM Control IDs        # zero, one, or many; only when verified
ACSC ISM Security Outcomes  # one or more outcome mappings
ISM Mapping Types           # Exact-control / Outcome / Extension / None
SCAP Content Package Version
SCAP Profile IDs            # one or more profiles
SCAP XCCDF Rule IDs         # one or more rules
SCAP Mapping Types          # Direct / Inherited / Tailored / None
Threat Detection Enhancement
RHEL 8
RHEL 9
Server
Workstation
Potential Volume
Performance Impact
Validation Command
Evidence
Exception / Tailoring
Notes
```

This prevents a single ambiguous `CIS/STIG/ISM = Yes` field from overstating compliance.

Where multiple controls from the same framework apply, store them as a list rather than collapsing them to one value. For example:

```text
CIS Control IDs:
- 6.3.3.1
- 6.3.3.3

DISA STIG IDs:
- RHEL-09-654150
- RHEL-09-654215

ACSC ISM Security Outcomes:
- privileged administrative activity
- access-control modification
- event logging and monitoring
```


# Reference Sources

Use the current official publications appropriate to the target operating system and accreditation boundary:

- **Australian Cyber Security Centre (ACSC) Information Security Manual (ISM)** — cyber.gov.au
- **CIS Benchmarks** — Center for Internet Security
- **DISA Security Technical Implementation Guides (STIGs)** — DoD Cyber Exchange; validate against the current RHEL 9 STIG release (for example V2R9 if that is the approved baseline in your environment)
- **OpenSCAP / ComplianceAsCode Security Content** — distribution-specific machine-readable and remediation content
- **Red Hat Security Hardening documentation** — RHEL release-specific audit and compliance guidance

---

*Consolidated from the supplied CIS RHEL 9 v2.0.0, DISA RHEL 9 STIG, ACSC/ISM-aligned, and SCAP/ComplianceAsCode auditd material. Exact compliance references are distinguished from framework-objective and implementation-profile mappings.*
