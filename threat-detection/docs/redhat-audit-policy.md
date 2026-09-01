# Required RHEL Audit Policy

This document consolidates the Linux Audit Framework (`auditd`) rules that
the Red Hat threat detection catalogue (`data/redhat-detections.json`)
depends on into a single deployable ruleset, organized by security
category. It is a companion to
[`redhat-detection-library.md`](redhat-detection-library.md), not a
replacement for it — the detections themselves remain the source of truth
for *why* each rule exists.

Every rule below is either:

- **Detection-tied** — extracted directly from the `audit_rules` field of
  one or more cataloged detections. The detection ID(s) that depend on it
  are listed so you can trace "why is this rule here" back to a specific
  SPL search.
- **Foundational** — a broad, non-path-specific rule that many detections
  assume is already in place (most commonly full command-line `EXECVE`
  auditing) but that isn't itself tied to a single detection's
  `audit_rules` array.
- **Supplemental** — a recommended hardening rule added here to close a
  category the master specification requires coverage for
  (*Network*, *Package management*) where no cataloged detection currently
  produces a matching `audit_rules` entry. These are clearly marked and
  should be treated as recommended, not as "required by detection X."

Rule ordering within `/etc/audit/rules.d/` matters: watches should be
loaded before the immutable flag (`-e 2`), and more specific `-a` syscall
rules should generally precede broader ones. The file below is ordered to
be deployable roughly top-to-bottom as a single `.rules` file.

> **Deployment note:** these rules assume RHEL 8/9 with `auditd` and the
> `audit-rules` service (`augenrules`). Drop this content into
> `/etc/audit/rules.d/threat-detection-library.rules` and run
> `augenrules --load`, or append it to `/etc/audit/audit.rules` directly
> if you are not using `augenrules`. Test in `-e 1` (non-immutable) mode
> before switching to `-e 2`, since immutable mode requires a reboot to
> change rules afterward.

---

## Foundational: command-line (EXECVE) auditing

20 detections in this catalogue (for example RHEL-025 auditd-service
monitoring, RHEL-051 firewalld-disable detection, RHEL-056 base64-decode-
to-shell, and the RH-X-004/RH-X-010 cross-platform correlations) depend on
full command-line visibility for arbitrary process execution rather than a
watch on one specific binary path. That visibility comes from a single
broad `EXECVE` rule, not from a per-detection `-w`/`-a -F path=` entry, so
it is called out here once instead of being duplicated 20 times below.

```
## Full command-line auditing for all non-system users. auid>=1000 excludes
## service/system accounts; auid!=unset (4294967295) excludes processes that
## never had a login uid assigned (kernel threads, some daemons).
-a always,exit -F arch=b64 -F euid=0 -S execve -k rootcmd
-a always,exit -F arch=b64 -F auid>=1000 -F auid!=4294967295 -S execve -k user_exec
-a always,exit -F arch=b32 -F euid=0 -S execve -k rootcmd
-a always,exit -F arch=b32 -F auid>=1000 -F auid!=4294967295 -S execve -k user_exec
```

**Without this rule**, `EXECVE` records (which carry the full argv the
Splunk searches in this catalogue parse — `a0`, `a1`, `a2`, ... fields)
will not exist for arbitrary commands, and any detection marked
`"requires_auditd": true` without a specific `audit_rules` entry will not
fire. Detections depending on this rule: RHEL-019, RHEL-025, RHEL-028,
RHEL-030, RHEL-034, RHEL-039, RHEL-041, RHEL-042, RHEL-051, RHEL-053,
RHEL-054, RHEL-055, RHEL-056, RHEL-057, RHEL-058, RHEL-066, RHEL-067,
RHEL-068, RH-X-004, RH-X-010.

---

## Identity

Watches on the accounts/groups themselves and the binaries that change
them.

```
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/useradd -k identity
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/usermod -k identity
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/chage -k identity
```

| Rule target | Detection(s) |
|---|---|
| `/etc/passwd` (wa), `useradd`, `usermod` | RHEL-014 |
| `/etc/group`, `/etc/gshadow` (wa) | RHEL-015 |
| `chage` | RHEL-016 |

## Authentication

PAM stack, SSH daemon config/host keys, and Kerberos client config —
anything that governs *how* a principal proves who they are.

```
-w /etc/pam.d/ -p wa -k pam_config
-w /etc/pam.conf -p wa -k pam_config
-w /etc/security/ -p wa -k pam_config
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config
-w /etc/ssh/ssh_host_rsa_key -p wa -k ssh_hostkey
-w /etc/ssh/ssh_host_ecdsa_key -p wa -k ssh_hostkey
-w /etc/ssh/ssh_host_ed25519_key -p wa -k ssh_hostkey
-w /etc/krb5.conf -p wa -k krb5_config
-w /etc/krb5.conf.d/ -p wa -k krb5_config
```

| Rule target | Detection(s) |
|---|---|
| `/etc/pam.d/`, `/etc/pam.conf`, `/etc/security/` | RHEL-007 |
| `/etc/ssh/sshd_config`, `sshd_config.d/` | RHEL-018 |
| SSH host key files | RHEL-020 |
| `/etc/krb5.conf`, `krb5.conf.d/` | IPA-017 |

## Privilege

setuid/setgid bit changes, filesystem capability grants, and Polkit's
`pkexec` — the primitives behind local privilege escalation.

```
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F a1&04000 -k setuid_change
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F a1&02000 -k setuid_change
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/setcap -k capabilities
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/pkexec -k privileged_exec
```

| Rule target | Detection(s) |
|---|---|
| `chmod`/`fchmod`/`fchmodat` with setuid (04000) or setgid (02000) bit | RHEL-021 |
| `setcap` | RHEL-022 |
| `pkexec` | RHEL-023 |

## Persistence

Cron/at job files, shell profile/init scripts, systemd unit directories,
SSH authorized-keys locations, and the dynamic-linker preload file —
the standard Linux persistence surface.

```
-w /etc/crontab -p wa -k cron_persistence
-w /etc/cron.d/ -p wa -k cron_persistence
-w /var/spool/cron/ -p wa -k cron_persistence
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/at -k at_persistence
-w /var/spool/at/ -p wa -k at_persistence
-w /etc/profile -p wa -k init_scripts
-w /etc/profile.d/ -p wa -k init_scripts
-w /etc/rc.d/rc.local -p wa -k init_scripts
-w /etc/systemd/system/ -p wa -k systemd_persistence
-w /usr/lib/systemd/system/ -p wa -k systemd_persistence
-w /root/.ssh -p wa -k ssh_persistence
-w /home -p wa -k ssh_persistence
-w /etc/ld.so.preload -p wa -k rootkit_ld_preload
```

| Rule target | Detection(s) |
|---|---|
| `/etc/crontab`, `/etc/cron.d/`, `/var/spool/cron/` | RHEL-044 |
| `at`, `/var/spool/at/` | RHEL-045 |
| `/etc/profile`, `profile.d/`, `rc.local` | RHEL-046 |
| `/etc/systemd/system/` | RHEL-040, RHEL-043 |
| `/usr/lib/systemd/system/` | RHEL-040 |
| `~/.ssh` (write) | RHEL-017 |
| `/etc/ld.so.preload` | RHEL-063 |

## Audit protection

Watches on the audit trail itself, plus the immutable-ruleset flag —
tampering here is a prerequisite for making almost any other attack
invisible.

```
-w /var/log/audit/ -p wa -k audit_log_protection
## Load this line LAST, after every other rule in this file:
-e 2
```

| Rule target | Detection(s) |
|---|---|
| `/var/log/audit/` | RHEL-027, RHEL-029 |
| Immutable flag (`-e 2`) | RHEL-026 (auditd stop/disable/fail detection is the compensating control when this flag is bypassed by stopping the *service* rather than editing rules) |

## Security controls

SELinux enforcement/policy state and `fapolicyd` trust configuration —
the platform controls that constrain what a compromised process can
actually do even after code execution.

```
-w /etc/selinux/config -p wa -k selinux_config
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/setenforce -k selinux_config
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/semodule -k selinux_policy
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/setsebool -k selinux_policy
-w /etc/fapolicyd/ -p wa -k fapolicyd_trust
```

| Rule target | Detection(s) |
|---|---|
| `/etc/selinux/config`, `setenforce` | RHEL-031 |
| `semodule` | RHEL-032 |
| `setsebool` | RHEL-033 |
| `/etc/fapolicyd/` | RHEL-036 |

## Kernel

Kernel module load/unload, eBPF program loading, sysctl runtime
parameters, and `memfd_create` (in-memory/fileless execution) — the
syscalls that touch kernel state directly or execute code without ever
writing a file to disk.

```
-a always,exit -F arch=b64 -S init_module,finit_module -k kernel_module_load
-a always,exit -F arch=b64 -S delete_module -k kernel_module_unload
-a always,exit -F arch=b64 -S bpf -k ebpf_activity
-w /etc/sysctl.conf -p wa -k sysctl_config
-w /etc/sysctl.d/ -p wa -k sysctl_config
-a always,exit -F arch=b64 -S memfd_create -k fileless_exec
```

| Rule target | Detection(s) |
|---|---|
| `init_module`/`finit_module`, `delete_module` | RHEL-047 |
| `bpf` syscall | RHEL-050 |
| `/etc/sysctl.conf`, `sysctl.d/` | RHEL-049 |
| `memfd_create` | RHEL-065 |

## Network

**No cataloged detection currently emits an `audit_rules` entry in this
category** — RHEL-051 (firewalld disabled) detects the change via the
foundational `EXECVE` rule above rather than a file watch, since
`systemctl stop firewalld` doesn't touch a config file. The rules below
are **supplemental hardening recommendations**, not requirements of any
specific detection in this catalogue today; add them if you want file-
integrity coverage of network configuration alongside the existing
command-based firewalld detection.

```
## SUPPLEMENTAL — not tied to a cataloged detection.
-w /etc/sysconfig/network-scripts/ -p wa -k network_config
-w /etc/NetworkManager/ -p wa -k network_config
-w /etc/firewalld/ -p wa -k network_config
-w /etc/hosts -p wa -k network_config
-w /etc/resolv.conf -p wa -k network_config
```

## Package management

**No cataloged detection currently emits an `audit_rules` entry in this
category.** Package-management abuse in this catalogue (malicious RPM
install, repo tampering) is expected to be detected primarily through
Satellite/Katello content-view and activation-key auditing (see SAT-###
detections) rather than host-level auditd, so host-side package rules are
**supplemental** here to close the category for hosts not fully managed
by Satellite.

```
## SUPPLEMENTAL — not tied to a cataloged detection.
-w /etc/dnf/ -p wa -k package_management
-w /etc/yum.repos.d/ -p wa -k package_management
-w /etc/yum.conf -p wa -k package_management
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/rpm -k package_management
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/dnf -k package_management
```

## Credentials

Read-access watches on credential material: shadow files, Kerberos
keytabs and credential caches, SSH private keys, and shell history (a
common place plaintext credentials leak into via `mysql -p<pw>`-style
invocations).

```
-w /etc/shadow -p r -k shadow_access
-w /etc/gshadow -p r -k shadow_access
-w /etc/krb5.keytab -p r -k keytab_access
-a always,exit -F arch=b64 -S open,openat -F key=ccache_access -k ccache_access
-w /root/.ssh -p r -k ssh_key_access
-w /home -p r -k ssh_key_access
-w /home -p r -k bash_history_access
```

| Rule target | Detection(s) |
|---|---|
| `/etc/shadow`, `/etc/gshadow` (read) | RHEL-059 |
| `/etc/krb5.keytab` (read) | RHEL-062 |
| Kerberos ccache open/read | IPA-015 |
| `~/.ssh` (read) | RHEL-061 |
| `/home` (read, bash history) | RHEL-060 |

> Note: watching `/etc/shadow`/`/etc/gshadow`/keytabs/`.ssh` for **read**
> access is high-volume by design (`sshd`, `sssd`, and other legitimate
> daemons read these routinely). See `redhat-audit-policy.md`'s companion
> detections (RHEL-059, RHEL-061, RHEL-062, IPA-015) for the process-
> allowlisting logic that turns this raw telemetry into a usable, low-
> noise alert — do not alert directly on the raw audit key.

## Destructive activity

Data-destruction utilities (`shred`, `wipefs`) and LVM volume removal
(`lvremove`) — the tools an attacker uses in the final stage of an
intrusion to destroy evidence or force a ransom/downtime outcome.

```
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/shred -k destructive_activity
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/wipefs -k destructive_activity
-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/lvremove -k destructive_activity
```

| Rule target | Detection(s) |
|---|---|
| `shred`, `wipefs` | RHEL-069 |
| `lvremove` | RHEL-070 |

---

## Gap analysis summary

| Category | Detection-tied rules | Supplemental rules | Notes |
|---|---:|---:|---|
| Identity | 6 | 0 | |
| Authentication | 10 | 0 | |
| Privilege | 4 | 0 | |
| Persistence | 13 | 0 | |
| Audit protection | 2 | 0 | plus the foundational `-e 2` immutable flag |
| Security controls | 5 | 0 | |
| Kernel | 6 | 0 | |
| Network | 0 | 5 | no cataloged detection currently ties to a network audit_rules entry — firewalld disable (RHEL-051) uses the foundational EXECVE rule instead |
| Package management | 0 | 5 | RPM/DNF abuse detection is primarily Satellite/Katello-side (SAT-### catalogue), not host auditd |
| Credentials | 7 | 0 | |
| Destructive activity | 3 | 0 | |
| **Foundational (EXECVE)** | **1 rule, 20 detections** | — | not path-specific, so not counted per-category above |

**56** unique detection-tied `audit_rules` strings across the catalogue,
**0** left uncategorized, **10** supplemental rules added to close the two
categories (*Network*, *Package management*) the specification requires
coverage for but that no individual detection's telemetry depends on
today. All are deduplicated — no rule string appears in more than one
category, and where the same path is watched for two different purposes
(e.g. `/etc/gshadow` for both integrity `-p wa` under *Identity* and
confidentiality `-p r` under *Credentials*, or `/etc/shadow`/`/etc/passwd`
appearing once each despite backing multiple RHEL-0## detections) each
distinct `(path, permission, key)` tuple is listed exactly once, with all
of its dependent detection IDs shown.
