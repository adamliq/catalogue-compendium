# How to Configure Auditing to Collect Each Event

This is a human-readable version of `data/reference/audit_configuration.csv` /
`data/reference/audit_configuration.json`. Each section is one subcategory in
this catalogue — the config file/command to use, the steps, and the event
IDs it causes to be logged.

For a much larger set of ready-to-deploy `auditctl`/`auditd.rules.d` rules
beyond this catalogue's own 45 subcategories — including CIS RHEL 9
Benchmark and DISA STIG identifiers alongside ACSC ISM outcome alignment —
see `docs/auditd-rules-master-reference.md`.

Most `audit/*` events need nothing beyond the audit subsystem being active
(`systemctl enable --now auditd`, or the kernel's built-in audit support if
you're not running the userspace daemon at all — check with
`auditctl -s`). Where a specific `auditctl` rule is required, it's called
out explicitly below and should go in a file under `/etc/audit/rules.d/`
followed by `augenrules --load` (or directly with `auditctl -a ...` for a
rule that doesn't need to survive a reboot).

Several of these subcategories also satisfy an ACSC Information Security
Manual (ISM) OFFICIAL control from the `xccdf_org.ssgproject.content_profile_ism_o`
SCAP profile — see the `acsc_ism_control` field on the corresponding events
in `data/events.csv`/`.json` and the full control text in
`data/reference/acsc_ism_controls.csv`/`.json`. Configuring auditd per this
guide is necessary but not sufficient for that profile — the profile's
actual SCAP rules also require the audit subsystem itself to be present
and enabled (`package_audit_installed`, `service_auditd_enabled`) and, for
control 0582 specifically, a documented retention/rotation configuration
(`auditd_data_retention_flush` et al. in `/etc/audit/auditd.conf`) beyond
what's covered here.

## Credential Validation
- **Config:** `/etc/audit/rules.d/audit.rules`
- **Steps:** Auditd ships with pam_unix/pam_faillock already wired to the
  audit subsystem on most distros. To be explicit: `-w /etc/pam.d/ -p wa -k
  pam_config`, then reload with `augenrules --load`.
- **Events:** 1100, 1101, 1109
- **Reference:** https://man7.org/linux/man-pages/man8/auditd.8.html

## Credential Lifecycle
- **Config:** PAM stack (`/etc/pam.d/*`)
- **Steps:** No extra config needed — CRED_ACQ/CRED_DISP/CRED_REFR are
  emitted automatically by `pam_unix.so` whenever a PAM-aware service
  authenticates a user, as long as the audit subsystem is running (auditd
  active, or `/proc/sys/kernel/audit_enabled=1`).
- **Events:** 1103, 1104, 1110

## Logon
- **Config:** PAM session hooks (login, sshd, su)
- **Steps:** Automatic once auditd is running: every PAM service that calls
  `pam_open_session()` (login, sshd, su, `sudo -i`, cron with PAM)
  generates USER_START; direct getty logins additionally generate
  USER_LOGIN via `login(1)`.
- **Events:** 1105, 1112

## Logoff
- **Config:** PAM session hooks
- **Steps:** Automatic — `pam_close_session()` generates USER_END;
  `login(1)`-managed sessions additionally generate USER_LOGOUT on exit.
- **Events:** 1106, 1113

## TTY Tracking
- **Config:** `/etc/audit/rules.d/audit.rules`
- **Steps:** Enabled by default for sudo (pam_unix records the controlling
  TTY on every PAM session); no rule needed to see USER_TTY records for
  sudo sessions specifically.
- **Events:** 1124

## Command Execution
- **Config:** `/etc/sudoers` (`Defaults log_input,log_output` or just
  default sudo logging) + auditd running
- **Steps:** sudo always emits a USER_CMD record via its PAM integration
  when auditd is active — no `/etc/sudoers` change required for the audit
  record itself; add `Defaults logfile=/var/log/sudo.log` for a parallel
  plaintext trail.
- **Events:** 1123
- **Reference:** https://man7.org/linux/man-pages/man5/sudoers.5.html

## Capability Use
- **Config:** `/etc/audit/rules.d/audit.rules`
- **Steps:** `auditctl -a always,exit -F arch=b64 -S capset -k cap_change`
  (add `-F a0=<uid>` to scope to a specific process if needed), then
  `augenrules --load`.
- **Events:** 1322

## User Account
- **Config:** `/etc/audit/rules.d/audit.rules`
- **Steps:** `auditctl -w /etc/passwd -p wa -k identity && auditctl -w
  /etc/shadow -p wa -k identity` — watching the account databases catches
  useradd/userdel/usermod regardless of which tool made the change.
- **Events:** 1114, 1115, 1125
- **Reference:** https://linux-audit.com/

## Group Management
- **Config:** `/etc/audit/rules.d/audit.rules`
- **Steps:** `auditctl -w /etc/group -p wa -k identity && auditctl -w
  /etc/gshadow -p wa -k identity`.
- **Events:** 1116, 1117, 1132

## Process Execution
- **Config:** `/etc/audit/rules.d/audit.rules`
- **Steps:** `auditctl -a always,exit -F arch=b64 -S execve -k exec`
  (repeat with `arch=b32` on mixed 32/64-bit systems); each matching
  execve produces a linked SYSCALL+EXECVE+CWD+PROCTITLE+EOE record group.
- **Events:** 1300, 1320
- **Reference:** https://linux-audit.com/audit-log-file-locations-and-how-to-configure-rules/

## Process Arguments / Process Command Line
- **Config:** same rule as Process Execution
- **Steps:** Automatically produced alongside SYSCALL whenever an execve
  rule matches — no separate rule needed. PROCTITLE captures
  `/proc/pid/cmdline` at exec time.
- **Events:** 1309, 1327

## File Access (Watch)
- **Config:** `/etc/audit/rules.d/audit.rules`
- **Steps:** `auditctl -w /etc/shadow -p r -k sensitive_read` (repeat per
  sensitive path — `/etc/sudoers`, SSH host keys, TLS private keys, etc.);
  `p` can be any combination of `r`/`w`/`x`/`a`.
- **Events:** 1302
- **Reference:** https://man7.org/linux/man-pages/man8/auditctl.8.html

## Audit Configuration
- **Config:** `/etc/audit/rules.d/audit.rules` + `auditctl`
- **Steps:** Watch the rules themselves so tampering is visible: `auditctl
  -w /etc/audit/ -p wa -k audit_config`. The `-e` flag itself (enable/
  disable auditing) is always logged as CONFIG_CHANGE regardless of
  rules, as long as the kernel audit subsystem is compiled in.
- **Events:** 1305

## Kernel Module
- **Config:** `/etc/audit/rules.d/audit.rules`
- **Steps:** `auditctl -a always,exit -F arch=b64 -S
  init_module,finit_module,delete_module -k module_load`.
- **Events:** 1330

## Boot/Shutdown
- **Config:** PAM/init (automatic)
- **Steps:** SYSTEM_BOOT/SYSTEM_SHUTDOWN are emitted automatically by the
  init system (systemd or sysvinit) via the audit netlink socket whenever
  auditd is running at boot.
- **Events:** 1127, 1128

## Audit Daemon
- **Config:** `systemctl status auditd` (automatic)
- **Steps:** DAEMON_START/DAEMON_END/DAEMON_ABORT/DAEMON_CONFIG are
  self-reported by auditd — no configuration needed, but forward them
  off-box (e.g. `audisp-remote`) so a local DAEMON_END from a compromised
  host can't just be deleted along with the rest of the log.
- **Events:** 1200, 1201, 1202, 1203
- **Reference:** https://man7.org/linux/man-pages/man8/auditd.8.html

## SELinux AVC
- **Config:** SELinux enforcing or permissive mode (automatic)
- **Steps:** AVC denials are logged automatically by the kernel whenever
  SELinux is loaded (`getenforce` != Disabled) and auditd is running; use
  `audit2allow -w -a` to translate a denial into the rule that would have
  allowed it.
- **Events:** 1400
- **Reference:** https://man7.org/linux/man-pages/man8/audit2allow.8.html

## AppArmor AVC
- **Config:** AppArmor profile in enforce or complain mode (automatic)
- **Steps:** AppArmor DENIED/ALLOWED messages are logged automatically via
  the kernel audit subsystem once a profile is loaded (`aa-status`) — no
  separate audit rule required; use `aa-logprof` to interactively update a
  profile from logged denials. Note this shares the same `AVC` (1400)
  message type as SELinux — see this catalogue's README for why.
- **Events:** 1400
- **Reference:** https://gitlab.com/apparmor/apparmor/-/wikis/Logging

## MAC Policy
- **Config:** SELinux (automatic)
- **Steps:** MAC_POLICY_LOAD fires whenever `semodule` loads/reloads
  policy; MAC_STATUS fires on `setenforce 0`/`1` or the `enforce=` boot
  parameter — both automatic once SELinux is active.
- **Events:** 1403, 1404

## Netfilter Configuration
- **Config:** `/etc/audit/rules.d/audit.rules`
- **Steps:** NETFILTER_CFG is emitted automatically by the kernel whenever
  nft/iptables replaces a table, as long as auditd is running — no rule
  needed.
- **Events:** 1325

## Netfilter Packet Log
- **Config:** nft/iptables rule with the audit target
- **Steps:** `nft add rule inet filter input ... log group 0` (with the
  kernel's `nf_log_type=nfnetlink` and auditd's audisp plugin), or the
  simpler `iptables -A INPUT ... -j AUDIT --type accept|drop`. Plain `-j
  LOG` writes to the kernel ring buffer (dmesg) instead of the audit
  trail.
- **Events:** 1324
- **Reference:** https://man7.org/linux/man-pages/man8/iptables-extensions.8.html

## SSH Session Disconnect
- **Config:** sshd (automatic)
- **Steps:** No configuration needed — every SSH disconnect logs the
  numeric reason code from RFC 4253 to the sshd syslog line (facility
  `auth`, via `/etc/ssh/sshd_config`'s `SyslogFacility`/`LogLevel`,
  default `AUTH`/`INFO`).
- **Events:** 2, 10, 11, 14
- **Reference:** https://man.openbsd.org/sshd_config

## Unit Lifecycle
- **Config:** systemd (automatic)
- **Steps:** Emitted automatically by systemd (PID 1) to the journal for
  every unit start/stop job; increase verbosity with `systemctl log-level
  debug` if a job's begun/finished pair isn't showing up.
- **Events:** the `7d4958e8…`, `39f53479…`, `de5b426a…`, `9d1aaa27…`
  systemd catalog UUIDs
- **Reference:** https://www.freedesktop.org/software/systemd/man/latest/systemd.journal-fields.html

## Unit Failure
- **Config:** systemd (automatic) + `OnFailure=` for alerting
- **Steps:** Automatic on any failed start job; to get proactive alerts
  rather than just a log line, add `OnFailure=failure-notify@%n.service`
  to the unit and write a small notify service, or poll `systemctl
  --failed`.
- **Events:** the `be02cf68…`, `d9b373ed…` systemd catalog UUIDs

## Resource Protection
- **Config:** systemd-oomd / kernel OOM killer (automatic)
- **Steps:** Automatic whenever a process is killed for memory pressure,
  whether by the classic in-kernel OOM killer or systemd-oomd (enable/
  tune via `/etc/systemd/oomd.conf`); systemd correlates the kill back to
  the owning unit.
- **Events:** the `fe6faa94…` systemd catalog UUID
- **Reference:** https://www.freedesktop.org/software/systemd/man/latest/systemd-oomd.service.html

## Session Management
- **Config:** systemd-logind (automatic)
- **Steps:** Automatic for every login session once systemd-logind is
  running (default on all systemd distros); session class/type detail is
  visible with `loginctl show-session`.
- **Events:** the `8d45620c…`, `33549394…` systemd catalog UUIDs

## Time Change
- **Config:** systemd-timesyncd / timedatectl (automatic)
- **Steps:** Automatic whenever the wall clock steps, whether via
  `date`/`timedatectl set-time`, NTP step correction, or `adjtimex()`; no
  configuration needed to log it, but pair with an audit watch on
  `/etc/adjtime` and `/etc/localtime` for the configuration side.
- **Events:** the `c7a78707…` systemd catalog UUID

## Journal
- **Config:** systemd-journald (automatic)
- **Steps:** Journal start/stop is self-reported by systemd-journald;
  rate-limit suppression is controlled by `RateLimitIntervalSec=`/
  `RateLimitBurst=` in `/etc/systemd/journald.conf` — raise or disable it
  (set to 0) on hosts where every audit-relevant line must survive a
  burst.
- **Events:** the `f77379a8…`, `d93fb3c9…`, `a596d6fe…` systemd catalog
  UUIDs
- **Reference:** https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html

---

The following subcategories were added from
`docs/auditd-rules-master-reference.md`; each event's `reference` field
cites the exact source `auditd_rules.csv` row(s).

## File Deletion
- **Config:** `/etc/audit/rules.d/audit.rules`
- **Steps:** `auditctl -a always,exit -F arch=b64 -S rmdir,unlink,unlinkat,rename,renameat,renameat2 -F auid>=1000 -F auid!=unset -k file_delete` (repeat with `arch=b32`).
- **Events:** 1300

## DAC Permission Change
- **Config:** `/etc/audit/rules.d/audit.rules`
- **Steps:** `auditctl -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k permissions && auditctl -a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -k ownership` (repeat with `arch=b32`).
- **Events:** 1300

## Filesystem Mounts
- **Config:** `/etc/audit/rules.d/audit.rules`
- **Steps:** `auditctl -a always,exit -F arch=b64 -S mount,umount2 -F auid>=1000 -F auid!=unset -k mounts` (repeat with `arch=b32`, adding `umount`).
- **Events:** 1300

## Removable Media
- **Config:** `/etc/audit/rules.d/audit.rules`
- **Steps:** `auditctl -w /media/ -p wa -k removable_media && auditctl -w /run/media/ -p wa -k removable_media`. Use with care on workstations due to event volume.
- **Events:** 1302

## Extended Attributes
- **Config:** `/etc/audit/rules.d/audit.rules`
- **Steps:** `auditctl -a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k xattr` (repeat with `arch=b32`); optionally also `-w /usr/bin/chcon -p x -k permissions`.
- **Events:** 1300

## Scheduled Tasks
- **Config:** `/etc/audit/rules.d/audit.rules`
- **Steps:** `auditctl -w /etc/crontab -p wa -k scheduled_tasks && auditctl -w /etc/cron.d/ -p wa -k scheduled_tasks` (repeat for `cron.{hourly,daily,weekly,monthly}` and `/var/spool/cron/`).
- **Events:** 1302

## Dynamic Linker Manipulation
- **Config:** `/etc/audit/rules.d/audit.rules`
- **Steps:** `auditctl -w /etc/ld.so.preload -p wa -k library_injection && auditctl -w /etc/ld.so.conf -p wa -k library_config`.
- **Events:** 1302

## Package Management
- **Config:** `/etc/audit/rules.d/audit.rules`
- **Steps:** `auditctl -w /usr/bin/rpm -p x -k software_install && auditctl -w /usr/bin/dnf -p x -k software_install` (add `/usr/bin/yum` on older releases).
- **Events:** 1302

## DNS Configuration
- **Config:** `/etc/audit/rules.d/audit.rules`
- **Steps:** `auditctl -w /etc/resolv.conf -p wa -k dns_config && auditctl -w /etc/nsswitch.conf -p wa -k dns_config`.
- **Events:** 1302

## SSH Host Keys
- **Config:** `/etc/audit/rules.d/audit.rules`
- **Steps:** `auditctl -w /etc/ssh/ssh_host_rsa_key -p wa -k ssh_host_keys` (repeat for `ssh_host_ecdsa_key` and `ssh_host_ed25519_key`).
- **Events:** 1302

## PKI / Trusted Certificates
- **Config:** `/etc/audit/rules.d/audit.rules`
- **Steps:** `auditctl -w /etc/pki/ca-trust/ -p wa -k trusted_certificates && auditctl -w /etc/pki/ca-trust/source/anchors/ -p wa -k trusted_certificates`.
- **Events:** 1302

## Container Administration
- **Config:** `/etc/audit/rules.d/audit.rules`
- **Steps:** `auditctl -w /usr/bin/docker -p x -k container_admin && auditctl -w /etc/docker/ -p wa -k docker_config` (add `/usr/bin/podman` and `/etc/containers/` where Podman is used instead).
- **Events:** 1302

## Identity Provider Configuration
- **Config:** `/etc/audit/rules.d/audit.rules`
- **Steps:** `auditctl -w /etc/krb5.conf -p wa -k kerberos && auditctl -w /etc/sssd/sssd.conf -p wa -k identity_provider`.
- **Events:** 1302

## Process Injection
- **Config:** `/etc/audit/rules.d/audit.rules`
- **Steps:** `auditctl -a always,exit -F arch=b64 -S ptrace -k process_injection` (repeat with `arch=b32`). Expect high volume on developer workstations; scope with `-F auid>=1000` if needed.
- **Events:** 1300

## Namespace Manipulation
- **Config:** `/etc/audit/rules.d/audit.rules`
- **Steps:** `auditctl -a always,exit -F arch=b64 -S unshare,setns -F auid>=1000 -F auid!=unset -k namespace`.
- **Events:** 1300

## Anti-Forensics
- **Config:** `/etc/audit/rules.d/audit.rules`
- **Steps:** `auditctl -w /usr/bin/shred -p x -k anti_forensics && auditctl -w /usr/bin/truncate -p x -k anti_forensics`.
- **Events:** 1302
