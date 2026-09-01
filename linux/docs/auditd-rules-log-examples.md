# Auditd Rules Catalogue — Log Output Examples

**Source catalogue:** Consolidated Linux auditd Rule Catalogue  
(CIS RHEL 9 v2.0.0 · DISA STIG RHEL 9 · ACSC ISM · SCAP/ComplianceAsCode)

**Purpose:** Representative raw `/var/log/audit/audit.log` event examples for each major rule category.  
All records belonging to the same event share the same timestamp and serial number.

**How to view interpreted output:**
```bash
ausearch -k <key> -i
# or
ausearch -a <event-id> -i
```

---

## 1. Base / Audit Control Rules

### Failure mode / Immutable finalisation
These are control directives (`-f 2`, `-e 2`). They do not themselves generate continuous SYSCALL events; they change kernel behaviour. Configuration changes appear as:

```
type=CONFIG_CHANGE msg=audit(1712345678.123:100): auid=0 ses=1 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 op=add_rule key="time_change" list=4 res=1
type=CONFIG_CHANGE msg=audit(1712345678.456:101): auid=0 ses=1 op=set audit_enabled=1 old=1 auid=0 ses=1 res=1
```

### Audit daemon start
```
type=DAEMON_START msg=audit(1363713609.192:5426): auditd start, ver=2.2 format=raw kernel=2.6.32-358.2.1.el6.x86_64 auid=1000 pid=4979 subj=unconfined_u:system_r:auditd_t:s0 res=success
```

---

## 2. Audit Subsystem Protection

**Typical rules**
```text
-w /etc/audit/ -p wa -k audit_config
-w /etc/audit/rules.d/ -p wa -k audit_rules
-w /var/log/audit/ -p wa -k audit_logs
-w /sbin/auditctl -p x -k audit_tools
```

### Example — modification of audit rules
```
type=SYSCALL msg=audit(1712345700.100:2001): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7fffd0dd98f0 a2=241 a3=1b6 items=2 ppid=1200 pid=1305 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="vi" exe="/usr/bin/vi" key="audit_rules"
type=CWD msg=audit(1712345700.100:2001): cwd="/etc/audit/rules.d"
type=PATH msg=audit(1712345700.100:2001): item=0 name="/etc/audit/rules.d" inode=12345 dev=08:01 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT
type=PATH msg=audit(1712345700.100:2001): item=1 name="99-finalize.rules" inode=12350 dev=08:01 mode=0100640 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL
type=PROCTITLE msg=audit(1712345700.100:2001): proctitle=7669002F6574632F61756469742F72756C65732E642F39392D66696E616C697A652E72756C6573
```

### Example — execution of auditctl
```
type=SYSCALL msg=audit(1712345710.200:2002): arch=c000003e syscall=59 success=yes exit=0 a0=7f... a1=7f... a2=7f... a3=0 items=2 ppid=1200 pid=1310 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="auditctl" exe="/sbin/auditctl" key="audit_tools"
type=EXECVE msg=audit(1712345710.200:2002): argc=3 a0="auditctl" a1="-l"
type=CWD msg=audit(1712345710.200:2002): cwd="/root"
type=PATH msg=audit(1712345710.200:2002): item=0 name="/sbin/auditctl" inode=... mode=0100755 ouid=0 ogid=0 nametype=NORMAL
type=PROCTITLE msg=audit(1712345710.200:2002): proctitle=617564697463746C002D6C
```

---

## 3. System Identity

**Typical rules**
```text
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system_identity
-w /etc/hostname -p wa -k system_identity
-w /etc/hosts -p wa -k network_config
```

### Example — hostname change via syscall
```
type=SYSCALL msg=audit(1712345800.300:2100): arch=c000003e syscall=170 success=yes exit=0 a0=7ffc... a1=10 a2=0 a3=0 items=0 ppid=1500 pid=1520 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=4 comm="hostname" exe="/usr/bin/hostname" key="system_identity"
type=PROCTITLE msg=audit(1712345800.300:2100): proctitle=686F73746E616D65006E6577686F7374
```

### Example — /etc/hosts modification
```
type=SYSCALL msg=audit(1712345810.400:2101): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7fff... a2=241 a3=1b6 items=1 ppid=1500 pid=1525 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=4 comm="vi" exe="/usr/bin/vi" key="network_config"
type=CWD msg=audit(1712345810.400:2101): cwd="/etc"
type=PATH msg=audit(1712345810.400:2101): item=0 name="/etc/hosts" inode=... mode=0100644 ouid=0 ogid=0 nametype=NORMAL
type=PROCTITLE msg=audit(1712345810.400:2101): proctitle=7669002F6574632F686F737473
```

---

## 4. Date and Time

**Typical rules**
```text
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time_change
-w /etc/localtime -p wa -k time_change
```

### Example — clock_settime
```
type=SYSCALL msg=audit(1712345900.500:2200): arch=c000003e syscall=227 success=yes exit=0 a0=0 a1=7fff... a2=0 a3=0 items=0 ppid=1600 pid=1610 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=5 comm="date" exe="/usr/bin/date" key="time_change"
type=PROCTITLE msg=audit(1712345900.500:2200): proctitle=64617465002D7300323032342D30312D30312031323A30303A3030
```

### Example — /etc/localtime change
```
type=SYSCALL msg=audit(1712345910.600:2201): arch=c000003e syscall=82 success=yes exit=0 a0=7fff... a1=7fff... a2=0 a3=0 items=2 ppid=1600 pid=1615 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=5 comm="ln" exe="/usr/bin/ln" key="time_change"
type=CWD msg=audit(1712345910.600:2201): cwd="/etc"
type=PATH msg=audit(1712345910.600:2201): item=0 name="/etc/localtime" inode=... mode=0120777 ouid=0 ogid=0 nametype=DELETE
type=PATH msg=audit(1712345910.600:2201): item=1 name="/usr/share/zoneinfo/Australia/Sydney" inode=... mode=0100644 ouid=0 ogid=0 nametype=CREATE
```

---

## 5. User and Group Account Management (Identity)

**Typical rules**
```text
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
```

### Example — /etc/passwd modification (useradd)
```
type=SYSCALL msg=audit(1712346000.700:2300): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7fff... a2=241 a3=1b6 items=1 ppid=1700 pid=1720 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=6 comm="useradd" exe="/usr/sbin/useradd" key="identity"
type=CWD msg=audit(1712346000.700:2300): cwd="/root"
type=PATH msg=audit(1712346000.700:2300): item=0 name="/etc/passwd" inode=... mode=0100644 ouid=0 ogid=0 nametype=NORMAL
type=PROCTITLE msg=audit(1712346000.700:2300): proctitle=75736572616464006E657775736572
```

### Example — account-management binary execution
```
type=SYSCALL msg=audit(1712346010.800:2301): arch=c000003e syscall=59 success=yes exit=0 a0=... a1=... a2=... a3=0 items=2 ppid=1700 pid=1725 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=6 comm="useradd" exe="/usr/sbin/useradd" key="account_management"
type=EXECVE msg=audit(1712346010.800:2301): argc=2 a0="useradd" a1="newuser"
type=PATH msg=audit(1712346010.800:2301): item=0 name="/usr/sbin/useradd" inode=... mode=0100755 ouid=0 ogid=0 nametype=NORMAL
```

---

## 6. Authentication Configuration

**Typical rules**
```text
-w /etc/pam.d/ -p wa -k authentication
-w /etc/security/ -p wa -k authentication
-w /etc/login.defs -p wa -k authentication
```

### Example — PAM configuration change
```
type=SYSCALL msg=audit(1712346100.900:2400): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7fff... a2=241 a3=1b6 items=1 ppid=1800 pid=1810 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=7 comm="vi" exe="/usr/bin/vi" key="authentication"
type=CWD msg=audit(1712346100.900:2400): cwd="/etc/pam.d"
type=PATH msg=audit(1712346100.900:2400): item=0 name="/etc/pam.d/sshd" inode=... mode=0100644 ouid=0 ogid=0 nametype=NORMAL
```

---

## 7. SSH Security

**Typical rules**
```text
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/ssh/sshd_config.d/ -p wa -k ssh_config
-w /root/.ssh/ -p wa -k ssh_keys
```

### Example — sshd_config modification attempt (permission denied)
```
type=SYSCALL msg=audit(1364481363.243:24287): arch=c000003e syscall=2 success=no exit=-13 a0=7fffd19c5592 a1=0 a2=7fffd19c4b50 a3=a items=1 ppid=2686 pid=3538 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm="cat" exe="/bin/cat" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="sshd_config"
type=CWD msg=audit(1364481363.243:24287): cwd="/home/shadowman"
type=PATH msg=audit(1364481363.243:24287): item=0 name="/etc/ssh/sshd_config" inode=409248 dev=fd:00 mode=0100600 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:etc_t:s0 nametype=NORMAL
type=PROCTITLE msg=audit(1364481363.243:24287): proctitle=636174002F6574632F7373682F737368645F636F6E666967
```

*(Interpreted: exit=-13 → Permission denied; proctitle → `cat /etc/ssh/sshd_config`)*

---

## 8. sudo and Privilege Escalation

**Typical rules**
```text
-w /etc/sudoers -p wa -k sudo_config
-w /etc/sudoers.d/ -p wa -k sudo_config
-w /usr/bin/sudo -p x -k privilege_escalation
-w /usr/bin/su -p x -k privilege_escalation
```

### Example — sudo execution
```
type=SYSCALL msg=audit(1712346200.100:2500): arch=c000003e syscall=59 success=yes exit=0 a0=... a1=... a2=... a3=0 items=2 ppid=1900 pid=1920 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=8 comm="sudo" exe="/usr/bin/sudo" key="privilege_escalation"
type=EXECVE msg=audit(1712346200.100:2500): argc=3 a0="sudo" a1="cat" a2="/etc/shadow"
type=CWD msg=audit(1712346200.100:2500): cwd="/home/user"
type=PATH msg=audit(1712346200.100:2500): item=0 name="/usr/bin/sudo" inode=... mode=0104755 ouid=0 ogid=0 nametype=NORMAL
type=PROCTITLE msg=audit(1712346200.100:2500): proctitle=7375646F00636174002F6574632F736861646F77
```

### Example — /etc/sudoers modification
```
type=SYSCALL msg=audit(1712346210.200:2501): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7fff... a2=241 a3=1b6 items=1 ppid=1900 pid=1925 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=8 comm="visudo" exe="/usr/sbin/visudo" key="sudo_config"
type=PATH msg=audit(1712346210.200:2501): item=0 name="/etc/sudoers" inode=... mode=0100440 ouid=0 ogid=0 nametype=NORMAL
```

---

## 9. UID/GID and Credential Manipulation

**Typical rules**
```text
-a always,exit -F arch=b64 -S setuid,setreuid,setresuid -k credential_change
-a always,exit -F arch=b64 -S setgid,setregid,setresgid -k credential_change
```

### Example — setuid
```
type=SYSCALL msg=audit(1712346300.300:2600): arch=c000003e syscall=105 success=yes exit=0 a0=0 a1=0 a2=0 a3=0 items=0 ppid=2000 pid=2010 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=9 comm="su" exe="/usr/bin/su" key="credential_change"
type=PROCTITLE msg=audit(1712346300.300:2600): proctitle=7375
```

---

## 10. Login and Session Tracking

**Typical rules**
```text
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/lastlog -p wa -k session
-w /var/run/faillock -p wa -k logins
```

### Example — session record update (login)
```
type=SYSCALL msg=audit(1712346400.400:2700): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7fff... a2=2 a3=0 items=1 ppid=1 pid=2100 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=10 comm="login" exe="/usr/bin/login" key="session"
type=PATH msg=audit(1712346400.400:2700): item=0 name="/var/log/wtmp" inode=... mode=0100664 ouid=0 ogid=0 nametype=NORMAL
```

### Example — PAM authentication failure
```
type=USER_AUTH msg=audit(1364475353.159:24270): user pid=3280 uid=1000 auid=1000 ses=1 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:authentication acct="root" exe="/bin/su" hostname=? addr=? terminal=pts/0 res=failed'
```

---

## 11. Failed File Access (EACCES / EPERM)

**Typical rules**
```text
-a always,exit -F arch=b64 -S open,openat,openat2,creat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access_denied
-a always,exit -F arch=b64 -S open,openat,openat2,creat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access_denied
```

### Example — permission denied on /etc/shadow
```
type=SYSCALL msg=audit(1690783519.928:929): arch=c000003e syscall=257 success=no exit=-13 a0=ffffff9c a1=7fffd0dd98f0 a2=80000 a3=0 items=1 ppid=1160 pid=1184 auid=4294967295 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts2 ses=4294967295 comm="bat" exe="/usr/bin/bat" key="access_denied"
type=PATH msg=audit(1690783519.928:929): item=0 name="/etc/shadow" inode=270575 dev=ca:03 mode=0100000 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL
type=PROCTITLE msg=audit(1690783519.928:929): proctitle=626174002D70002F6574632F736861646F77
```

*(exit=-13 → EACCES / Permission denied)*

---

## 12. File Deletion and Rename

**Typical rules**
```text
-a always,exit -F arch=b64 -S rmdir,unlink,unlinkat,rename,renameat,renameat2 -F auid>=1000 -F auid!=unset -k file_delete
```

### Example — unlink / rm
```
type=SYSCALL msg=audit(1691747463.379:6628264): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=561b659c14d0 a2=0 a3=fffffffffffffb8c items=2 ppid=25291 pid=25450 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts4 ses=3 comm="rm" exe="/usr/bin/rm" key="file_delete"
type=CWD msg=audit(1691747463.379:6628264): cwd="/root"
type=PATH msg=audit(1691747463.379:6628264): item=0 name="/root" inode=654081 dev=08:01 mode=040700 ouid=0 ogid=0 rdev=00:00 nametype=PARENT
type=PATH msg=audit(1691747463.379:6628264): item=1 name="test_creation.txt" inode=655075 dev=08:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE
type=PROCTITLE msg=audit(1691747463.379:6628264): proctitle=726D00746573745F6372656174696F6E2E747874
```

---

## 13. Permission and Ownership Changes

**Typical rules**
```text
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k permissions
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -k ownership
```

### Example — chmod
```
type=PROCTITLE msg=audit(02/15/2022 20:56:56.248:12696): proctitle=chmod --recursive 777 /baeldung
type=PATH msg=audit(02/15/2022 20:56:56.248:12696): item=0 name=/baeldung inode=1966582 dev=08:11 mode=dir,755 ouid=root ogid=root rdev=00:00 nametype=NORMAL
type=CWD msg=audit(02/15/2022 20:56:56.248:12696): cwd=/
type=SYSCALL msg=audit(02/15/2022 20:56:56.248:12696): arch=x86_64 syscall=fchmodat success=yes exit=0 a0=AT_FDCWD a1=0x55b15f13e500 a2=0777 items=1 ppid=... pid=... auid=... uid=... gid=... euid=... suid=... fsuid=... egid=... sgid=... fsgid=... tty=pts1 ses=... comm=chmod exe=/usr/bin/chmod key="permissions"
```

---

## 14. Extended Attributes

**Typical rules**
```text
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k xattr
```

### Example — setxattr
```
type=SYSCALL msg=audit(1712346500.500:2800): arch=c000003e syscall=188 success=yes exit=0 a0=7fff... a1=7fff... a2=7fff... a3=0 items=1 ppid=2200 pid=2210 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=11 comm="setfattr" exe="/usr/bin/setfattr" key="xattr"
type=PATH msg=audit(1712346500.500:2800): item=0 name="/tmp/testfile" inode=... mode=0100644 ouid=0 ogid=0 nametype=NORMAL
```

---

## 15. Linux Capabilities

**Typical rules**
```text
-a always,exit -F arch=b64 -S capset -k capabilities
-w /usr/sbin/setcap -p x -k capabilities
```

### Example — setcap execution
```
type=SYSCALL msg=audit(1712346600.600:2900): arch=c000003e syscall=59 success=yes exit=0 a0=... a1=... a2=... a3=0 items=2 ppid=2300 pid=2310 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=12 comm="setcap" exe="/usr/sbin/setcap" key="capabilities"
type=EXECVE msg=audit(1712346600.600:2900): argc=3 a0="setcap" a1="cap_net_bind_service=+ep" a2="/usr/bin/myapp"
```

---

## 16. SUID/SGID and Privileged Execution

**Typical rules**
```text
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k privileged_exec
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged
```

### Example — privileged execve (euid=0)
```
type=SYSCALL msg=audit(1712346700.700:3000): arch=c000003e syscall=59 success=yes exit=0 a0=... a1=... a2=... a3=0 items=2 ppid=2400 pid=2410 auid=1000 uid=1000 gid=1000 euid=0 suid=0 fsuid=0 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=13 comm="passwd" exe="/usr/bin/passwd" key="privileged_exec"
type=EXECVE msg=audit(1712346700.700:3000): argc=1 a0="passwd"
type=PATH msg=audit(1712346700.700:3000): item=0 name="/usr/bin/passwd" inode=... mode=0104755 ouid=0 ogid=0 nametype=NORMAL
```

---

## 17. Kernel Module Activity

**Typical rules**
```text
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k kernel_module
-w /usr/sbin/insmod -p x -k kernel_module
-w /usr/sbin/modprobe -p x -k kernel_module
```

### Example — modprobe
```
type=SYSCALL msg=audit(1712346800.800:3100): arch=c000003e syscall=59 success=yes exit=0 a0=... a1=... a2=... a3=0 items=2 ppid=2500 pid=2510 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=14 comm="modprobe" exe="/usr/sbin/modprobe" key="kernel_module"
type=EXECVE msg=audit(1712346800.800:3100): argc=2 a0="modprobe" a1="nfs"
type=PATH msg=audit(1712346800.800:3100): item=0 name="/usr/sbin/modprobe" inode=... mode=0100755 ouid=0 ogid=0 nametype=NORMAL
```

---

## 18–20. Kernel Config / Bootloader / SELinux

### Example — SELinux config change
```
type=SYSCALL msg=audit(1712346900.900:3200): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7fff... a2=241 a3=1b6 items=1 ppid=2600 pid=2610 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=15 comm="vi" exe="/usr/bin/vi" key="selinux"
type=PATH msg=audit(1712346900.900:3200): item=0 name="/etc/selinux/config" inode=... mode=0100644 ouid=0 ogid=0 nametype=NORMAL
```

### Example — setenforce
```
type=SYSCALL msg=audit(1712346910.000:3201): arch=c000003e syscall=59 success=yes exit=0 a0=... a1=... a2=... a3=0 items=2 ppid=2600 pid=2615 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=15 comm="setenforce" exe="/usr/sbin/setenforce" key="selinux"
type=EXECVE msg=audit(1712346910.000:3201): argc=2 a0="setenforce" a1="0"
```

---

## 21–23. Firewall / Network / Route

### Example — firewall-cmd
```
type=SYSCALL msg=audit(1712347000.100:3300): arch=c000003e syscall=59 success=yes exit=0 a0=... a1=... a2=... a3=0 items=2 ppid=2700 pid=2710 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=16 comm="firewall-cmd" exe="/usr/bin/firewall-cmd" key="firewall"
type=EXECVE msg=audit(1712347000.100:3300): argc=3 a0="firewall-cmd" a1="--add-port=8080/tcp" a2="--permanent"
```

---

## 24. Mounting Filesystems

**Typical rules**
```text
-a always,exit -F arch=b64 -S mount,umount2 -F auid>=1000 -F auid!=unset -k mounts
-w /usr/bin/mount -p x -k mounts
```

### Example — mount
```
type=SYSCALL msg=audit(1712347100.200:3400): arch=c000003e syscall=165 success=yes exit=0 a0=7fff... a1=7fff... a2=7fff... a3=0 items=2 ppid=2800 pid=2810 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=17 comm="mount" exe="/usr/bin/mount" key="mounts"
type=EXECVE msg=audit(1712347100.200:3400): argc=3 a0="mount" a1="/dev/sdb1" a2="/mnt/data"
type=PATH msg=audit(1712347100.200:3400): item=0 name="/dev/sdb1" inode=... mode=060660 ouid=0 ogid=0 nametype=NORMAL
type=PATH msg=audit(1712347100.200:3400): item=1 name="/mnt/data" inode=... mode=040755 ouid=0 ogid=0 nametype=NORMAL
```

---

## 26. Cron Configuration

**Typical rules**
```text
-w /etc/crontab -p wa -k scheduled_tasks
-w /etc/cron.d/ -p wa -k scheduled_tasks
-w /var/spool/cron/ -p wa -k scheduled_tasks
```

### Example — crontab modification
```
type=SYSCALL msg=audit(1712347200.300:3500): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7fff... a2=241 a3=1b6 items=1 ppid=2900 pid=2910 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=18 comm="crontab" exe="/usr/bin/crontab" key="scheduled_tasks"
type=PATH msg=audit(1712347200.300:3500): item=0 name="/var/spool/cron/root" inode=... mode=0100600 ouid=0 ogid=0 nametype=NORMAL
```

---

## 27. systemd Service Persistence

**Typical rules**
```text
-w /etc/systemd/system/ -p wa -k systemd
-w /usr/bin/systemctl -p x -k service_management
```

### Example — systemctl
```
type=SYSCALL msg=audit(1712347300.400:3600): arch=c000003e syscall=59 success=yes exit=0 a0=... a1=... a2=... a3=0 items=2 ppid=3000 pid=3010 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=19 comm="systemctl" exe="/usr/bin/systemctl" key="service_management"
type=EXECVE msg=audit(1712347300.400:3600): argc=3 a0="systemctl" a1="enable" a2="myservice.service"
```

---

## 30. Dynamic Linker Manipulation

**Typical rules**
```text
-w /etc/ld.so.preload -p wa -k library_injection
-w /etc/ld.so.conf.d/ -p wa -k library_config
```

### Example — ld.so.preload write
```
type=SYSCALL msg=audit(1712347400.500:3700): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7fff... a2=241 a3=1b6 items=1 ppid=3100 pid=3110 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=20 comm="vi" exe="/usr/bin/vi" key="library_injection"
type=PATH msg=audit(1712347400.500:3700): item=0 name="/etc/ld.so.preload" inode=... mode=0100644 ouid=0 ogid=0 nametype=NORMAL
```

---

## 31–32. Package Management / RPM Database

### Example — dnf / rpm execution
```
type=SYSCALL msg=audit(1712347500.600:3800): arch=c000003e syscall=59 success=yes exit=0 a0=... a1=... a2=... a3=0 items=2 ppid=3200 pid=3210 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=21 comm="dnf" exe="/usr/bin/dnf" key="software_install"
type=EXECVE msg=audit(1712347500.600:3800): argc=3 a0="dnf" a1="install" a2="httpd"
```

---

## 36. Anti-Forensics Utilities

**Typical rules**
```text
-w /usr/bin/shred -p x -k anti_forensics
-w /usr/bin/truncate -p x -k anti_forensics
```

### Example — shred
```
type=SYSCALL msg=audit(1712347600.700:3900): arch=c000003e syscall=59 success=yes exit=0 a0=... a1=... a2=... a3=0 items=2 ppid=3300 pid=3310 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=22 comm="shred" exe="/usr/bin/shred" key="anti_forensics"
type=EXECVE msg=audit(1712347600.700:3900): argc=3 a0="shred" a1="-u" a2="/tmp/secret.txt"
```

---

## 37–39. Process Execution / Root Command / Direct Root Sessions

**Typical rules**
```text
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=unset -k user_exec
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k root_command
-a always,exit -F arch=b64 -S execve -F auid=0 -k root_session
```

### Example — full command execution (python script)
```
type=SYSCALL msg=audit(1675255174.901:30777): arch=c000003e syscall=59 success=yes exit=0 a0=11ba5a8 a1=13f78c8 a2=10ab008 a3=598 items=2 ppid=8720 pid=24107 auid=4294967295 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts19 ses=4294967295 comm="python" exe="/usr/bin/python2.7" key="user_exec"
type=EXECVE msg=audit(1675255174.901:30777): argc=2 a0="python" a1="badscript.py"
type=CWD msg=audit(1675255174.901:30777): cwd="/home/izy/Documents/testing"
type=PATH msg=audit(1675255174.901:30777): item=0 name="/usr/bin/python" inode=659272 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL
type=PATH msg=audit(1675255174.901:30777): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=926913 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL
type=PROCTITLE msg=audit(1675255174.901:30777): proctitle=707974686F6E006261647363726970742E7079
```

### Example — root_command (euid=0 from auid≥1000)
```
type=SYSCALL msg=audit(1532489108.216:3721): arch=c000003e syscall=59 success=yes exit=0 a0=16169e0 a1=16116f0 a2=161ab60 a3=7ffd940300a0 items=2 ppid=10627 pid=20240 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=3 comm="cat" exe="/usr/bin/cat" key="root_command"
type=EXECVE msg=audit(1532489108.216:3721): argc=2 a0="cat" a1="10-procmon.rules"
```

---

## 40. Process Tracing / Debugging (ptrace)

**Typical rules**
```text
-a always,exit -F arch=b64 -S ptrace -k process_injection
```

### Example — ptrace
```
type=SYSCALL msg=audit(1712347700.800:4000): arch=c000003e syscall=101 success=yes exit=0 a0=0 a1=1234 a2=0 a3=0 items=0 ppid=3400 pid=3410 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=23 comm="gdb" exe="/usr/bin/gdb" key="process_injection"
type=OBJ_PID msg=audit(1712347700.800:4000): opid=1234 oauid=1000 ouid=1000 oses=5 ocomm="target"
```

---

## 44. Reboot and Shutdown

**Typical rules**
```text
-w /usr/sbin/reboot -p x -k system_shutdown
-w /usr/sbin/shutdown -p x -k system_shutdown
```

### Example — reboot
```
type=SYSCALL msg=audit(1712347800.900:4100): arch=c000003e syscall=59 success=yes exit=0 a0=... a1=... a2=... a3=0 items=2 ppid=3500 pid=3510 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=24 comm="reboot" exe="/usr/sbin/reboot" key="system_shutdown"
type=EXECVE msg=audit(1712347800.900:4100): argc=1 a0="reboot"
```

---

## 52–55. Container / Kubernetes

### Example — docker / podman
```
type=SYSCALL msg=audit(1712347900.000:4200): arch=c000003e syscall=59 success=yes exit=0 a0=... a1=... a2=... a3=0 items=2 ppid=3600 pid=3610 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=25 comm="podman" exe="/usr/bin/podman" key="container_admin"
type=EXECVE msg=audit(1712347900.000:4200): argc=4 a0="podman" a1="run" a2="-it" a3="ubi9"
```

---

## Record-Type Quick Reference

| type=          | Meaning |
|----------------|---------|
| SYSCALL        | The system call that triggered the event |
| EXECVE         | Full argv[] of an executed program (best command-line source) |
| PATH           | File/directory path involved (item=0, item=1, …) |
| CWD            | Current working directory |
| PROCTITLE      | Hex-encoded process title (fallback for command line) |
| OBJ_PID        | Target process info (kill, ptrace, etc.) |
| USER_AUTH      | PAM authentication result |
| USER_LOGIN     | Login event |
| CONFIG_CHANGE  | Audit rule or configuration change |
| DAEMON_START   | auditd started |
| AVC            | SELinux Access Vector Cache decision |

---

## Operational Tips

1. **Always use `ausearch -i`** — it decodes hex fields, maps syscall numbers to names, and converts exit codes.
2. **Filter by key** — `ausearch -k identity -i`, `ausearch -k access_denied -i`, etc.
3. **Event ID correlation** — every multi-record event shares the same serial (the number after the colon).
4. **Volume caution** — broad `execve`, read-access and whole-directory watches generate very high volume; test before fleet deployment.
5. **UID_MIN** — replace hard-coded `1000` with the value from `/etc/login.defs` when generating rules programmatically.

---

*Generated from the Consolidated Linux auditd Rule Catalogue (CIS RHEL 9 v2.0.0 · DISA STIG RHEL 9 · ACSC ISM · SCAP) and real-world audit log samples.*
