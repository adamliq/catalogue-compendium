# How to Configure Auditing to Collect Each Event

This is a human-readable version of `data/reference/audit_configuration.csv` /
`data/reference/audit_configuration.json`. Each section is one auditing
subcategory (mostly Advanced Audit Policy Configuration subcategories, plus a
few product-specific settings) — the Group Policy / registry path to enable
it, the steps, and the event IDs it causes to be logged.

Most Security-log subcategories share the same base steps:

> Event Viewer / Group Policy Management Editor → navigate to
> `Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy Configuration\<Category>\<Subcategory>`
> → check **Configure the following audit events** → check **Success**
> and/or **Failure** → OK.

## Audit Credential Validation
- **Path:** `...\Account Logon\Audit Credential Validation`
- **Events:** 4774, 4775, 4776, 4777
- **Reference:** https://docs.microsoft.com/en-us/windows/device-security/auditing/audit-credential-validation

## Audit Kerberos Authentication Service
- **Path:** `...\Account Logon\Audit Kerberos Authentication Service`
- **Events:** 4768, 4771, 4772
- **Reference:** https://docs.microsoft.com/en-us/windows/device-security/auditing/audit-kerberos-authentication-service

## Audit Kerberos (verbose / debug logging)
- **Path (GPO):** enable all four Account Logon subcategories (Audit
  Credential Validation, Audit Kerberos Authentication Service, Audit
  Kerberos Service Ticket Operations, Audit Other Account Logon Events).
- **Path (single machine, verbose):** `regedit.exe` →
  `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters`
  → create DWORD `LogLevel` if missing → set value to `1`.
- **Events:** 4649, 4768, 4769, 4770, 4771, 4772, 4774, 4775, 4776, 4777,
  4778, 4779, 4800, 4801, 4802, 4803, 5378, 5632, 5633

## Audit User Account Management
- **Path:** `...\Account Management\Audit User Account Management`
- **Events:** 4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740

## Audit Computer Account Management
- **Path:** `...\Account Management\Audit Computer Account Management`
- **Events:** 4741, 4742, 4743

## Audit Security Group Management
- **Path:** `...\Account Management\Audit Security Group Management`
- **Events:** 4727, 4728, 4729, 4730, 4735, 4737

## Audit Directory Service Changes
- **Path:** `...\DS Access\Audit Directory Service Changes`
- **Events:** 5136, 5137, 5141

## Audit Account Lockout
- **Path:** `...\Logon/Logoff\Audit account lockout events`
- **Events:** 4625
- **Reference:** https://docs.microsoft.com/en-us/windows/device-security/auditing/audit-account-lockout

## Audit Logoff
- **Path:** `...\Logon/Logoff\Audit logoff events`
- **Events:** 4634, 4647
- **Reference:** https://docs.microsoft.com/en-us/windows/device-security/auditing/audit-logoff

## Audit Logon
- **Path:** `...\Logon/Logoff\Audit logon events`
- **Events:** 4624, 4625, 4648, 4675
- **Reference:** https://docs.microsoft.com/en-us/windows/device-security/auditing/audit-logon

## Audit Network Policy Server
- **Path:** `...\Logon/Logoff\Audit Network Policy Server`
- **Events:** 6272, 6273, 6274, 6275, 6276, 6277, 6278, 6279, 6280

## Audit Other Logon/Logoff Events
- **Path:** `...\Logon/Logoff\Audit other logon/logoff events`
- **Events:** 4649, 4778, 4779, 4800, 4801, 4802, 4803, 5378, 5632, 5633
- **Reference:** https://docs.microsoft.com/en-us/windows/device-security/auditing/audit-other-logonlogoff-events

## Audit Special Logon
- **Path:** `...\Logon/Logoff\Audit Special Logon`
- **Events:** 4964
- **Reference:** https://docs.microsoft.com/en-us/windows/device-security/auditing/audit-special-logon

## Audit Non-Sensitive Privilege Use / Audit Sensitive Privilege Use
- **Path:** `...\Privilege Use\Audit Non-Sensitive Privilege Use` /
  `...\Privilege Use\Audit Sensitive Privilege Use`
- **Events:** 4672, 4673, 4674

## Audit PNP Activity
- **Path:** `...\Detailed Tracking\Audit PNP Activity`
- **Events:** 6416, 6419, 6420, 6421, 6422, 6423, 6424
- **Reference:** https://docs.microsoft.com/en-us/windows/device-security/auditing/audit-pnp-activity

## Audit Token Right Adjustment
- **Path:** `...\Detailed Tracking\Audit Token Right Adjustment`
- **Events:** 4703
- **Notes:** Not audited by default; high event volume.

## Audit User / Device Claims
- **Path:** `...\DS Access\Audit User / Device Claims`
- **Events:** 4626
- **Notes:** Requires Audit Logon to also be enabled to get events from this subcategory.

## Audit Group Membership
- **Path:** `...\DS Access\Audit Group Membership`
- **Events:** 4627
- **Notes:** Requires Audit Logon to also be enabled to get events from this subcategory.

## Audit Central Access Policy Staging
- **Path:** `...\Object Access\Audit Central Access Policy Staging`
- **Events:** 4818
- **Notes:** Requires a proposed Central Access Policy to be staged; generates an event whenever the proposed and current policy would grant different access.

## Audit Process Creation / Audit Process Termination
- **Path:** `Advanced Security Audit Policy Settings\Detailed Tracking\Audit Process Creation` /
  `...\Audit Process Termination`
- **Events:** 4688, 4696 / 4689

## Audit Certification Services
- **Path:** `Advanced Security Audit Policy Settings\Object Access\Audit Certification Services`
- **Events:** 4868–4898 (AD CS certificate services events)

## Audit Removable Storage
Full step-by-step (this one needs Handle Manipulation too if you want Failure events):
1. Sign in to the domain controller as a domain administrator.
2. Server Manager → Tools → Group Policy Management.
3. Right-click the target GPO → Edit.
4. Navigate to `Computer Configuration\Security Settings\Advanced Audit Policy Configuration\Object Access\Audit Removable Storage`.
5. Check **Configure the following audit events**, check **Success** (and **Failure** if desired) → OK.
6. If Failure was selected, also open **Audit Handle Manipulation**, check **Configure the following audit events**, and select **Failure**.
7. OK, close the Group Policy Management Editor.

- **Events:** 2003, 2004, 2005, 2010, 2100, 2105, 2106, 4656, 4663

## Printer auditing
1. For print job names to appear in the log, install KB2919355.
2. Per-printer object auditing: Printer Properties → Security tab → Advanced → Auditing tab → Add → select Principal → select Group → set Type and permissions → OK.
3. Enable the log channel: Event Viewer → Applications and Services Logs → Microsoft → Windows → PrintService → Operational → right-click → Enable Log.

- **Log:** `Microsoft-Windows-PrintService/Operational`
- **Events:** 307, 800, 802, 805

## NTLM auditing
- **Path:** `Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Restrict NTLM`
- **Events:** 4776 (plus NTLM-specific events 8001–8004)
- **Reference:**
  https://technet.microsoft.com/en-au/library/jj865682%28v=ws.10%29.aspx?f=255&MSPPError=-2147217396,
  https://blogs.technet.microsoft.com/askds/2009/10/08/ntlm-blocking-and-you-application-analysis-and-auditing-methodologies-in-windows-7/

## Netlogon debug logging
Not a Windows Event Log — writes to `%windir%\debug\netlogon.log`.

- **Enable:**
  ```
  Nltest /DBFlag:2080FFFF
  ```
  or via registry:
  ```
  reg add "\\$computerName\HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters" /v DBFlag /t REG_DWORD /d 0x2080ffdf /f
  reg add "\\$computerName\HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters" /v MaximumLogFileSize /t REG_DWORD /d 100000000 /f
  ```
  then restart the service:
  ```
  net stop netlogon
  net start netlogon
  ```
- **Disable:**
  ```
  Nltest /DBFlag:0x0
  ```
- **Reference:** https://support.microsoft.com/en-us/help/109626/enabling-debug-logging-for-the-netlogon-service

## Enable Microsoft-Windows-WebAuthN/Operational log
Not a GPO audit policy — a per-machine diagnostic channel, disabled by
default. It records FIDO2/CTAP security-key and Windows Hello (NGC)
`MakeCredential` (registration) and `GetAssertion` (sign-in) operations,
down to USB/NFC transport-level detail.

- **GUI:** launch `eventvwr.exe` → Applications and Services Logs →
  Microsoft → Windows → WebAuthN → right-click **Operational** → **Enable Log**.
- **Command line:**
  ```
  wevtutil sl Microsoft-Windows-WebAuthN/Operational /e:true
  ```
- **Events:** 1000–1008, 1020–1025, 1040–1043, 1060, 1100–1104 (MakeCredential/GetAssertion,
  Windows Hello, CBOR encode/decode, errors); 2000–2001 (service lifecycle);
  2100–2104, 2110–2111 (CTAP command dispatch, device enumeration);
  2200–2226 (USB transport); 2300–2328 (NFC transport); 2400–2402 (test provider).
- **Reference:** https://learn.microsoft.com/en-us/windows/win32/api/webauthn/
