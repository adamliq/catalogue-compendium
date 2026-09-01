# Winevent-catalogue

A structured catalogue of Windows Event Log IDs. Built from a personal MS
Server administration notebook (TiddlyWiki export) covering Security
auditing events (mapped to their Group Policy audit subcategories), DHCP
Server events, Removable Media / Plug-and-Play device events, Network
Location Awareness (NLA) events, Terminal Services / RDS session events,
and System shutdown/restart events — plus WebAuthn (FIDO2/Windows Hello)
operational log events (sourced from the real Microsoft-Windows-WebAuthN
ETW manifest) and event IDs cross-referenced from the ASD/ACSC "Priority
logs for SIEM ingestion: Practitioner guidance" (2025), including AD FS,
LDAP signing, Code Integrity/WDAC, AppLocker, Sysmon, PowerShell, WMI
Activity, Task Scheduler, ESENT, and Windows DNS Server analytic events.

## Contents

- `data/events.csv` / `data/events.json` — the main catalogue, one row per
  `(event_id, log, category, subcategory)` combination:
  - `event_id` — the Windows Event ID (decimal, or hex where the source used hex)
  - `log` — the event log / channel the event is written to
  - `source` — the event provider / source name
  - `category` — high-level grouping (e.g. `DHCP`, `Removable Media / Device (PNP)`,
    or the Group Policy "Audit ..." category for Security events)
  - `subcategory` — the specific Group Policy audit subcategory, where applicable
  - `description` — what the event means
  - `sample` — every event has one: a real sample where the source notebook
    captured one, otherwise a generated representative example (Event
    Viewer-style text) using a consistent fictional environment
    (`CORP.LOCAL` domain, `DC01.corp.local`, etc.)
  - `reference` — pointer to related configuration notes or docs
  - `how_to_collect` — which auditing subcategory/subcategories (from
    `data/reference/audit_configuration.csv`) must be enabled to generate
    this event
  - `sample_type` — `original` (captured from the source notebook),
    `illustrative` (a representative example I built), or `template` (the
    event's raw message string as published in the source ETW manifest,
    with its `{Placeholder}` tokens left unfilled — used for the bulk ETW
    manifest import, see below). The web lookup page tags both generated
    types so they're never mistaken for a real capture.
  - `mitre_techniques` — MITRE ATT&CK technique ID(s) associated with the
    event, semicolon-separated, where mapped (populated for Sysmon,
    AppLocker, Code Integrity, Windows Defender, and — via the full
    technique↔event dataset in `data/reference/mitre_attack_mapping.csv` —
    48 Security-log audit events; blank elsewhere). High-fan-out events
    (e.g. 4688 Process Creation, which maps to 286 techniques) are shown
    truncated to the first 10 in the web lookup page's detail view, with a
    link through to the full reference table.
  - `acsc_priority_log` — `Yes` if this exact `(event_id, log)` appears in
    the ASD/ACSC "Priority logs for SIEM ingestion: Practitioner guidance"
    tables (Microsoft Domain Controller; AD & Domain Service Security Logs;
    Microsoft Windows endpoint logs; Windows DNS server analytic event
    logs), blank otherwise. The web lookup page has a toggle to show only
    these events.
  - `nist_800_53_au` — NIST SP 800-53 Audit and Accountability (AU) control
    ID(s) most relevant to the event: `AU-9` (Protection of Audit
    Information) for log-clearing/log-service events, `AU-8` (Time Stamps)
    for clock-change events, and `AU-2, AU-3, AU-12` (the standard "what to
    audit and how to generate it" triad) applied at the audit-subcategory
    level via `data/reference/audit_configuration.csv` — not a substitute
    for a full compliance assessment.
  - `field_schema` — populated for every event: a structured map of the
    fields inside that event's `sample`, parsed out of the Event
    Viewer-style text and grouped the way the real event does (e.g.
    `subject`, `new_logon`, `process_information` for a logon event), with
    each leaf giving that field's inferred type (`string`, `integer`,
    `hex`, `sid`, `guid`, `ip`, `path`, `principal`, `enum`,
    `list<string>`). Every row gets at least a `header` block (`log_name`,
    `source`, `event_id`, `level`, `computer`, `description`, etc.); most of
    the 3,907 bulk-imported ETW `template` rows have nothing further since
    their sample is just a single unfilled message string, while
    `original`/`illustrative` rows (and any `template` row whose message
    itself lists `Key: {Placeholder}` fields) get the fuller nested
    breakdown. In `events.json` this is a nested object; in `events.csv`
    it's the same structure serialized as a JSON string (CSV can't nest).
    It's derived automatically from each event's own `sample` field by a
    generic parser (header block, free-text description, then
    `Key: Value` / `Key = Value` fields either flat or nested under a
    `GroupName:` block) — best-effort type inference from example values,
    not a guarantee of the real Windows event schema. The web lookup page
    renders it as a "Field Schema" section in the detail view, below the
    raw sample.
  - `group_policy_path` — for the ~1,362 events whose log isn't driven by
    the Advanced Audit Policy system (so `how_to_collect` is blank), the
    Group Policy path that governs the underlying feature generating that
    event — e.g. AppLocker events point at `Application Control
    Policies\AppLocker`, BitLocker events at `BitLocker Drive Encryption`,
    PowerShell script-block events at `Turn on PowerShell Script Block
    Logging`. Populated only for logs with a well-established, documented
    native Windows GPO path (curated by provider, not guessed per event);
    left blank everywhere else, including every event that already has
    `how_to_collect` — the two are mutually exclusive by design, since
    those already get detailed audit-subcategory guidance. It's the
    governing policy area for the feature, not a per-event "enable this
    log" toggle — many of these channels still need a separate `wevtutil
    sl <channel> /e:true` (or Event Viewer's "Enable Log") once the
    feature itself is turned on. The web lookup page shows it as a "Group
    Policy path" card in the detail view, with that caveat.
  - `opposite_event_id` — for 109 rows forming 54 known success/failure
    pairs of the same underlying operation with two distinct event IDs
    (e.g. 4624 successful logon ↔ 4625 failed logon; 6272 NPS access
    granted ↔ 6273 access denied; 51026 valid DHCP Info-request reply ↔
    51027 invalid reply), the partner event's ID. Curated by manually
    reviewing every same-subcategory description pair the catalogue's own
    text flagged as plausible opposites (near-identical wording except for
    a success/fail word), discarding false matches (state-machine states
    like VPN "Connecting"/"Disconnected" aren't a success/failure pair;
    cross-matched pairs where the operations didn't actually correspond);
    left blank everywhere there wasn't a clear, confidently-verified
    opposite. One pair (4656/4663, read/write to removable media) only
    applies to those IDs' `Removable Media / Device (PNP)` rows — both
    IDs mean something unrelated elsewhere in the Security log, so the
    pairing is scoped to that specific category, not the bare event ID.
    The web lookup page shows it as a clickable "Opposite outcome" field
    that jumps straight to the paired event's own detail view.
  - `cim_mapping` — for 546 rows, the Splunk Common Information Model
    data model/dataset the event maps to cleanly (e.g. `Authentication`,
    `Change.Account_Management`, `Endpoint.Processes`,
    `Malware.Malware_Attacks`) — see
    `data/reference/splunk_cim_data_models.csv` for what each dataset
    means, which CIM fields it carries, and whether it's confirmed by the
    real Splunk Add-on for Microsoft Windows package.

    Built in two passes. First, this catalogue's own analysis: per
    Security-log audit subcategory (the official Advanced Audit Policy
    taxonomy already in `category`/`subcategory` maps very predictably to
    CIM datasets — e.g. every `Audit User Account Management` event is
    `Change.Account_Management`), per canonical Sysmon event ID, and by
    hand-reviewing every event's actual message text on channels that
    looked homogeneous but turned out to mix genuine signal with
    diagnostic noise — e.g. the Terminal Services connection-manager
    channels contain real session-lifecycle events (logon, disconnect,
    reconnect, shadow session start/stop) alongside licensing/timing/
    profile-cache diagnostics that don't belong in any CIM dataset, so
    those were mapped event ID by event ID rather than as a whole channel;
    the dedicated Windows Firewall/IPsec channels turned out to be rule
    *configuration* events (`Change.Network_Changes`), not actual traffic
    pass/block events, once their text was read rather than assumed from
    the channel name.

    Second, a real `Splunk_TA_windows-11.0.2.tar` package (the actual
    Splunk Add-on for Microsoft Windows) was supplied and cross-checked
    against the first pass: its `eventtypes.conf`/`tags.conf` were parsed
    to compute, per Security/System-log EventCode, the union of CIM tags
    every matching eventtype assigns, then classified into a dataset by
    the standard CIM tag-requirement combinations (`change`+`account` →
    `Change.Account_Management`, `process`+`report` →
    `Endpoint.Processes`, etc.). Wherever that produced an explicit
    answer it **overrode** this catalogue's own guess, correcting several
    real mistakes — e.g. 4634/4647 (logoff) and 4740/4767 (account
    lockout/unlock) had been guessed as `Authentication` but the real
    add-on tags them `Change.Account_Management`; 5154/5158/4957/861
    (Windows Filtering Platform "permitted to listen") had been guessed
    as `Network_Traffic`/`Change.Network_Changes` but the add-on has a
    dedicated `Endpoint.Ports` dataset for exactly this; 4717/4718 had
    been guessed as `Change.Auditing_Changes` but the add-on tags them
    `Change.Account_Management`. It also surfaced a real product gap
    worth noting: EventCode 4772 (Kerberos service-ticket request
    failed) is listed in the add-on's own `eventtypes.conf` *comment*
    but the comment doesn't match its actual search filter, so 4772 (and
    4770, ticket renewed) get no CIM tag in the real product at all —
    left blank here too, matching the real add-on rather than what
    seems like it should obviously be true. The add-on doesn't cover
    Sysmon, Terminal Services, the dedicated Windows Firewall channels,
    Certificate Services Client, or DNS Server at the event-code level
    at all, so those stay as this catalogue's own analysis from the
    first pass, unverified but undisputed.

    Left blank everywhere a confident single-dataset mapping doesn't
    exist (ambiguous object-access events, and channels like
    `CertificateServices-Deployment/Operational` whose message text in
    this catalogue is an undecoded placeholder). The web lookup page
    shows it as a clickable "Splunk CIM" field that jumps to the matching
    row in the new Reference tables entry, and it's also selectable as a
    Pivot explorer facet.

- `data/reference/splunk_cim_data_models.csv` / `.json` — the 20 Splunk
  CIM data models/datasets referenced by `cim_mapping`, each with its
  description, representative CIM field list, whether it's confirmed by
  the real Splunk Add-on for Microsoft Windows package (`ta_verified`:
  Yes/Partial/No), and which Windows event sources in this catalogue feed
  it. Includes `Alerts` (Azure Monitor alert firings and Microsoft
  Defender XDR's cross-product alert record) and `Data Loss Prevention
  (DLP)` (Microsoft Purview DLP policy matches), added for the cloud logs
  below — neither is covered by Splunk_TA_windows, since it's a
  Windows-only add-on (`ta_verified: No` for both).
- `data/cloud_logs.csv` / `.json` — expands beyond Windows Event Log into
  Microsoft's cloud platforms, kept as a separate data model rather than
  shoehorned into `events.csv`: cloud logs are identified by a named
  category within a resource type (e.g. `SignInLogs` under the
  tenant-wide `Microsoft Entra ID` area), not a numeric event ID, and a
  single category like `AuditLogs` covers many distinct operation types
  rather than being enumerated individually the way Windows events are —
  so `event_id`/`group_policy_path`/`how_to_collect` don't apply and
  aren't reused. 216 rows across seven platforms:
  - **Entra ID** (13 rows) — all Microsoft Entra ID tenant-wide log
    categories (`AuditLogs`, `SignInLogs`, `RiskyUsers`, etc.).
  - **Azure** (146 rows) — all 8 Subscription Activity Log categories
    (`Administrative`, `Security`, `Policy`, etc.) plus 138 Azure
    resource-log categories across 47 resource types
    (`Microsoft.KeyVault/vaults`, `Microsoft.Storage/storageAccounts`,
    `Microsoft.ContainerService/managedClusters`,
    `Microsoft.Sql/servers/databases`, and dozens more, from
    high-traffic ones like `Microsoft.Cdn/profiles` (Azure Front Door)
    down to niche ones like `Microsoft.SignalRService/SignalR`,
    `Microsoft.Batch/batchAccounts`, `Microsoft.Maps/accounts`, and
    `Microsoft.AzureStackHCI/clusters`) — deduplicated, unioned, and
    comma-escaping-fixed from a supplied
    `Azure_Log_Categories_Complete.csv` export, which had a large
    duplicated block (several resource types listed twice, near-verbatim,
    later in the file) and two rows with unescaped commas inside unquoted
    description fields that would have silently misaligned columns on a
    naive parse; the two occurrences of each duplicated resource type
    were unioned rather than either one being dropped outright, since the
    second pass sometimes added genuinely new categories the first didn't
    have (e.g. `Microsoft.ContainerService/managedClusters` gained
    `csi-azuredisk-controller` and `csi-azurefile-controller` from its
    second listing). Two later export rounds added the rest of the long
    tail (Azure Virtual Desktop, Azure Front Door/WAF, Microsoft Purview's
    own account-level resource logs, Azure Arc, Managed DevOps Pools,
    Azure Communication Services, Azure AI Services/OpenAI, Azure Maps,
    and Azure Stack HCI) — split into one row per documented diagnostic
    category the same way the earlier resource types were (e.g. Azure
    Virtual Desktop's `Checkpoint`/`Error`/`Management`/`Connection`/
    `HostRegistration` categories became 5 separate `hostpools` rows
    rather than one combined row), except where the source only gave a
    single combined category name without enough detail to split
    confidently (Azure Communication Services, Azure Arc). One export
    round also supplied two more Azure Backup/Site Recovery categories
    for the existing `Microsoft.RecoveryServices/vaults` row
    (`CoreAzureBackup`, the `AddonAzureBackup*` family,
    `AzureSiteRecoveryReplicatedItems`) that were merged into that row's
    existing combined category string rather than added as new rows,
    since they're the same resource type's diagnostic settings, just
    described at finer granularity than the first pass had captured.
  - **Microsoft 365** (28 rows) — the major record types of the
    Microsoft Purview unified audit log: Exchange Online admin/mailbox
    activity, SharePoint Online/OneDrive file and sharing operations,
    Microsoft Teams, Power Platform, Power BI, Dynamics 365/Dataverse,
    Microsoft Fabric, Data Loss Prevention policy matches, and Microsoft
    Defender for Office 365 threat detections. Most of these were built
    from Microsoft's own published audit-log record-type reference
    (well-established, common security-engineering knowledge) rather
    than a source export, scoped to record types with genuinely
    established, well-known meaning rather than attempting to enumerate
    the full record-type list from memory. A later supplied export's
    Microsoft 365/Power Platform rows turned out to substantially
    restate record types already covered here at a coarser or
    less-precise grain (e.g. its generic
    `UnifiedAuditLog / Audit.General / ...` row versus this catalogue's
    already-itemized `ExchangeAdmin`/`ExchangeItem`/etc.; its
    `PowerAppsActivity / PowerAutomateActivity / PowerBIActivity` row
    versus the already-present `MicrosoftFlow`/`PowerAppsApp` record
    types) — those were left out rather than duplicated, and only the
    genuinely new, confidently-real record type it surfaced
    (`PowerBIAudit`) was added, alongside `Dynamics365Activity` and a
    Microsoft Fabric workspace-activity row built from general knowledge
    of Purview's audit coverage.
  - **Microsoft Defender** (23 rows) — added from a second, updated
    supplied export that appended 11 source rows for Defender for Cloud,
    Endpoint, Identity, Cloud Apps, and Office 365. Several of those
    source rows named multiple Microsoft Sentinel/Defender XDR advanced
    hunting tables together (e.g. `DeviceEvents / DeviceProcessEvents /
    DeviceNetworkEvents / ...`); each was split into its own row here,
    since these are genuinely distinct, individually well-documented
    tables with their own schemas — the same granularity choice this
    catalogue already makes for e.g. its own Sysmon rows.
  - **Azure DevOps** (3 rows) — organization-level audit streaming
    (`AzureDevOpsAuditing`, plus a row summarizing the Category/Area
    taxonomy its events carry) and pipeline run diagnostic/agent/worker
    logging (`system.debug=true`). A new platform rather than folded
    into Azure, since it's a separate product surface with its own
    auditing model, not an ARM resource with diagnostic settings.
  - **Microsoft Intune** (2 rows) — tenant-wide device compliance/
    configuration/app-protection logging, plus Windows 365 Cloud PC
    provisioning/connection activity (folded in here rather than given
    its own platform, since Windows 365 is managed entirely through the
    Intune admin center).
  - **GitHub** (1 row) — organization/enterprise audit log streaming.
    Included since GitHub is a Microsoft subsidiary whose audit log is
    commonly piped into the same Sentinel/Splunk pipelines as the rest
    of this catalogue's cloud sources.

  Fields: `platform` (`Entra ID` / `Azure` / `Microsoft 365` /
  `Microsoft Defender` / `Azure DevOps` / `Microsoft Intune` /
  `GitHub`), `area`, `resource_type`, `category`,
  `description`, `severity_notes` (including license-tier caveats like
  "P1/P2" or "requires Microsoft 365 E5 / Advanced Audit"),
  `config_location` (the Diagnostic Settings / Purview Audit / Defender
  XDR connector path — the cloud analog of `group_policy_path`),
  `cim_mapping` (reuses `splunk_cim_data_models.csv` — CIM is
  platform-agnostic, so e.g. `SignInLogs` and Defender for Endpoint's
  `DeviceLogonEvents` both map to `Authentication` exactly like Windows
  4624/4625 do, `DeviceProcessEvents` maps to `Endpoint.Processes`
  exactly like Windows 4688/Sysmon 1 do, `AzureFirewallNetworkRule`/
  `ApplicationGatewayFirewallLog` map to `Network_Traffic` exactly like
  Windows' own Filtering Platform events do, `ComplianceDLPExchange`/
  `ComplianceDLPSharePoint`/`DLPEndpoint` map to the `DLP` dataset,
  Defender for Cloud's `SecurityAlerts` / Defender XDR's `AlertInfo` /
  Azure Front Door's WAF logs map to the `Alerts` dataset, and
  `AzureDevOpsAuditing` / the GitHub audit log map to `Change` the same
  way the Azure Subscription Activity Log's `Administrative` category
  does), `nist_800_53_au` (the same `AU-2, AU-3,
  AU-12` controls that apply to any audit-logging configuration), and
  `windows_equivalent` — a cross-link (semicolon-separated Security-log
  event IDs) pointing at the on-premises Windows event that's the
  closest counterpart to a cloud log category, for hybrid AD
  environments (populated for `SignInLogs`/`ADFSSignInLogs`,
  `Microsoft.AAD/domainServices`' `AccountLogon`/`LogonLogoff`, and
  Defender's `DeviceLogonEvents`/`IdentityLogonEvents` → `4624`, plus
  `DeviceProcessEvents` → `4688` and `DeviceRegistryEvents` → `4657` —
  Azure AD Domain Services runs an actual Windows-style directory so its
  log category names mirror Security log categories directly, and
  Defender for Endpoint/Identity observe the same underlying Windows
  activity from a different vantage point; nothing in the Microsoft 365
  rows gets one, since Exchange/SharePoint/Teams have no on-premises
  event in this catalogue to point at).

  `cim_mapping` and `windows_equivalent` were populated conservatively
  throughout — on a bit under a quarter of the 216 rows, where a clean,
  confident mapping exists (mostly Authentication, Change.Account_
  Management, Network_Traffic, DLP, Alerts, and bare Change), left blank
  everywhere else (`RiskyUsers`, all the SQL/DocumentDB/Databricks/
  Synapse performance-telemetry categories, App Insights telemetry, most
  platform-as-a-service operational logs, most Exchange/SharePoint/Teams
  activity categories, the Azure Virtual Desktop/Arc/Intune/Communication
  Services rows, and the broader Defender advanced-hunting tables like
  `DeviceEvents`/`CloudAppEvents`/`EmailEvents` whose content spans too
  many kinds of activity to fit one CIM dataset) rather than force-fit a
  Splunk CIM dataset that doesn't actually describe what the category
  captures. The web lookup page's "Cloud logs" tab browses this list
  with the same search/filter/detail-view pattern as the Events tab, a
  seven-way platform toggle (each platform independently on or off,
  wrapping onto a second row on narrow viewports) in place of the Events
  tab's Log/Category comboboxes — its list rows show the resource type
  as their second badge for the Azure Resource Log and Microsoft Purview
  rows specifically (their `area` field is identical across every row
  within each of those two groups, so it wouldn't help distinguish
  anything at a glance; every other platform's `area` already varies
  meaningfully row to row, so they keep showing it) — and its clickable
  Splunk CIM / Windows equivalent fields jump into the Reference tables
  tab and Events tab respectively, reusing
  `jumpToCimTable()`/`jumpToEvent()` rather than new navigation code.

  This remains a snapshot, not a claimed-complete enumeration: not every
  Azure resource type is here (only the ones present in the supplied
  exports), Microsoft 365's own record-type list is larger than the 28
  covered here, and none of these seven platforms stand still — all of
  them ship new log sources on an ongoing basis.
- `data/reference/audit_configuration.csv` / `.json` — how to configure
  auditing to collect events, one row per audit subcategory (or
  product-specific setting): the Group Policy / registry path, the steps to
  enable it, the event IDs it produces, a reference URL where available,
  and its NIST 800-53 AU control mapping. See
  `docs/audit-configuration-guide.md` for the readable version.
- `data/reference/audit_policy_matrix.csv` — the raw Group Policy audit
  category → Event ID mapping (Account Logon, Account Management, Detailed
  Tracking, DS Access, Logon/Logoff, Object Access, Policy Change, Privilege
  Use, System, Global Object Access Auditing), before expansion into
  `events.csv`.
- `data/reference/ntlm_error_codes_4776.csv` — NTLM/Kerberos status codes
  seen in the `Error Code` field of Event ID 4776.
- `data/reference/kerberos_result_codes.csv` / `.json` — the 47 standard
  Kerberos protocol result codes (RFC description plus notes on common
  failure causes), seen in the `Result Code` field of the Kerberos ticket
  events (4768, 4769, 4770, 4771, 4772, 4774, 4775, 4777, 4820, 4821,
  4824). The web lookup page shows the matching table inline on each of
  those events' detail views, and the full table on the Reference tables
  tab.
- `data/reference/ntstatus_codes.csv` / `.json` — the full official
  Windows NTSTATUS reference: 1,795 codes with their symbolic name (e.g.
  `STATUS_WRONG_PASSWORD`) and description, seen in `Status` / `Sub
  Status` fields such as those on Event ID 4625 (An account failed to log
  on). Sourced from Microsoft's MS-ERREF Open Specifications
  documentation (redistributed, with attribution, by the Samba project —
  `joyasystems.com`, the site originally requested, was unreachable from
  this environment). The web lookup page shows a curated set of the most
  common logon-failure codes inline on 4625's detail view, with a link
  through to the full, searchable 1,795-row table on the Reference tables
  tab.
- `data/reference/windows_message_tokens.csv` / `.json` — 17 Windows
  message-table string references (the raw `%%NNNN` tokens Windows
  substitutes into rendered event text): 11 `Sub Status` tokens seen on
  Event ID 4625 (e.g. `%%2313` = clock skew, `%%2311` = account locked
  out), plus 6 `Logon Process` / `Authentication Package` tokens (e.g.
  `%%1833` = NtLmSsp, `%%1841` = Kerberos) seen across the logon-related
  Security events. The web lookup page shows the full table inline on
  4625 (which has both kinds of token) and the Logon Process/Package
  subset inline on the other 15 events that carry those fields.
- `data/reference/kerberos_encryption_types.csv` / `.json` — the 16
  Kerberos ticket encryption types (e.g. `0x12` = `AES256-CTS-HMAC-SHA1-96`,
  `0x17` = `ARCFOUR-HMAC` / RC4-HMAC), seen in the `Ticket Encryption Type`
  field of Kerberos ticket events 4768, 4769, 4770, 4771, 4772, 4774, 4775,
  and 4777. Sourced from MIT krb5's `ENCTYPE_*` constants.
- `data/reference/kerberos_preauth_types.csv` / `.json` — the 42 Kerberos
  pre-authentication data types (PA-DATA type registry), seen in the
  `Pre-Authentication Type` field of Kerberos ticket events 4768, 4769,
  4770, 4771, 4772, 4774, 4775, 4777, and 4824. Sourced from MIT krb5's
  `KRB5_PADATA_*` constants.
- `data/reference/kerberos_ticket_options_flags.csv` / `.json` — the 17
  bit flags making up the `Ticket Options` (KDCOptions) field of Kerberos
  ticket events 4768, 4769, 4770, 4771, 4772, 4774, 4775, 4777, 4820, and
  4821 — a bitmask, not a simple enum, so the reference table lists each
  bit's mask and meaning for OR-ing together to decode a value. Sourced
  from MIT krb5's `KDC_OPT_*` constants and verified against the
  catalogue's own 4768 sample (`0x40810010` decodes to forwardable +
  renewable + canonicalize + renewable-ok).
- `data/reference/logon_type_codes.csv` / `.json` — the 13 Windows Logon
  Type values (2=Interactive, 3=Network, 4=Batch, 5=Service, 7=Unlock,
  8=NetworkCleartext, 9=NewCredentials, 10=RemoteInteractive,
  11=CachedInteractive, etc.), seen in the `Logon Type` field of 16
  logon-related Security events (4624, 4625, 4634, 4647, 4648, 4649, 4675,
  4779, 4800–4803, 4964, 5378, 5632, 5633).
- `data/reference/ip_protocol_numbers.csv` / `.json` — the 150 assigned
  IANA IP protocol numbers (1=ICMP, 6=TCP, 17=UDP, etc.), seen in the
  `Protocol` field of 67 IPsec and Windows Firewall events (4709–4712,
  4944–4958, 5031, 5040–5048, 5140, 5150–5159, and the 5440–5477 range).
  Sourced from nmap's `nmap-protocols` data file (itself a redistribution
  of the IANA protocol-numbers registry).
- `data/reference/nps_reason_codes.csv` / `.json` — the 94 Network Policy
  Server (RADIUS) reason codes, each with its `IAS_*` symbolic name where
  documented and Microsoft's full description, seen in the `Reason Code`
  field of NPS events 6272–6280. Sourced from a community PowerShell
  script that transcribed Microsoft's NPS Reason Codes documentation.
- `data/reference/disconnect_reason_codes_event40.csv` — RDS client
  disconnect reason codes seen in Event ID 40
  (`TerminalServices-LocalSessionManager`).
- `data/reference/sharepoint_audit_event_types.csv` — SharePoint audit log
  event type codes. These use a separate numbering scheme from Windows
  Event Log IDs and are kept out of the main catalogue to avoid collisions.
- `data/reference/mitre_attack_mapping.csv` / `.json` — the full MITRE
  ATT&CK technique ↔ Security-log Event ID mapping, one row per
  `(technique_id, audit_category, audit_sub_category, event_id)`
  combination: 1,417 associations across 390 ATT&CK techniques, each with
  its technique name, tactic(s), and the Windows audit category/subcategory
  that generates the event. This is the source for `mitre_techniques` on
  Security-log rows in the main catalogue, and is browsable in full
  (searchable by technique ID, technique name, tactic, or event ID) on the
  web lookup page's Reference tables tab — the main catalogue's detail view
  truncates high-fan-out events and links here for the rest.
- `docs/event-log-operations.md` — PowerShell / `wevtutil` snippets for
  querying, exporting, and clearing event logs, including a working example
  for auditing user account creation (Event ID 4720) across all domain
  controllers.
- `docs/audit-configuration-guide.md` — how to configure Windows/AD to
  actually collect each event: the Advanced Audit Policy Configuration (or
  registry) path to enable, step-by-step instructions, and the event IDs
  each setting produces.

## Web lookup

`index.html` is a self-contained (no build step, no external requests)
lookup page: search all 4,737 events by ID or keyword; filter by Log or
Category via searchable multi-select comboboxes (logs grouped by provider
family, e.g. all `Microsoft-Windows-AppLocker/*` variants collapse under
one header — this replaced a flat 188-button chip row and a 189-option
dropdown, which stopped being usable once the catalogue grew past ~40
logs); toggle to show only ASD/ACSC priority logs; active filters surface
as removable chips above the results. View full detail — description,
sample log text, MITRE ATT&CK mapping, Splunk CIM data model mapping, and
how-to-collect configuration steps — plus a Reference tables tab covering
15 code/lookup tables (NTLM and Kerberos error/result codes, Kerberos
encryption/pre-auth/ticket-option codes, Logon Type, IP protocol numbers,
NPS reason codes, RDS disconnect codes, SharePoint audit types, the raw
audit policy matrix, the MITRE ATT&CK mapping, the full NTSTATUS
reference, the Windows `%%` message-token table, and the Splunk CIM data
model reference). A single search box at the top of the tab filters
every one of the 15 tables at once — matching sections expand and show
only their matching rows, non-matching sections
disappear entirely (nav pills included), and clearing the box returns
everything to its default collapsed state; a sticky jump-nav next to the
search box lists all 15 with live row counts and scrolls straight to any
one of them, switching back to plain browse mode (clearing the search) as
it does — added once the tab grew past a handful of tables and scrolling
to find one stopped being practical. Every table (both on the Reference
tab and inline on an event's detail view) is also height-capped with its
own internal scroll and a sticky header row, so a single 1,795-row table
can't push the rest of the page — or, on events like 4768 that pull in
four Kerberos tables at once, the whole detail view — out to an
unreasonable length. All 15 Reference tables collapse into an accordion
by default (one click to expand, or the global search auto-expands
whichever sections actually match) so the tab itself opens as a
single-screen list of headings instead of every table rendered open at
once. Open it directly in a browser.

## Source

Extracted from a TiddlyWiki 5 export ("MSServer" notebook) covering Windows
Server administration topics. Only the Event Log / Event ID related tiddlers
were used to build this catalogue.

WebAuthn events were cross-checked against the real
`Microsoft-Windows-WebAuthN` ETW provider manifest (event IDs, symbols, and
field names verified, not guessed). Events added from the ASD/ACSC SIEM
ingestion guidance carry that document's exact category/event-ID pairings;
a handful of low-confidence entries (exact log channel not independently
corroborated — e.g. the two "Kerberos" events 4678/4679, and the log
channel split for 3033/3063) say so explicitly in their `reference` field.

Also cross-referenced against Microsoft's "Appendix L: Events to Monitor"
(fetched from the public `MicrosoftDocs/windowsserverdocs` GitHub mirror)
and Graylog's "Critical Windows Event IDs to Monitor" — both were almost
entirely already covered (both draw on the same underlying "Monitoring
Active Directory for Signs of Compromise" reference as the ASD guidance);
the genuinely new additions were IPsec/OCSP Responder Service Security-log
events, Netlogon secure-channel hardening events (Zerologon, CVE-2020-1472),
the classic "previous shutdown was unexpected" event, BitLocker volume
encryption/decryption/conversion events, and a Windows Time Service event
relevant to detecting clock-manipulation attacks.

Also cross-referenced against an uploaded "Windows Event ID Catalogue"
reference spreadsheet (provider/channel/event ID/description/level/MITRE
ATT&CK technique/collection-priority schema). ~40% of its 339 rows were
already covered; the rest — full Sysmon event ID coverage (1-29), Windows
Defender/Operational events, further AppLocker/Code Integrity/DNS-Client/
PowerShell/Task Scheduler events, Windows Update and Service Control
Manager System-log events, and a handful of same-numbered-but-different-
channel events (e.g. Sysmon's own 21-25 vs. Terminal Services' 21-25) —
were added, carrying that source's MITRE ATT&CK mappings where provided.

Also cross-referenced against NSA's `Event-Forwarding-Guidance`
(`Events/RecommendedEvents.csv` on GitHub, the companion dataset to NSA's
"Spotting the Adversary with Windows Event Log Monitoring"). About 55% of
its 205 individual event IDs were already covered; the rest opened up
several new log channels not previously in the catalogue — WLAN-AutoConfig,
CAPI2 (certificate chain building), NetworkProfile, TerminalServices-
RDPClient, USB-USBHUB3-Analytic, Kernel-PnP device configuration, LSA/
Operational, CertificationAuthority, RemoteAccess (RRAS/RADIUS), and
Application-Experience/Program-Inventory — plus boot/shutdown Kernel-
General events, Windows Firewall rule-change events, and further Windows
Defender and Windows Update failure events. A few NSA rows that
duplicated an event ID already covered by another source, but with a
generic or mismatched label (e.g. "Exception Raised" for what are
actually distinct PowerShell script-block-logging events already
correctly described), were treated as a labeling artifact and skipped in
favor of the existing, more specific entry.

Finally, cross-checked against a broader set of sources: **Microsoft's
official Advanced Audit Policy Configuration reference** (used to bring
`audit_policy_matrix.csv` to full coverage of all ~61 official
subcategories — added the 6 that were missing: Audit PNP Activity, Audit
Token Right Adjustment, Audit User / Device Claims, Audit Group
Membership, Audit Removable Storage, and Audit Central Access Policy
Staging, including two genuinely new events, 4626 and 4818, and
correcting a miscategorized 4703); **DISA's Windows STIG** (confirmed it
mandates Success/Failure settings for a subset of that same official
subcategory list rather than introducing separate event IDs, so no
additional events were needed); **community Sysmon configs**
(SwiftOnSecurity, Olaf Hartong — confirmed full coverage of the fixed
Sysmon 1-29 schema, no new IDs); and a bounded sample of **Splunk
Security Content (ESCU)** detections (GitHub code search and
research.splunk.com were both inaccessible in this environment without
repository approval, so this was a representative sample rather than the
full ~400-detection corpus — every EventCode found was already covered).

**NIST SP 800-53 AU controls** and **MITRE ATT&CK** aren't event-ID lists,
so instead of a gap-fill pass they were added as enrichment: the
`nist_800_53_au` field (see above) and an expanded `mitre_techniques`
pass covering ~85 additional clearly technique-relevant events (logon,
account/group management, Kerberos ticket operations, process/service/
scheduled-task creation, AppLocker/Code Integrity blocks, WMI activity,
PowerShell script-block logging, Zerologon-hardening, log clearing, and
several others) — left blank on purely diagnostic/operational events
(transport-layer detail, database internals, DHCP/DNS configuration, and
similar) where a technique mapping would be a stretch.

Subsequently cross-checked against a **comprehensive MITRE ATT&CK ↔
Windows Security Event ID mapping dataset** (390 techniques, 48 distinct
Security-log events, 1,417 technique–event associations in total) — this
superseded the earlier, narrower `mitre_techniques` values on the 48
affected events with the full technique list per event, and the complete
dataset was added as a new reference table,
`data/reference/mitre_attack_mapping.csv` / `.json`, since several events
(e.g. 4688 Process Creation → 286 techniques) map to far more techniques
than fit usefully in a single catalogue field. The web lookup page's
detail view shows the first 10 techniques for such events with a link
through to the full, searchable reference table rather than truncating
silently.

Finally, added a **`field_schema`** for every event in the catalogue: a
parser walks each event's own `sample` text (the header block, the
free-text description, then the event's `Key: Value` / `Key = Value`
fields — flat or nested under a `GroupName:` block, e.g. Security's
`Subject:` / `New Logon:`) and infers a type per field from its example
value (`sid`, `hex`, `guid`, `ip`, `path`, `principal`, `integer`, `enum`,
`list<string>`, or `string`). Initially built for just the 212
`acsc_priority_log` events, then extended to all 4,737: doing so surfaced
one gap the narrower pass hadn't hit — several bulk ETW `template`
messages state their fields as a run of `Label: {Placeholder}` lines
straight after the description sentence, with no blank-line separator —
so the parser's description/fields boundary detection was generalized to
recognize that shape too (a description line is only treated as a real
field once it looks like `Key: value`, isn't the line immediately after
`Description:`, and its value isn't full prose), which is what lets
events like `Microsoft-Windows-Security-Audit-Configuration-Client`'s 105
correctly break out `display_name` / `gpo_id` / `sysvol_path` instead of
folding them all into one description string. This is best-effort
structure extraction from the catalogue's own example data, not a
reference to Microsoft's authoritative event schema — useful for seeing
at a glance what a given event's `EventData` actually looks like without
reading the full rendered sample, but not a substitute for the real
schema when building a parser against live events.

Finally, added `group_policy_path` (see above) for events whose log isn't
driven by the Advanced Audit Policy system: went through every log with
no `how_to_collect` value (most of the bulk ETW import — 188 logs in
total needed checking) and, for the subset with a well-established native
Windows GPO path I could point to with confidence (AppLocker, BitLocker,
Windows Defender, Code Integrity/Device Guard, Windows Firewall with
Advanced Security, WinRM, Remote Desktop Services — session host and
client separately, NTLM auditing, Windows Hello for Business, certificate
auto-enrollment, Windows Update, UAC, Smart Card, and Application
Compatibility), added it — 1,362 events across 56 logs. Left
blank everywhere else on purpose: most Diagnostic/Debug/Analytic/Trace
ETW channels in this catalogue are enabled per-channel via `wevtutil`
or Event Viewer rather than a discoverable Group Policy ADMX setting, and
a wrong GPO path in a reference catalogue is worse than a missing one.

## Bulk ETW manifest import

A full Windows Server 2019 (1809, build 17763.1457) ETW event manifest
export — 45,958 event definitions across 813 providers, covering every
registered ETW provider on the system, not just security-relevant ones —
was cross-referenced and partially ingested. Given the scale (roughly 55x
the size of the curated catalogue at the time), the import was bounded to
security/audit-relevant channels only, identified by provider/channel name
(NTLM, Kerberos, Windows Hello for Business, Group Policy, WinRM, DHCP
Client, LDAP Client, Winlogon, UAC, Credential/Device Guard, IPsec,
Terminal Services variants, Smart Card, DPAPI, Hyper-V security-relevant
channels, and more) — adding 2,709 new events across ~130 new log
channels. Excluded: ~700 non-security providers (codecs, shell UI,
hardware/driver diagnostics, etc.), ~600 pure-ETW-trace events with no
Windows Event Log channel (not viewable in Event Viewer), and a handful
of rows whose channel name in the export was a generic placeholder
("Operational", "Admin", "Debug") rather than a real channel path.

The same treatment was applied to a second manifest export, this time
from Windows 11 24H2 Pro (build 26100.1742) — 52,405 events across 870
providers. The same security-adjacent channel filter added a further
1,198 new events (deduplicated against everything already in the
catalogue, including the Server 2019 import): full coverage of Windows
11-era security surfaces like WebAuthN, Windows Hello for Business
(including its Debug channel), BitLocker (encryption/decryption
lifecycle events previously missing), WLAN-AutoConfig diagnostics,
Privacy-Auditing, and Hyper-V VID admin/analytic channels. One channel
name collision was caught and fixed: the export truncated
`Microsoft-Windows-BitLocker-API`'s channel to the bare, ambiguous name
"Management" — renamed to `Microsoft-Windows-BitLocker-API/Management`
to avoid colliding with any other provider that might use the same
generic channel label in a future import.

These rows use `sample_type: template` — the manifest's own message
string, reformatted with the header fields and a best-effort line-break
fix for a source data quality issue (the export had stripped the original
message template's line breaks, causing segments to visually run
together; fixed by inserting a break wherever a placeholder or
punctuation mark was immediately followed by a capital letter). Unlike
the curated entries, these have no `how_to_collect`, `mitre_techniques`,
`nist_800_53_au`, or `acsc_priority_log` mapping — that enrichment was
done deliberately for the smaller curated set and hasn't been extended to
this bulk import.
