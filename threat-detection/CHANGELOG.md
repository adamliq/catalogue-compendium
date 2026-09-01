# Changelog

All notable changes to this project are documented here. Versioning
follows [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`):

- **MAJOR** — breaking changes (an entry ID scheme changes, a schema
  drops/renames a required field, a data file's shape changes in a way
  that breaks an existing integration).
- **MINOR** — new catalogues, new platforms, new pages/features (a new
  detection catalogue, a new MITRE ATT&CK Coverage platform, a new
  validation catalogue, a new tab/view).
- **PATCH** — bug fixes, data corrections, and documentation-only
  updates that don't add or remove content.

The current version lives in [`VERSION`](VERSION) (the single source of
truth — `tools/build.py` reads it and stamps it into the page header)
and is echoed near the top of [`README.md`](README.md).

## [1.2.0] - 2026-08-26

### Added
- Fifth validation catalogue: Windows Privileged Admin Action Validation
  (`data/windows-privileged-admin-validations.json`, 146 entries,
  `WIN-PRIV-001..146`), platform `Windows Endpoint` (matching the same
  component value `data/windows-endpoint-detections.json` already uses
  for this telemetry domain), sharing the Validations page with the
  RHEL, FortiGate, Cisco SD-WAN, and RHEL IdM/IPA catalogues.
- A fifth `VALIDATION_TELEMETRY_GROUPS` entry in the Validations
  detail-panel renderer for this catalogue's Windows Event Log fields
  (event ID/channel/provider, logon type, subject/target account,
  process/image, object path, command line).

### Notes
- MITRE ATT&CK mapping resolved live against the current `mitre/cti`
  STIX corpus, same discipline as the other four catalogues, with the
  new wrinkle that some rows cite two technique IDs in one cell. The
  conversion now extracts every technique ID present and resolves each
  independently, deduping by the *current* resolved ID -- correctly
  collapsing a cited old-ID/new-ID pair (`T1060 / T1547.001`, where
  `T1060` itself just redirects to `T1547.001`) into one technique,
  while keeping a cited pair that redirects to two different current
  techniques (`T1070.001` -> `T1685.005` and `T1562.002` -> `T1685.001`)
  as two. 126/146 entries (86%, the highest resolution rate of the five
  catalogues) resolved at least one currently-valid technique; 5 entries
  resolved two.

## [1.1.1] - 2026-08-26

### Added
- A **Companion Tools** dropdown menu in the page header, linking to
  other tools from the same author — currently [Splunk Taxonomy — My
  Tools](https://adamliq.github.io/Splunk_Taxonomy/#my-tools). Plain
  dropdown (not the shared overlay modal), closes on outside click or
  Escape.

## [1.1.0] - 2026-08-26

### Added
- Fourth validation catalogue: RHEL IdM/IPA Privileged Admin Action
  Validation (`data/rhel-ipa-privileged-admin-validations.json`, 139
  entries, `IPA-PRIV-001..139`), platform `IdM/IPA/FreeIPA`, sharing the
  Validations page with the RHEL, FortiGate, and Cisco SD-WAN
  catalogues. Distinct from the existing RHEL Privileged Action
  catalogue: this one covers IPA/IdM (FreeIPA) directory/identity
  management actions (users, HBAC/sudo rules, Kerberos, certificates,
  DNS, trusts, replication topology) rather than general RHEL OS-level
  actions.
- A fourth `VALIDATION_TELEMETRY_GROUPS` entry in the Validations
  detail-panel renderer for this catalogue's IPA-specific telemetry
  fields (LDAP target, IPA command family, admin/principal identity).

### Notes
- MITRE ATT&CK mapping resolved live against the current `mitre/cti`
  STIX corpus, same discipline as the other three catalogues: the
  pre-split "Defense Evasion" tactic-name issue recurred, and the
  `T1562.001` revoked-technique redirect (`T1685`) reappeared -- this
  technique family's renumbering has now been corrected five times
  across this library's history. Also caught a stale technique name in
  the workbook (`T1484.002` labeled "Domain Trust Modification"; MITRE's
  current name is "Trust Modification"), preserved in the entry's note
  field. 92/139 entries (66%) resolved a currently-valid technique.

## [1.0.0] - 2026-08-26

Initial versioned baseline. This release starts version tracking for
the library going forward — it does not retroactively assign version
numbers to the project's prior history, which predates this scheme.
What's included as of this baseline:

- Fourteen detection catalogues sharing the Detections page: ESXi/Splunk
  SPL, VMware Aria Operations for Logs, Red Hat (RHEL/IdM/IPA/FreeIPA/
  AAP/Satellite), Fortinet Security Fabric, Dell iDRAC, HPE iLO, Windows
  DHCP Server, Windows RDP, VMware Cloud Foundation, Splunk Platform,
  Active Directory, Splunk Security Content (ESCU), Cisco Network
  Device, and Windows Endpoint — 4,017 detections total.
- An ATT&CK Coverage browser spanning ten MITRE ATT&CK platforms: ESXi,
  Windows, Cisco, SaaS, Identity Provider, Containers, Linux, IaaS,
  Office Suite, and macOS.
- A Heat Coverage tab (technique × tactic matrix shaded by detection
  density across the whole library).
- A Validations page holding this library's first validation
  catalogues — a distinct content type from the detection catalogues
  (see [`docs/validations.md`](docs/validations.md)): RHEL Privileged
  Action (204 entries), FortiGate Privileged Admin Action (146
  entries), and Cisco SD-WAN Privileged Admin Action (145 entries) — 495
  validation entries total, sharing one page via a `platform` filter
  facet.
