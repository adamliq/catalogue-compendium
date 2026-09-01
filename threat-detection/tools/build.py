#!/usr/bin/env python3
"""
Build index.html from VERSION + index.template.html + data/detections.json +
data/aria-detections.json + data/redhat-detections.json +
data/fortinet-detections.json + data/idrac-detections.json +
data/ilo-detections.json + data/dhcp-detections.json +
data/rdp-detections.json + data/vcf-detections.json +
data/splunk-detections.json + data/ad-detections.json +
data/splunk-escu-detections.json + data/cisco-detections.json +
data/windows-endpoint-detections.json +
data/rhel-privileged-action-validations.json +
data/fortigate-privileged-admin-validations.json +
data/cisco-sdwan-privileged-admin-validations.json +
data/rhel-ipa-privileged-admin-validations.json +
data/windows-privileged-admin-validations.json.

index.html is the combined library: it embeds the ESXi/Splunk SPL, VMware
Aria Operations for Logs, Red Hat (RHEL/IdM/IPA/FreeIPA/AAP/Satellite),
Fortinet Security Fabric, Dell iDRAC, HPE iLO, Windows DHCP Server,
Windows RDP, VMware Cloud Foundation, Splunk Platform (Splunk Cloud &
Splunk Enterprise self-protection), Active Directory Domain Services,
Splunk Security Content (ESCU), Cisco Network Device (MITRE-gap-fill),
and Windows Endpoint (MITRE-gap-fill) Splunk SPL catalogues (all fourteen
share the Detections page), plus the RHEL Privileged Action, FortiGate
Privileged Admin Action, Cisco SD-WAN Privileged Admin Action, RHEL
IdM/IPA Privileged Admin Action, and Windows Privileged Admin Action
Validation catalogues -- a distinct content type on their own shared
Validations page, not detection catalogues (see docs/validations.md).
Run this after editing any data file (adding a new batch, fixing a
field, etc.) to regenerate the static, self-contained index.html that
GitHub Pages / file:// serves. Also stamps the version from VERSION
(single source of truth, semver -- see README.md's Versioning section
and CHANGELOG.md) into the page header; bump VERSION and add a
CHANGELOG.md entry before rebuilding when a batch warrants a version
bump.

Usage:
    python3 tools/build.py
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
VERSION_FILE = ROOT / "VERSION"
DATA_FILE = ROOT / "data" / "detections.json"
ARIA_DATA_FILE = ROOT / "data" / "aria-detections.json"
REDHAT_DATA_FILE = ROOT / "data" / "redhat-detections.json"
FORTINET_DATA_FILE = ROOT / "data" / "fortinet-detections.json"
IDRAC_DATA_FILE = ROOT / "data" / "idrac-detections.json"
ILO_DATA_FILE = ROOT / "data" / "ilo-detections.json"
DHCP_DATA_FILE = ROOT / "data" / "dhcp-detections.json"
RDP_DATA_FILE = ROOT / "data" / "rdp-detections.json"
VCF_DATA_FILE = ROOT / "data" / "vcf-detections.json"
SPLUNK_DATA_FILE = ROOT / "data" / "splunk-detections.json"
AD_DATA_FILE = ROOT / "data" / "ad-detections.json"
ESCU_DATA_FILE = ROOT / "data" / "splunk-escu-detections.json"
CISCO_DATA_FILE = ROOT / "data" / "cisco-detections.json"
WEND_DATA_FILE = ROOT / "data" / "windows-endpoint-detections.json"
VALIDATIONS_DATA_FILE = ROOT / "data" / "rhel-privileged-action-validations.json"
FGT_VALIDATIONS_DATA_FILE = ROOT / "data" / "fortigate-privileged-admin-validations.json"
CSDWAN_VALIDATIONS_DATA_FILE = ROOT / "data" / "cisco-sdwan-privileged-admin-validations.json"
IPA_VALIDATIONS_DATA_FILE = ROOT / "data" / "rhel-ipa-privileged-admin-validations.json"
WIN_VALIDATIONS_DATA_FILE = ROOT / "data" / "windows-privileged-admin-validations.json"
TEMPLATE_FILE = ROOT / "index.template.html"
OUTPUT_FILE = ROOT / "index.html"
MARKER = "__DETECTIONS_JSON__"
ARIA_MARKER = "__ARIA_DETECTIONS_JSON__"
REDHAT_MARKER = "__REDHAT_DETECTIONS_JSON__"
FORTINET_MARKER = "__FORTINET_DETECTIONS_JSON__"
IDRAC_MARKER = "__IDRAC_DETECTIONS_JSON__"
ILO_MARKER = "__ILO_DETECTIONS_JSON__"
DHCP_MARKER = "__DHCP_DETECTIONS_JSON__"
RDP_MARKER = "__RDP_DETECTIONS_JSON__"
VCF_MARKER = "__VCF_DETECTIONS_JSON__"
SPLUNK_MARKER = "__SPLUNK_DETECTIONS_JSON__"
AD_MARKER = "__AD_DETECTIONS_JSON__"
ESCU_MARKER = "__ESCU_DETECTIONS_JSON__"
CISCO_MARKER = "__CISCO_DETECTIONS_JSON__"
WEND_MARKER = "__WEND_DETECTIONS_JSON__"
VALIDATIONS_MARKER = "__RHEL_PRIV_VALIDATIONS_JSON__"
FGT_VALIDATIONS_MARKER = "__FGT_PRIV_VALIDATIONS_JSON__"
CSDWAN_VALIDATIONS_MARKER = "__CSDWAN_PRIV_VALIDATIONS_JSON__"
IPA_VALIDATIONS_MARKER = "__IPA_PRIV_VALIDATIONS_JSON__"
WIN_VALIDATIONS_MARKER = "__WIN_PRIV_VALIDATIONS_JSON__"
VERSION_MARKER = "__LIBRARY_VERSION__"


def check_ids(data, source_name):
    ids = [d["id"] for d in data]
    if len(ids) != len(set(ids)):
        seen = set()
        dupes = sorted({i for i in ids if i in seen or seen.add(i)})
        sys.exit(f"Duplicate detection id(s) in {source_name}: {dupes}")


def to_payload(data):
    payload = json.dumps(data, indent=2, ensure_ascii=False)
    # The payload sits inside a <script type="application/json"> element, so
    # only closing </script> sequences need escaping to stay well-formed HTML.
    return payload.replace("</script", "<\\/script")


def read_version():
    version = VERSION_FILE.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        sys.exit(f"VERSION file must contain a MAJOR.MINOR.PATCH string, got: {version!r}")
    return version


def main():
    version = read_version()

    data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    check_ids(data, DATA_FILE.name)

    aria_data = json.loads(ARIA_DATA_FILE.read_text(encoding="utf-8"))
    check_ids(aria_data, ARIA_DATA_FILE.name)

    redhat_data = json.loads(REDHAT_DATA_FILE.read_text(encoding="utf-8"))
    check_ids(redhat_data, REDHAT_DATA_FILE.name)

    fortinet_data = json.loads(FORTINET_DATA_FILE.read_text(encoding="utf-8"))
    check_ids(fortinet_data, FORTINET_DATA_FILE.name)

    idrac_data = json.loads(IDRAC_DATA_FILE.read_text(encoding="utf-8"))
    check_ids(idrac_data, IDRAC_DATA_FILE.name)

    ilo_data = json.loads(ILO_DATA_FILE.read_text(encoding="utf-8"))
    check_ids(ilo_data, ILO_DATA_FILE.name)

    dhcp_data = json.loads(DHCP_DATA_FILE.read_text(encoding="utf-8"))
    check_ids(dhcp_data, DHCP_DATA_FILE.name)

    rdp_data = json.loads(RDP_DATA_FILE.read_text(encoding="utf-8"))
    check_ids(rdp_data, RDP_DATA_FILE.name)

    vcf_data = json.loads(VCF_DATA_FILE.read_text(encoding="utf-8"))
    check_ids(vcf_data, VCF_DATA_FILE.name)

    splunk_data = json.loads(SPLUNK_DATA_FILE.read_text(encoding="utf-8"))
    check_ids(splunk_data, SPLUNK_DATA_FILE.name)

    ad_data = json.loads(AD_DATA_FILE.read_text(encoding="utf-8"))
    check_ids(ad_data, AD_DATA_FILE.name)

    escu_data = json.loads(ESCU_DATA_FILE.read_text(encoding="utf-8"))
    check_ids(escu_data, ESCU_DATA_FILE.name)

    cisco_data = json.loads(CISCO_DATA_FILE.read_text(encoding="utf-8"))
    check_ids(cisco_data, CISCO_DATA_FILE.name)

    wend_data = json.loads(WEND_DATA_FILE.read_text(encoding="utf-8"))
    check_ids(wend_data, WEND_DATA_FILE.name)

    validations_data = json.loads(VALIDATIONS_DATA_FILE.read_text(encoding="utf-8"))
    check_ids(validations_data, VALIDATIONS_DATA_FILE.name)

    fgt_validations_data = json.loads(FGT_VALIDATIONS_DATA_FILE.read_text(encoding="utf-8"))
    check_ids(fgt_validations_data, FGT_VALIDATIONS_DATA_FILE.name)

    csdwan_validations_data = json.loads(CSDWAN_VALIDATIONS_DATA_FILE.read_text(encoding="utf-8"))
    check_ids(csdwan_validations_data, CSDWAN_VALIDATIONS_DATA_FILE.name)

    ipa_validations_data = json.loads(IPA_VALIDATIONS_DATA_FILE.read_text(encoding="utf-8"))
    check_ids(ipa_validations_data, IPA_VALIDATIONS_DATA_FILE.name)

    win_validations_data = json.loads(WIN_VALIDATIONS_DATA_FILE.read_text(encoding="utf-8"))
    check_ids(win_validations_data, WIN_VALIDATIONS_DATA_FILE.name)

    all_ids = [
        d["id"]
        for d in data + aria_data + redhat_data + fortinet_data + idrac_data
        + ilo_data + dhcp_data + rdp_data + vcf_data + splunk_data + ad_data
        + escu_data + cisco_data + wend_data + validations_data + fgt_validations_data
        + csdwan_validations_data + ipa_validations_data + win_validations_data
    ]
    if len(all_ids) != len(set(all_ids)):
        seen = set()
        dupes = sorted({i for i in all_ids if i in seen or seen.add(i)})
        sys.exit(f"Duplicate detection id(s) across catalogues: {dupes}")

    template = TEMPLATE_FILE.read_text(encoding="utf-8")
    for marker in (
        MARKER, ARIA_MARKER, REDHAT_MARKER, FORTINET_MARKER, IDRAC_MARKER,
        ILO_MARKER, DHCP_MARKER, RDP_MARKER, VCF_MARKER, SPLUNK_MARKER,
        AD_MARKER, ESCU_MARKER, CISCO_MARKER, WEND_MARKER, VALIDATIONS_MARKER,
        FGT_VALIDATIONS_MARKER, CSDWAN_VALIDATIONS_MARKER, IPA_VALIDATIONS_MARKER,
        WIN_VALIDATIONS_MARKER, VERSION_MARKER,
    ):
        if marker not in template:
            sys.exit(f"Marker {marker} not found in {TEMPLATE_FILE.name}")

    output = (
        template.replace(MARKER, to_payload(data))
        .replace(ARIA_MARKER, to_payload(aria_data))
        .replace(REDHAT_MARKER, to_payload(redhat_data))
        .replace(FORTINET_MARKER, to_payload(fortinet_data))
        .replace(IDRAC_MARKER, to_payload(idrac_data))
        .replace(ILO_MARKER, to_payload(ilo_data))
        .replace(DHCP_MARKER, to_payload(dhcp_data))
        .replace(RDP_MARKER, to_payload(rdp_data))
        .replace(VCF_MARKER, to_payload(vcf_data))
        .replace(SPLUNK_MARKER, to_payload(splunk_data))
        .replace(AD_MARKER, to_payload(ad_data))
        .replace(ESCU_MARKER, to_payload(escu_data))
        .replace(CISCO_MARKER, to_payload(cisco_data))
        .replace(WEND_MARKER, to_payload(wend_data))
        .replace(VALIDATIONS_MARKER, to_payload(validations_data))
        .replace(FGT_VALIDATIONS_MARKER, to_payload(fgt_validations_data))
        .replace(CSDWAN_VALIDATIONS_MARKER, to_payload(csdwan_validations_data))
        .replace(IPA_VALIDATIONS_MARKER, to_payload(ipa_validations_data))
        .replace(WIN_VALIDATIONS_MARKER, to_payload(win_validations_data))
        .replace(VERSION_MARKER, version)
    )
    OUTPUT_FILE.write_text(output, encoding="utf-8")
    print(
        f"Built {OUTPUT_FILE.relative_to(ROOT)} (v{version}) from {len(data)} ESXi/Splunk SPL + "
        f"{len(aria_data)} Aria + {len(redhat_data)} Red Hat + {len(fortinet_data)} Fortinet + "
        f"{len(idrac_data)} Dell iDRAC + {len(ilo_data)} HPE iLO + {len(dhcp_data)} Windows DHCP + "
        f"{len(rdp_data)} Windows RDP + {len(vcf_data)} VMware Cloud Foundation + "
        f"{len(splunk_data)} Splunk Platform + {len(ad_data)} Active Directory + "
        f"{len(escu_data)} Splunk ESCU + {len(cisco_data)} Cisco Network Device + "
        f"{len(wend_data)} Windows Endpoint detection(s), plus "
        f"{len(validations_data)} RHEL Privileged Action, "
        f"{len(fgt_validations_data)} FortiGate Privileged Admin Action, "
        f"{len(csdwan_validations_data)} Cisco SD-WAN Privileged Admin Action, "
        f"{len(ipa_validations_data)} RHEL IdM/IPA Privileged Admin Action, and "
        f"{len(win_validations_data)} Windows Privileged Admin Action "
        f"Validation entries."
    )


if __name__ == "__main__":
    main()
