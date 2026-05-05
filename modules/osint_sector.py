"""
cyberm4fia-scanner - Sector-Specific OSINT Recon
Targeted reconnaissance patterns for healthcare, finance, ICS/SCADA,
IoT, and government sectors with protocol-specific probes.

CAUTION: ICS/SCADA probes are passive-only (no active TCP connection).
"""

import re
from urllib.parse import urlparse

from utils.colors import log_info, log_success, log_warning, log_error, Colors
from utils.request import smart_request, ScanExceptions


SECTOR_DORKS = {
    "healthcare": {
        "label": "Healthcare",
        "dorks": [
            'site:{domain} filetype:pdf "HIPAA"',
            'site:{domain} filetype:pdf "PHI" OR "patient records"',
            'site:{domain} filetype:xlsx "patient"',
            'site:{domain} "DICOM" OR "HL7" OR "ICD-10"',
            'site:{domain} "EHR" OR "EMR" OR "PACS"',
            'site:{domain} inurl:"/FHIR/" OR inurl:"/fhir/"',
            'site:{domain} "HIPAA" AND "compliance"',
            'site:{domain} intitle:"Epic" OR intitle:"Cerner"',
            'site:{domain} "patient portal" OR "provider portal"',
        ],
        "protocols": {
            "DICOM": {"port": 11112, "alt_port": 4242, "severity": "CRITICAL"},
            "HL7": {"port": 2575, "severity": "HIGH"},
        },
        "tech_indicators": [
            r"(?i)epic(.{0,10})systems",
            r"(?i)cerner(.{0,10})corporation",
            r"(?i)allscripts|meditech|athenahealth|nextgen|eclinicalworks",
        ],
    },
    "finance": {
        "label": "Finance",
        "dorks": [
            'site:{domain} filetype:pdf "SOC" OR "SOC2" OR "audit report"',
            'site:{domain} filetype:pdf "Form 10-K" OR "Form 10-Q"',
            'site:{domain} filetype:xlsx "earnings" OR "financial statement"',
            'site:{domain} "SWIFT" OR "BIC" OR "IBAN"',
            'site:{domain} "PCI" OR "PCI DSS" OR "SOX" OR "GLBA"',
            'site:{domain} "wire transfer" OR "ACH" OR "SEPA"',
            'site:{domain} inurl:"/trading/" OR inurl:"/wealth/"',
            'site:{domain} "compliance" AND "KYC" OR "AML"',
            'site:{domain} intitle:"Temenos" OR intitle:"Finacle" OR intitle:"FIS"',
        ],
        "protocols": {
            "FIX": {"port": 9876, "severity": "CRITICAL"},
            "SWIFT": {"port": 8080, "severity": "CRITICAL"},
        },
        "tech_indicators": [
            r"(?i)temenos(.{0,10})t24",
            r"(?i)finacle|fiserv|jack.?henry",
            r"(?i)bloomberg(.{0,10})terminal",
            r"(?i)fidessa|charles.?river|eze.?software|aladdin",
        ],
    },
    "ics_scada": {
        "label": "ICS/SCADA/OT",
        "dorks": [
            'site:{domain} "PLC" OR "SCADA" OR "DCS" OR "HMI"',
            'site:{domain} "Modbus" OR "BACnet" OR "DNP3" OR "EtherNet/IP"',
            'site:{domain} "Siemens S7" OR "Allen Bradley" OR "Rockwell"',
            'site:{domain} "control system" OR "process control"',
            'site:{domain} filetype:pdf "ICS" OR "OT" OR "critical infrastructure"',
            'site:{domain} "NERC CIP" OR "IEC 62443"',
            'site:{domain} "Tridium" OR "Niagara" OR "Honeywell EBI"',
        ],
        "protocols": {
            "Modbus": {"port": 502, "severity": "CRITICAL"},
            "BACnet": {"port": 47808, "severity": "CRITICAL"},
            "Siemens S7": {"port": 102, "severity": "CRITICAL"},
            "DNP3": {"port": 20000, "severity": "CRITICAL"},
            "EtherNet/IP": {"port": 44818, "severity": "HIGH"},
        },
        "tech_indicators": [
            r"(?i)siemens(.{0,10})simatic|s7-1200|s7-1500",
            r"(?i)tridium(.{0,10})niagara",
            r"(?i)honeywell(.{0,10})ebi|experion",
            r"(?i)ge(.{0,10})proficy|ifix",
            r"(?i)rockwell(.{0,10})automation|allen.?bradley",
        ],
        "passive_only": True,
    },
    "iot": {
        "label": "IoT/Consumer/SOHO",
        "dorks": [
            'site:{domain} "MQTT" OR "CoAP" OR "UPnP"',
            'site:{domain} "firmware" OR "embedded" OR "microcontroller"',
            'site:{domain} "Hikvision" OR "Dahua" OR "Axis Communications"',
            'site:{domain} "smart home" OR "connected device"',
            'site:{domain} "RTSP" OR "streaming" OR "surveillance"',
        ],
        "protocols": {
            "MQTT": {"port": 1883, "alt_port": 8883, "severity": "HIGH"},
            "CoAP": {"port": 5683, "severity": "MEDIUM"},
            "UPnP/SSDP": {"port": 1900, "severity": "MEDIUM"},
        },
        "tech_indicators": [
            r"(?i)hikvision|dahua|axis(.{0,10})communications",
            r"(?i)esp8266|esp32|arduino|raspberry.?pi",
            r"(?i)mqtt(.{0,10})broker|mosquitto",
        ],
    },
    "government": {
        "label": "Government/Public Sector",
        "dorks": [
            'site:{domain} filetype:pdf "FOUO" OR "controlled unclassified" OR "CUI"',
            'site:{domain} filetype:pdf "personnel security" OR "clearance"',
            'site:{domain} "FedRAMP" OR "FISMA" OR "NIST 800-53"',
            'site:{domain} "FOIA" OR "public records request"',
            'site:{domain} "procurement" OR "RFQ" OR "RFP" OR "solicitation"',
            'site:{domain} "contract award" OR "vendor of record"',
            'site:{domain} inurl:".gov" OR inurl:".mil"',
        ],
        "protocols": {},
        "tech_indicators": [
            r"(?i)fedramp|fisma|cmmc",
            r"(?i)nist(.{0,10})800-53|800-171",
            r"(?i)sam\.gov|usaspending|fpds",
        ],
    },
}


def _generate_sector_dorks(domain, sectors=None):
    dorks = {}
    if sectors is None:
        sectors = list(SECTOR_DORKS.keys())

    for sector_key in sectors:
        sector = SECTOR_DORKS.get(sector_key)
        if not sector:
            continue
        dorks[sector["label"]] = [
            tpl.format(domain=domain) for tpl in sector.get("dorks", [])
        ]
    return dorks


def _scan_body_indicators(body, sector):
    findings = []
    for indicator in sector.get("tech_indicators", []):
        matches = re.findall(indicator, body, re.IGNORECASE)
        if matches:
            findings.append({
                "type": "sector_indicator",
                "sector": sector["label"],
                "indicator": matches[0][:80] if isinstance(matches[0], str) else str(matches[0])[:80],
            })
    return findings


def scan_sector_osint(url, sectors=None, delay=0):
    """
    Sector-specific OSINT reconnaissance for the target.

    Generates sector-aware dorks, scans response bodies for sector-specific
    technology indicators, and catalogs relevant protocols.

    NOTE: ICS/SCADA protocol probing is passive-only by default — this module
    does NOT make active TCP connections to industrial protocols. It catalogs
    the protocol surfaces for operator awareness.

    Args:
        url: Target URL
        sectors: Optional list of sector keys to check
                   ['healthcare', 'finance', 'ics_scada', 'iot', 'government']
        delay: Request delay

    Returns:
        dict with keys: sector_dorks, sector_indicators, protocol_surfaces
    """
    parsed = urlparse(url)
    domain = parsed.hostname or ""
    if domain.startswith("www."):
        domain = domain[4:]

    if sectors is None:
        sectors = list(SECTOR_DORKS.keys())

    print(f"\n{Colors.BOLD}{Colors.CYAN}──── SECTOR-SPECIFIC OSINT ────{Colors.END}")
    log_info(f"Analyzing {domain} across {len(sectors)} sector(s)...")

    findings = []
    sector_dorks = {}
    protocol_surfaces = {}

    # Scan main page for sector tech indicators
    try:
        resp = smart_request("get", url, delay=delay, timeout=10)
        body = resp.text[:100000]

        for sector_key in sectors:
            sector = SECTOR_DORKS.get(sector_key)
            if not sector:
                continue

            # Body indicators
            indicators = _scan_body_indicators(body, sector)
            if indicators:
                findings.extend(indicators)
                log_success(f"[{sector['label']}] Found {len(indicators)} tech indicator(s)")

            # Generate dorks
            sector_dorks[sector["label"]] = [
                tpl.format(domain=domain) for tpl in sector.get("dorks", [])
            ]

            # Catalog protocols (passive — no active probe)
            protocols = sector.get("protocols", {})
            if protocols:
                protocol_surfaces[sector["label"]] = []
                for proto_name, proto_info in protocols.items():
                    entry = {
                        "protocol": proto_name,
                        "port": proto_info["port"],
                        "severity": proto_info["severity"],
                    }
                    if "alt_port" in proto_info:
                        entry["alt_port"] = proto_info["alt_port"]
                    protocol_surfaces[sector["label"]].append(entry)

                    if sector.get("passive_only"):
                        log_info(
                            f"  [{sector['label']}] {proto_name} (port {proto_info['port']}) "
                            f"— flagged for operator awareness (passive only)"
                        )
                    else:
                        log_info(
                            f"  [{sector['label']}] {proto_name} (port {proto_info['port']}) "
                            f"— severity: {proto_info['severity']}"
                        )

    except ScanExceptions as e:
        log_error(f"Sector OSINT scan failed: {e}")

    # Summary
    total_indicators = len(findings)
    log_success(
        f"Sector OSINT complete. {total_indicators} tech indicator(s) across "
        f"{len(sector_dorks)} sector(s), {len(protocol_surfaces)} protocol surface(s) cataloged."
    )

    # Print sector dorks
    print(f"\n{Colors.BOLD}[*] Sector-Specific Dorks{Colors.END}")
    for sector_label, dorks in sector_dorks.items():
        print(f"  {Colors.CYAN}[{sector_label}]{Colors.END}")
        for dork in dorks[:3]:
            print(f"    {Colors.GREY}{dork}{Colors.END}")
        if len(dorks) > 3:
            print(f"    {Colors.DIM}... +{len(dorks) - 3} more{Colors.END}")

    print(f"\n{Colors.BOLD}{Colors.CYAN}──── SECTOR OSINT COMPLETE ────{Colors.END}\n")

    return {
        "domain": domain,
        "sectors_analyzed": sectors,
        "sector_dorks": sector_dorks,
        "indicators": findings,
        "protocol_surfaces": protocol_surfaces,
    }
