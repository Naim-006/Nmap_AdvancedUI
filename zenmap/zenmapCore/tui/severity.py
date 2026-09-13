#!/usr/bin/env python3
"""Heuristic severity and risk level tagging for Nmap service detection."""

import re
from typing import Optional, Tuple, Dict, List

# Severity levels
CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFO = "INFO"

SEVERITY_ORDER = [CRITICAL, HIGH, MEDIUM, LOW, INFO]
SEVERITY_RANK = {
    INFO: 0,
    LOW: 1,
    MEDIUM: 2,
    HIGH: 3,
    CRITICAL: 4,
}

# Local reference table for common obviously-risky signatures.
# Kept concise, explicit, and easy to audit/edit.
# Each entry is: (regex pattern, severity level)
LOCAL_REFERENCE_TABLE = [
    # Explicit Critical vulnerabilities / backdoors
    (r"vsftpd\s+2\.3\.4", CRITICAL),
    (r"smb-vuln-ms17-010|ms17-010.*vulnerable", CRITICAL),
    (r"cve-(?:199\d|20\d{2})-\d{4,7}.*?(?:9\.[0-9]|10\.0)", CRITICAL),

    # High severity: Outdated critical daemons, remote exec, clear unauth DBs
    (r"proftpd\s+1\.3\.(?:3[a-c]|5)", HIGH),
    (r"mysql\s+5\.(?:[0-4]\.|5\.[0-9]\b)", HIGH),
    (r"\brlogin\b|\brsh\b|\brexec\b", HIGH),
    (r"ssl-heartbleed.*vulnerable", HIGH),
    (r"openssh\s+[1-4]\.", HIGH),
    (r"cve-(?:199\d|20\d{2})-\d{4,7}.*?(?:7\.[0-9]|8\.[0-9])", HIGH),

    # Medium severity: Plaintext administrative/auth protocols or older web servers
    (r"\btelnet\b", MEDIUM),
    (r"\bvnc\b", MEDIUM),
    (r"\bsnmp\b", MEDIUM),
    (r"\bmongodb\b|\bredis\b", MEDIUM),
    (r"apache(?:\s+httpd)?\s+2\.(?:0|2|4\.41|4\.49)\b", MEDIUM),
    (r"\bhttp\b(?!s)", MEDIUM),
    (r"cve-(?:199\d|20\d{2})-\d{4,7}.*?(?:4\.[0-9]|5\.[0-9]|6\.[0-9])", MEDIUM),
    (r"vulnerable", MEDIUM),

    # Low severity: Standard secure/modern services
    (r"\bhttps\b|\bssl\b", LOW),
    (r"\bssh\b|openssh", LOW),
    (r"\bftp\b", LOW),
    (r"\bdomain\b|\bdns\b", LOW),
    (r"\bntp\b", LOW),
    (r"\bsmtp\b|\bpop3\b|\bimap\b", LOW),
    (r"\bnginx\b", LOW),
]

PORT_LINE_REGEX = re.compile(
    r"^(\d+/(?:tcp|udp|sctp))\s+(open\S*)\s+([^\s]+)(?:\s+(.*))?$"
)


def supports_service_tagging(command_args: List[str]) -> bool:
    """Returns True if the command includes service/version detection or vuln scripts."""
    for idx, arg in enumerate(command_args):
        if arg in ("-sV", "-A", "--version-all", "--version-light", "-sC"):
            return True
        if arg.startswith("-sV"):
            return True
        if "--script" in arg and ("vuln" in arg or "vulners" in arg or "default" in arg):
            return True
        if arg == "--script" and idx + 1 < len(command_args):
            next_arg = command_args[idx + 1]
            if "vuln" in next_arg or "vulners" in next_arg or "default" in next_arg:
                return True
    return False


def evaluate_service_severity(service_name: str, version_info: str = "") -> str:
    """Evaluates the heuristic severity for a given service and version text."""
    combined = f"{service_name} {version_info}".strip()

    # 1. Match against local reference table
    for pattern, severity in LOCAL_REFERENCE_TABLE:
        if re.search(pattern, combined, re.IGNORECASE):
            return severity

    # 2. Fallback to INFO for any unrecognized service
    return INFO


def tag_port_line(line: str) -> Tuple[str, Optional[str]]:
    """
    Inspects an Nmap output line. If it is an open port/service line,
    appends a heuristic severity tag (e.g. [LOW], [MEDIUM], [HIGH], [CRITICAL], [INFO])
    and returns (tagged_line, severity_level). Otherwise returns (original_line, None).
    """
    match = PORT_LINE_REGEX.match(line)
    if not match:
        return line, None

    port_proto = match.group(1)
    state = match.group(2)
    service = match.group(3)
    version = (match.group(4) or "").strip()

    # Only tag 'open' ports
    if not state.startswith("open"):
        return line, None

    # Don't re-tag if already tagged
    if any(f"[{lvl}]" in line for lvl in SEVERITY_ORDER):
        return line, None

    severity = evaluate_service_severity(service, version)
    tag = f"[{severity}]"

    # Clean alignment: format with padding
    line_trimmed = line.rstrip()
    tagged_line = f"{line_trimmed}  {tag}"
    return tagged_line, severity


CVE_CVSS_REGEX = re.compile(
    r"(?:cve-(?:199\d|20\d{2})-\d{4,7}|ssv:\d+)[:\s]+([0-9]+(?:\.[0-9]+)?)\b",
    re.IGNORECASE,
)
VULN_STATE_REGEX = re.compile(
    r"\b(?:State:\s*VULNERABLE|Risk factor:\s*(\w+))\b",
    re.IGNORECASE,
)


def parse_script_vuln_severity(line: str) -> Optional[str]:
    """Inspects an NSE script line for CVSS scores or vulnerability indicators."""
    cvss_match = CVE_CVSS_REGEX.search(line)
    if cvss_match:
        try:
            score = float(cvss_match.group(1))
            if score >= 9.0:
                return CRITICAL
            elif score >= 7.0:
                return HIGH
            elif score >= 4.0:
                return MEDIUM
            else:
                return LOW
        except ValueError:
            pass

    vuln_match = VULN_STATE_REGEX.search(line)
    if vuln_match:
        risk = (vuln_match.group(1) or "").upper()
        if "CRIT" in risk:
            return CRITICAL
        elif "HIGH" in risk:
            return HIGH
        elif "MED" in risk:
            return MEDIUM
        elif "LOW" in risk:
            return LOW
        return HIGH
    return None

