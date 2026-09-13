#!/usr/bin/env python3
"""Scan profile representations and definitions for the Nmap TUI."""

from typing import Optional, List


class ScanProfile:
    """Represents an Nmap scan profile selectable within the TUI."""

    def __init__(
        self,
        key: str,
        name: str,
        command_template: str,
        description: str,
        scan_type: str,
        flags: Optional[List[str]] = None,
    ):
        self.key = key
        self.name = name
        self.command_template = command_template
        self.description = description
        self.scan_type = scan_type  # e.g., 'quick', 'version', 'full', 'os', 'aggressive', 'udp', 'custom', 'file', 'history', 'exit'
        self.flags = flags if flags is not None else []

    def get_display_command(self, target: str = "") -> str:
        """Returns preview command formatted with target if present."""
        target_str = f" {target.strip()}" if target and target.strip() else ""
        if self.scan_type == "custom":
            return f"nmap <args>{target_str}"
        elif self.scan_type == "file":
            file_target = target.strip() if target and target.strip() else "<file>"
            return f"nmap -iL {file_target}"
        elif self.scan_type == "history":
            return "(view past scans)"
        elif self.scan_type == "exit":
            return "(quit application)"
        else:
            return f"{self.command_template}{target_str}"

    def __repr__(self) -> str:
        return f"<ScanProfile [{self.key}] {self.name}: {self.command_template}>"


def get_default_profiles() -> List[ScanProfile]:
    """Returns the 10 profiles matching the reference dashboard in exact order."""
    return [
        ScanProfile(
            key="1",
            name="Quick Scan",
            command_template="nmap -T4 -F",
            description="Fast scan using aggressive timing and top common ports.",
            scan_type="quick",
            flags=["-T4", "-F"],
        ),
        ScanProfile(
            key="2",
            name="Service & Version",
            command_template="nmap -sV",
            description="Detects service/version, tagged with a heuristic risk level.",
            scan_type="version",
            flags=["-sV"],
        ),
        ScanProfile(
            key="3",
            name="Full Port Scan",
            command_template="nmap -p-",
            description="Scan all 65,535 TCP ports for comprehensive network coverage.",
            scan_type="full",
            flags=["-p-"],
        ),
        ScanProfile(
            key="4",
            name="OS Detection",
            command_template="nmap -O",
            description="Identify target operating system using TCP/IP fingerprinting.",
            scan_type="os",
            flags=["-O"],
        ),
        ScanProfile(
            key="5",
            name="Aggressive Scan",
            command_template="nmap -A",
            description="Comprehensive scan enabling OS detection, version scan, scripts, and traceroute.",
            scan_type="aggressive",
            flags=["-A"],
        ),
        ScanProfile(
            key="6",
            name="UDP Scan",
            command_template="nmap -sU",
            description="Scan UDP ports for active services such as DNS, DHCP, and SNMP.",
            scan_type="udp",
            flags=["-sU"],
        ),
        ScanProfile(
            key="7",
            name="Custom Scan",
            command_template="nmap <custom>",
            description="User-defined scan with arbitrary custom Nmap arguments and options.",
            scan_type="custom",
            flags=[],
        ),
        ScanProfile(
            key="8",
            name="Scan from File",
            command_template="nmap -iL <file>",
            description="Read scan targets from an input file containing a list of hosts/networks.",
            scan_type="file",
            flags=["-iL"],
        ),
        ScanProfile(
            key="9",
            name="Scan History",
            command_template="(view past scans)",
            description="Browse past scan executions, commands, targets, timestamps, and outcomes.",
            scan_type="history",
            flags=[],
        ),
        ScanProfile(
            key="0",
            name="Exit",
            command_template="(quit application)",
            description="Close the NMAP Toolkit interactive dashboard and return to shell.",
            scan_type="exit",
            flags=[],
        ),
    ]
