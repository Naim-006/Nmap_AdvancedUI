#!/usr/bin/env python3
"""Command builder and target validator for Nmap TUI."""

import ipaddress
import os
import re
import shlex
import shutil
from typing import List, Tuple, Optional
from zenmapCore.tui.profiles import ScanProfile

# Hostname validation pattern (RFC 1123 compliant + localhost)
HOSTNAME_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)


class ValidationError(Exception):
    """Raised when target or argument validation fails."""
    pass


class CommandBuilder:
    """Builds safe Nmap argument lists and validates targets."""

    @staticmethod
    def find_nmap_binary() -> Optional[str]:
        """Locate the nmap binary on the system."""
        try:
            from zenmapCore.UmitConf import PathsConfig
            configured_path = PathsConfig().nmap_command_path
            resolved = shutil.which(configured_path)
            if resolved:
                return resolved
        except Exception:
            pass

        return shutil.which("nmap")

    @classmethod
    def validate_target(cls, target: str, is_file_scan: bool = False) -> Tuple[bool, str]:
        """Validates the scan target. Returns (is_valid, error_message)."""
        target = target.strip()
        if not target:
            return False, "Target cannot be empty. Please enter an IP, hostname, or domain."

        if is_file_scan:
            expanded = os.path.expanduser(target)
            if not os.path.exists(expanded):
                return False, f"Target file '{target}' does not exist."
            if not os.path.isfile(expanded):
                return False, f"Target '{target}' is not a regular file."
            if not os.access(expanded, os.R_OK):
                return False, f"Target file '{target}' is not readable."
            return True, ""

        # Check for multiple targets (whitespace-separated)
        targets = target.split()
        for t in targets:
            valid, err = cls._validate_single_target(t)
            if not valid:
                return False, err
        return True, ""

    @staticmethod
    def _validate_single_target(target: str) -> Tuple[bool, str]:
        # Strip potential IPv6 brackets
        clean = target.strip("[]")

        # Check if valid single IP
        try:
            ipaddress.ip_address(clean)
            return True, ""
        except ValueError:
            pass

        # Check if valid CIDR network
        try:
            ipaddress.ip_network(clean, strict=False)
            return True, ""
        except ValueError:
            pass

        # Check IPv4 range notation like 192.168.1.1-50 or 10.0.0-255.1
        parts = target.split(".")
        if len(parts) == 4:
            has_dash = any("-" in p for p in parts)
            valid_range = True
            for p in parts:
                if "-" in p:
                    subparts = p.split("-")
                    if len(subparts) == 2 and subparts[0].isdigit() and subparts[1].isdigit():
                        if not (0 <= int(subparts[0]) <= 255 and 0 <= int(subparts[1]) <= 255 and int(subparts[0]) <= int(subparts[1])):
                            valid_range = False
                            break
                    else:
                        valid_range = False
                        break
                elif p.isdigit():
                    if not (0 <= int(p) <= 255):
                        valid_range = False
                        break
                else:
                    valid_range = False
                    break
            if valid_range and has_dash:
                return True, ""
            if not valid_range and all(p.isdigit() or "-" in p for p in parts):
                return False, f"Invalid IP address octets in: '{target}'."

        # If it consists of 4 digit groups separated by dots, but wasn't valid IP, reject
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return False, f"Invalid IPv4 address: '{target}'."

        # Check valid domain / hostname / localhost
        if target.lower() == "localhost":
            return True, ""

        if HOSTNAME_REGEX.match(target):
            # TLD cannot be purely numeric
            tld = parts[-1]
            if not tld.isdigit():
                return True, ""

        return False, f"Invalid target specification: '{target}'. Must be IP, CIDR, or valid hostname."

    @classmethod
    def build_command(
        cls,
        profile: ScanProfile,
        target: str,
        custom_args: str = "",
    ) -> List[str]:
        """Constructs safe argument list for subprocess execution (no shell=True)."""
        binary = cls.find_nmap_binary() or "nmap"
        args = [binary]

        target_cleaned = target.strip()

        if profile.scan_type == "custom":
            # Safely parse user arguments with shlex
            if custom_args.strip():
                try:
                    parsed_custom = shlex.split(custom_args.strip())
                    args.extend(parsed_custom)
                except ValueError as e:
                    raise ValidationError(f"Invalid custom arguments syntax: {e}")
            if target_cleaned:
                args.extend(shlex.split(target_cleaned))

        elif profile.scan_type == "file":
            valid, err = cls.validate_target(target_cleaned, is_file_scan=True)
            if not valid:
                raise ValidationError(err)
            args.extend(["-iL", os.path.expanduser(target_cleaned)])

        else:
            valid, err = cls.validate_target(target_cleaned, is_file_scan=False)
            if not valid:
                raise ValidationError(err)
            args.extend(profile.flags)
            args.extend(shlex.split(target_cleaned))

        return args

    @classmethod
    def build_display_command(
        cls,
        profile: ScanProfile,
        target: str,
        custom_args: str = "",
    ) -> str:
        """Returns a formatted command string for preview inside the UI."""
        target_display = target.strip()
        if profile.scan_type == "custom":
            c_args = custom_args.strip() if custom_args.strip() else "<args>"
            t_args = f" {target_display}" if target_display else ""
            return f"nmap {c_args}{t_args}"
        elif profile.scan_type == "file":
            f_target = target_display if target_display else "<file>"
            return f"nmap -iL {f_target}"
        elif profile.scan_type in ("history", "exit"):
            return profile.command_template
        else:
            t_args = f" {target_display}" if target_display else ""
            return f"{profile.command_template}{t_args}"
