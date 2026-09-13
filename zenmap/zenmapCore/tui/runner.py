#!/usr/bin/env python3
"""Asynchronous Nmap execution engine with live streaming output."""

import os
import signal
import subprocess
import threading
import time
from typing import List, Callable, Optional

from zenmapCore.tui.severity import (
    supports_service_tagging,
    tag_port_line,
    parse_script_vuln_severity,
    SEVERITY_ORDER,
    SEVERITY_RANK,
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO,
)


class ScanState:
    IDLE = "IDLE"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScanRunner:
    """Executes Nmap in a background thread and streams output safely."""

    def __init__(self):
        self.state = ScanState.IDLE
        self.process: Optional[subprocess.Popen] = None
        self.output_lines: List[str] = []
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self.exit_code: Optional[int] = None
        self.start_time: float = 0.0
        self.end_time: float = 0.0
        self.on_complete_callback: Optional[Callable[["ScanRunner"], None]] = None
        self.command_args: List[str] = []
        self.command_str: str = ""
        self.target: str = ""
        self.profile_name: str = ""
        self.supports_tagging: bool = False
        self.severity_counts: dict = {CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0}
        self.has_severity_tags: bool = False
        self._last_port_line_idx: Optional[int] = None
        self._last_port_severity: Optional[str] = None

    def is_running(self) -> bool:
        return self.state == ScanState.RUNNING

    def get_output_copy(self) -> List[str]:
        with self._lock:
            return list(self.output_lines)

    def _append_line(self, line: str):
        with self._lock:
            # Strip trailing newline/carriage return
            cleaned = line.rstrip("\r\n")
            self.output_lines.append(cleaned)

    def start_scan(
        self,
        command_args: List[str],
        command_str: str,
        target: str,
        profile_name: str,
        on_complete: Optional[Callable[["ScanRunner"], None]] = None,
    ):
        """Starts the scan execution in a background thread."""
        if self.is_running():
            raise RuntimeError("A scan is already in progress.")

        with self._lock:
            self.output_lines.clear()

        self.command_args = command_args
        self.command_str = command_str
        self.target = target
        self.profile_name = profile_name
        self.on_complete_callback = on_complete
        self.state = ScanState.RUNNING
        self.exit_code = None
        self.start_time = time.time()
        self.end_time = 0.0
        self.supports_tagging = supports_service_tagging(command_args)
        self.severity_counts = {CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0}
        self.has_severity_tags = False
        self._last_port_line_idx = None
        self._last_port_severity = None


        self._append_line(f"[▶] Starting scan: {command_str}")
        self._append_line("─" * 50)

        self._thread = threading.Thread(target=self._run_process, daemon=True)
        self._thread.start()

    def _run_process(self):
        try:
            self.process = subprocess.Popen(
                self.command_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
                errors="replace",
            )
        except FileNotFoundError:
            self._append_line("[✗] Scan failed: 'nmap' executable not found in PATH.")
            self._append_line("    Please ensure Nmap is installed and accessible.")
            self.state = ScanState.FAILED
            self.end_time = time.time()
            if self.on_complete_callback:
                self.on_complete_callback(self)
            return
        except PermissionError as e:
            self._append_line(f"[✗] Scan failed: Permission denied executing nmap: {e}")
            self.state = ScanState.FAILED
            self.end_time = time.time()
            if self.on_complete_callback:
                self.on_complete_callback(self)
            return
        except Exception as e:
            self._append_line(f"[✗] Scan failed to start: {e}")
            self.state = ScanState.FAILED
            self.end_time = time.time()
            if self.on_complete_callback:
                self.on_complete_callback(self)
            return

        # Stream stdout/stderr in real-time
        try:
            if self.process.stdout:
                for line in iter(self.process.stdout.readline, ""):
                    if not line and self.process.poll() is not None:
                        break
                    if line:
                        if self.supports_tagging:
                            tagged_line, sev = tag_port_line(line)
                            if sev:
                                self.severity_counts[sev] += 1
                                self.has_severity_tags = True
                                self._append_line(tagged_line)
                                with self._lock:
                                    self._last_port_line_idx = len(self.output_lines) - 1
                                self._last_port_severity = sev
                            else:
                                script_sev = parse_script_vuln_severity(line)
                                if (
                                    script_sev
                                    and self._last_port_line_idx is not None
                                    and self._last_port_severity
                                ):
                                    if SEVERITY_RANK.get(script_sev, 0) > SEVERITY_RANK.get(self._last_port_severity, 0):
                                        old_sev = self._last_port_severity
                                        with self._lock:
                                            if 0 <= self._last_port_line_idx < len(self.output_lines):
                                                old_line = self.output_lines[self._last_port_line_idx]
                                                self.output_lines[self._last_port_line_idx] = old_line.replace(
                                                    f"[{old_sev}]", f"[{script_sev}]"
                                                )
                                        self.severity_counts[old_sev] = max(0, self.severity_counts[old_sev] - 1)
                                        self.severity_counts[script_sev] += 1
                                        self._last_port_severity = script_sev
                                if line.startswith("Nmap scan report") or line.startswith("Nmap done"):
                                    self._last_port_line_idx = None
                                    self._last_port_severity = None
                                self._append_line(line)
                        else:
                            self._append_line(line)
                self.process.stdout.close()

            self.exit_code = self.process.wait()
        except Exception as e:
            self._append_line(f"[!] Error while reading output: {e}")
            self.exit_code = -1

        self.end_time = time.time()
        elapsed = self.end_time - self.start_time

        if self.state == ScanState.CANCELLED:
            self._append_line("─" * 50)
            self._append_line(f"[!] Scan cancelled by user ({elapsed:.2f}s).")
        elif self.exit_code == 0:
            self.state = ScanState.COMPLETED
            if self.supports_tagging:
                if self.has_severity_tags:
                    parts = []
                    for lvl in SEVERITY_ORDER:
                        cnt = self.severity_counts.get(lvl, 0)
                        if cnt > 0:
                            parts.append(f"{cnt} {lvl}")
                    if parts:
                        self._append_line("")
                        self._append_line("Summary: " + "  ·  ".join(parts))
                else:
                    self._append_line("")
                    self._append_line("[INFO] No open ports detected on target.")
            self._append_line("─" * 50)
            self._append_line(f"[✓] Scan completed successfully ({elapsed:.2f}s).")
        else:
            self.state = ScanState.FAILED
            self._append_line("─" * 50)
            self._append_line(f"[✗] Scan failed with exit code {self.exit_code} ({elapsed:.2f}s).")
            with self._lock:
                has_root_err = any("requires root privileges" in l for l in self.output_lines)
            if has_root_err:
                self._append_line("[💡] Tip: This scan requires root privileges on Linux. Please run with: sudo ./nmap-tui")

        if self.on_complete_callback:
            try:
                self.on_complete_callback(self)
            except Exception:
                pass

    def cancel(self):
        """Cancels any running Nmap scan process."""
        if not self.is_running() or not self.process:
            return

        self.state = ScanState.CANCELLED
        try:
            self.process.terminate()
            # Wait up to 1.5 seconds for graceful shutdown
            for _ in range(15):
                if self.process.poll() is not None:
                    break
                time.sleep(0.1)
            else:
                self.process.kill()
        except Exception:
            pass
