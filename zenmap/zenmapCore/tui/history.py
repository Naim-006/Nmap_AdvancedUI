#!/usr/bin/env python3
"""Lightweight scan history persistence for Nmap TUI."""

import json
import os
import time
from typing import List, Dict, Any, Optional


class ScanRecord:
    def __init__(
        self,
        record_id: int,
        target: str,
        profile: str,
        command: str,
        timestamp: str,
        outcome: str,
        duration: float,
        output_lines: Optional[List[str]] = None,
    ):
        self.record_id = record_id
        self.target = target
        self.profile = profile
        self.command = command
        self.timestamp = timestamp
        self.outcome = outcome
        self.duration = duration
        self.output_lines = output_lines or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.record_id,
            "target": self.target,
            "profile": self.profile,
            "command": self.command,
            "timestamp": self.timestamp,
            "outcome": self.outcome,
            "duration": round(self.duration, 2),
            "output_lines": self.output_lines[:150],  # keep reasonable log size per record
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanRecord":
        return cls(
            record_id=data.get("id", 0),
            target=data.get("target", ""),
            profile=data.get("profile", ""),
            command=data.get("command", ""),
            timestamp=data.get("timestamp", ""),
            outcome=data.get("outcome", ""),
            duration=data.get("duration", 0.0),
            output_lines=data.get("output_lines", []),
        )


class ScanHistory:
    """Manages persistent scan history in JSON format."""

    def __init__(self, history_file: Optional[str] = None):
        self.history_file = history_file or self._resolve_history_path()
        self.records: List[ScanRecord] = []
        self.load()

    def _resolve_history_path(self) -> str:
        # Check ~/.zenmap first
        user_home = os.path.expanduser("~")
        zenmap_dir = os.path.join(user_home, ".zenmap")
        try:
            if not os.path.exists(zenmap_dir):
                os.makedirs(zenmap_dir, exist_ok=True)
            candidate = os.path.join(zenmap_dir, "tui_scan_history.json")
            with open(candidate, "a"):
                pass
            return candidate
        except Exception:
            pass

        # Fallback to local workspace
        return os.path.abspath(".nmap_scan_history.json")

    def load(self):
        if not os.path.exists(self.history_file):
            return
        try:
            with open(self.history_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    self.records = [ScanRecord.from_dict(item) for item in data]
        except Exception:
            self.records = []

    def get_records(self) -> List[ScanRecord]:
        return list(self.records)

    def save(self):
        try:
            payload = [rec.to_dict() for rec in self.records]
            with open(self.history_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        except Exception:
            pass

    def add_record(
        self,
        target: str,
        profile: str,
        command: str,
        outcome: str,
        duration: float,
        output_lines: List[str],
    ) -> ScanRecord:
        record_id = len(self.records) + 1
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        record = ScanRecord(
            record_id=record_id,
            target=target,
            profile=profile,
            command=command,
            timestamp=timestamp,
            outcome=outcome,
            duration=duration,
            output_lines=output_lines,
        )
        self.records.append(record)
        self.save()
        return record

    def clear(self):
        self.records = []
        self.save()
