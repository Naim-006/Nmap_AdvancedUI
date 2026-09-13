#!/usr/bin/env python3
"""Interactive terminal application controller for Nmap TUI."""

import curses
import locale
import os
import shutil
import sys
import threading
import time
from typing import Optional, List

from zenmapCore.tui.profiles import get_default_profiles, ScanProfile
from zenmapCore.tui.builder import CommandBuilder, ValidationError
from zenmapCore.tui.runner import ScanRunner, ScanState
from zenmapCore.tui.history import ScanHistory
from zenmapCore.tui.view import TUIView


class NmapTUI:
    """Terminal User Interface application controller."""

    def __init__(
        self,
        stdscr,
        initial_target: str = "",
        initial_profile: Optional[str] = None,
    ):
        self.stdscr = stdscr
        self.profiles: List[ScanProfile] = get_default_profiles()
        self.selected_index: int = 0
        self.target: str = initial_target
        self._original_target: str = initial_target
        self.target_error: str = ""
        self.custom_args: str = ""
        self.active_focus: str = "options"  # "options", "target", "custom_args", "output"
        self.cursor_col: int = len(self.target)

        # Components
        self.view = TUIView(stdscr)
        self.runner = ScanRunner()
        self.history = ScanHistory()

        # Output state
        self.output_lines: List[str] = []
        self.output_scroll: int = 0  # 0 = follow tail
        self.scan_state_str: str = "Ready"

        # Apply initial profile if passed
        if initial_profile:
            for idx, p in enumerate(self.profiles):
                if initial_profile.lower() in p.name.lower() or initial_profile == p.key:
                    self.selected_index = idx
                    break

        self.scan_start_time: float = 0.0

        # Curses setup
        self._set_cursor_visible(False)
        self.stdscr.timeout(50)  # 50ms non-blocking polling

        # Enable mouse tracking
        try:
            curses.mousemask(curses.ALL_MOUSE_EVENTS | curses.REPORT_MOUSE_POSITION)
            curses.mouseinterval(0)
        except curses.error:
            pass

    def _set_cursor_visible(self, visible: bool):
        try:
            curses.curs_set(1 if visible else 0)
        except curses.error:
            pass

    def run(self):
        """Main interaction loop."""
        while True:
            # Sync running output
            is_scanning = self.runner.is_running()
            if is_scanning:
                self.output_lines = self.runner.get_output_copy()
                self.scan_state_str = "Scanning..."
            elif self.runner.state == ScanState.COMPLETED:
                self.output_lines = self.runner.get_output_copy()
                self.scan_state_str = "Completed"
            elif self.runner.state == ScanState.FAILED:
                self.output_lines = self.runner.get_output_copy()
                self.scan_state_str = "Failed"
            elif self.runner.state == ScanState.CANCELLED:
                self.output_lines = self.runner.get_output_copy()
                self.scan_state_str = "Cancelled"

            elapsed_secs = (time.time() - self.scan_start_time) if (is_scanning and self.scan_start_time > 0) else 0.0

            show_severity_legend = (
                self.runner.state == ScanState.COMPLETED
                and getattr(self.runner, "has_severity_tags", False)
            )

            # Render UI
            self.view.render(
                profiles=self.profiles,
                selected_index=self.selected_index,
                target=self.target,
                custom_args=self.custom_args,
                active_focus=self.active_focus,
                output_lines=self.output_lines,
                output_scroll=self.output_scroll,
                scan_state_str=self.scan_state_str,
                cursor_col=self.cursor_col,
                target_error=self.target_error,
                show_severity_legend=show_severity_legend,
                is_scanning=is_scanning,
                elapsed_secs=elapsed_secs,
            )

            try:
                ch = self.stdscr.getch()
            except curses.error:
                continue

            if ch == -1:
                continue

            # Process resize event
            if ch == curses.KEY_RESIZE:
                curses.update_lines_cols()
                continue

            # Process mouse event (clicks, scrolling, button presses)
            if ch == curses.KEY_MOUSE:
                try:
                    _, mx, my, _, bstate = curses.getmouse()
                    self._handle_mouse_event(mx, my, bstate)
                except curses.error:
                    pass
                continue

            # Handle global quit (only active when not typing text)
            if ch in (ord("q"), ord("Q")) and self.active_focus not in ("target", "custom_args"):
                if self.runner.is_running():
                    self.runner.cancel()
                break

            # Handle cancellation
            if ch in (3, ord("c"), ord("C")) and self.runner.is_running():  # Ctrl+C or 'c'
                self.runner.cancel()
                self.scan_state_str = "Cancelled"
                continue

            # Route key by focus
            if self.active_focus == "options":
                self._handle_options_input(ch)
            elif self.active_focus == "target":
                self._handle_target_input(ch)
            elif self.active_focus == "custom_args":
                self._handle_custom_args_input(ch)
            elif self.active_focus == "output":
                self._handle_output_input(ch)

    def _handle_options_input(self, ch: int):
        """Handles keyboard input when Scan Options is focused."""
        # Arrow navigation
        if ch in (curses.KEY_UP, ord("k")):
            self.selected_index = (self.selected_index - 1) % len(self.profiles)
            self._on_profile_change()
        elif ch in (curses.KEY_DOWN, ord("j")):
            self.selected_index = (self.selected_index + 1) % len(self.profiles)
            self._on_profile_change()

        # Direct number jump (1-9, 0)
        elif ord("1") <= ch <= ord("9"):
            target_idx = ch - ord("1")
            if target_idx < len(self.profiles):
                self.selected_index = target_idx
                self._on_profile_change()
        elif ch == ord("0"):
            self.selected_index = len(self.profiles) - 1  # Exit is last profile (index 9)
            self._on_profile_change()

        # Tab or 't' or 'T' to change focus to target input
        elif ch in (ord("\t"), 9, ord("t"), ord("T")):
            self.active_focus = "target"
            self._original_target = self.target
            self.cursor_col = len(self.target)
            self.target_error = ""
            self._set_cursor_visible(True)

        # Enter / Execute
        elif ch in (curses.KEY_ENTER, 10, 13):
            self._execute_selected_action()

        # PageUp / PageDown for scrolling output directly
        elif ch == curses.KEY_PPAGE:
            self._scroll_output(-5)
        elif ch == curses.KEY_NPAGE:
            self._scroll_output(5)

    def _handle_target_input(self, ch: int):
        """Handles text typing and editing in Target field."""
        curr_prof = self.profiles[self.selected_index]

        # Tab confirms target and moves to custom args (if custom scan) or back to options
        if ch in (ord("\t"), 9):
            self._original_target = self.target
            self._set_cursor_visible(False)
            if curr_prof.scan_type == "custom":
                self.active_focus = "custom_args"
                self.cursor_col = len(self.custom_args)
                self._set_cursor_visible(True)
            else:
                self.active_focus = "options"
            return

        # Escape cancels edit and restores previous value
        if ch == 27:
            self.target = self._original_target
            self.cursor_col = len(self.target)
            self.target_error = ""
            self._set_cursor_visible(False)
            self.active_focus = "options"
            return

        # Enter confirms target and returns focus to options
        if ch in (curses.KEY_ENTER, 10, 13):
            self._original_target = self.target
            self._set_cursor_visible(False)
            self.active_focus = "options"
            return

        # Up/Down arrows confirm edit and return to options navigation
        if ch in (curses.KEY_UP, curses.KEY_DOWN):
            self._original_target = self.target
            self._set_cursor_visible(False)
            self.active_focus = "options"
            self._handle_options_input(ch)
            return

        # Left arrow
        if ch == curses.KEY_LEFT:
            if self.cursor_col > 0:
                self.cursor_col -= 1
            return

        # Right arrow
        if ch == curses.KEY_RIGHT:
            if self.cursor_col < len(self.target):
                self.cursor_col += 1
            return

        # Home / Ctrl+A
        if ch in (curses.KEY_HOME, 1):
            self.cursor_col = 0
            return

        # End / Ctrl+E
        if ch in (curses.KEY_END, 5):
            self.cursor_col = len(self.target)
            return

        # Backspace
        if ch in (curses.KEY_BACKSPACE, 127, 8):
            if self.cursor_col > 0:
                self.target = self.target[: self.cursor_col - 1] + self.target[self.cursor_col :]
                self.cursor_col -= 1
                self.target_error = ""
            return

        # Delete key (KEY_DC)
        if ch == curses.KEY_DC:
            if self.cursor_col < len(self.target):
                self.target = self.target[: self.cursor_col] + self.target[self.cursor_col + 1 :]
                self.target_error = ""
            return

        # Ctrl+U (clear line)
        if ch == 21:
            self.target = ""
            self.cursor_col = 0
            self.target_error = ""
            return

        # Ctrl+K (delete to end)
        if ch == 11:
            self.target = self.target[: self.cursor_col]
            self.target_error = ""
            return

        # Printable character input
        if 32 <= ch <= 126:
            char = chr(ch)
            self.target = self.target[: self.cursor_col] + char + self.target[self.cursor_col :]
            self.cursor_col += 1
            self.target_error = ""
            return

    def _handle_custom_args_input(self, ch: int):
        """Handles typing custom arguments."""
        if ch in (ord("\t"), 9):
            self._set_cursor_visible(False)
            self.active_focus = "options"
            return

        if ch == 27:
            self._set_cursor_visible(False)
            self.active_focus = "options"
            return

        if ch in (curses.KEY_ENTER, 10, 13):
            self._set_cursor_visible(False)
            self.active_focus = "options"
            self._execute_selected_action()
            return

        if ch in (curses.KEY_BACKSPACE, 127, 8):
            if self.custom_args:
                self.custom_args = self.custom_args[:-1]
            return

        if 32 <= ch <= 126:
            self.custom_args += chr(ch)

    def _handle_output_input(self, ch: int):
        """Handles scrolling when Output panel is focused."""
        if ch in (ord("\t"), 9):
            self.active_focus = "options"
            return

        if ch in (curses.KEY_UP, ord("k")):
            self._scroll_output(-1)
        elif ch in (curses.KEY_DOWN, ord("j")):
            self._scroll_output(1)
        elif ch == curses.KEY_PPAGE:
            self._scroll_output(-10)
        elif ch == curses.KEY_NPAGE:
            self._scroll_output(10)
        elif ch == curses.KEY_HOME:
            self.output_scroll = 1
        elif ch == curses.KEY_END:
            self.output_scroll = 0  # Follow tail

    def _scroll_output(self, delta: int):
        total = len(self.output_lines)
        if total == 0:
            return
        if self.output_scroll == 0:
            self.output_scroll = max(1, total - 10)
        self.output_scroll = max(1, min(total, self.output_scroll + delta))

    def _on_profile_change(self):
        """Called whenever user moves selection."""
        prof = self.profiles[self.selected_index]
        if prof.scan_type == "history":
            self._display_history()

    def _display_history(self):
        """Displays recorded scan history in the output area."""
        records = self.history.records
        self.output_lines.clear()
        self.output_scroll = 0
        self.scan_state_str = "History View"

        if not records:
            self.output_lines.append("[!] No previous scans recorded yet.")
            self.output_lines.append("    Run a scan profile against a target to build history.")
            return

        self.output_lines.append("═" * 70)
        self.output_lines.append(f"  SCAN HISTORY ({len(records)} past scans recorded)")
        self.output_lines.append("═" * 70)
        self.output_lines.append(f"{'#':<3} | {'Timestamp':<19} | {'Outcome':<9} | {'Target':<18} | Profile")
        self.output_lines.append("─" * 70)

        for rec in reversed(records):
            outcome_tag = f"[{rec.outcome[:4]}]"
            self.output_lines.append(
                f"{rec.record_id:<3} | {rec.timestamp:<19} | {rec.outcome:<9} | {rec.target:<18} | {rec.profile}"
            )
            self.output_lines.append(f"    Command: {rec.command}")

        self.output_lines.append("─" * 70)
        self.output_lines.append("💡 Use PageUp/PageDown to scroll history.")

    def _execute_selected_action(self):
        """Executes the currently highlighted profile action."""
        prof = self.profiles[self.selected_index]

        # 1. Exit Profile
        if prof.scan_type == "exit":
            if self.runner.is_running():
                self.runner.cancel()
            sys.exit(0)

        # 2. History Profile
        if prof.scan_type == "history":
            self._display_history()
            return

        # 3. Prevent duplicate execution while running
        if self.runner.is_running():
            self.output_lines.append("[!] Another scan is currently in progress. Press 'c' to cancel.")
            return

        # 4. Target and Argument validation
        try:
            cmd_args = CommandBuilder.build_command(
                profile=prof,
                target=self.target,
                custom_args=self.custom_args,
            )
            display_cmd = CommandBuilder.build_display_command(
                profile=prof,
                target=self.target,
                custom_args=self.custom_args,
            )
        except ValidationError as e:
            self.target_error = str(e)
            self.output_lines = [
                f"[✗] Validation Error: {e}",
                "─" * 50,
                "Please check the target specification and try again.",
            ]
            self.scan_state_str = "Error"
            return

        # 5. Start Execution
        self.target_error = ""
        self.output_scroll = 0
        self.scan_state_str = "Starting..."
        self.scan_start_time = time.time()

        def on_complete(r: ScanRunner):
            # Record in history
            duration = r.end_time - r.start_time
            self.history.add_record(
                target=r.target,
                profile=r.profile_name,
                command=r.command_str,
                outcome=r.state,
                duration=duration,
                output_lines=r.get_output_copy(),
            )

        self.runner.start_scan(
            command_args=cmd_args,
            command_str=display_cmd,
            target=self.target,
            profile_name=prof.name,
            on_complete=on_complete,
        )

    def _handle_mouse_event(self, mx: int, my: int, bstate: int):
        """Handles mouse clicks, button hits, and mouse wheel scrolling."""
        # 1. Mouse wheel scrolling
        wheel_up = bstate & (getattr(curses, "BUTTON4_PRESSED", 0) | 0x10000 | 0x80000)
        wheel_down = bstate & (getattr(curses, "BUTTON5_PRESSED", 0) | 0x200000 | 0x800000)

        if wheel_up:
            if self.output_lines:
                curr = self.output_scroll if self.output_scroll > 0 else len(self.output_lines)
                self.output_scroll = max(1, curr - 3)
            return
        elif wheel_down:
            if self.output_lines and self.output_scroll > 0:
                self.output_scroll += 3
                if self.output_scroll >= len(self.output_lines):
                    self.output_scroll = 0
            return

        # 2. Left click detection
        is_click = bool(
            bstate
            & (
                getattr(curses, "BUTTON1_CLICKED", 0)
                | getattr(curses, "BUTTON1_PRESSED", 0)
                | getattr(curses, "BUTTON1_RELEASED", 0)
                | getattr(curses, "BUTTON1_DOUBLE_CLICKED", 0)
            )
        )
        if not is_click:
            return

        # A. Execute / Cancel Button
        btn_y, btn_x, btn_h, btn_w = getattr(self.view, "rect_execute_btn", (0, 0, 0, 0))
        if btn_y <= my < btn_y + btn_h and btn_x <= mx < btn_x + btn_w:
            if self.runner.is_running():
                self.runner.cancel()
                self.scan_state_str = "Cancelled"
            else:
                self._execute_selected_action()
            return

        # B. Target Input Box
        in_y, in_x, in_h, in_w = getattr(self.view, "rect_target_input", (0, 0, 0, 0))
        if in_y <= my < in_y + in_h and in_x <= mx < in_x + in_w:
            self.active_focus = "target"
            text_x = in_x + 2
            self.cursor_col = max(0, min(len(self.target), mx - text_x))
            return

        # C. Target Helper Examples line
        hlp_y, hlp_x, hlp_w = getattr(self.view, "rect_target_helper", (0, 0, 0))
        if my == hlp_y and hlp_x <= mx < hlp_x + hlp_w:
            self._handle_helper_click(mx)
            return

        # D. Scan Options list
        opt_y, opt_x, opt_h, opt_w = getattr(self.view, "rect_options", (0, 0, 0, 0))
        if opt_y + 1 <= my < opt_y + opt_h - 1 and opt_x <= mx < opt_x + opt_w:
            clicked_idx = my - (opt_y + 1)
            display_count = min(9, len(self.profiles))
            if 0 <= clicked_idx < display_count:
                if self.active_focus == "target":
                    is_valid, _ = CommandBuilder.validate_target(
                        self.target, is_file_scan=(self.profiles[self.selected_index].scan_type == "file")
                    )
                    if not is_valid:
                        self.target = self._original_target
                    self.target_error = ""
                self.selected_index = clicked_idx
                self.active_focus = "options"
                self._on_profile_change()
            return

        # E. Output panel
        out_y, out_x, out_h, out_w = getattr(self.view, "rect_output", (0, 0, 0, 0))
        if out_y <= my < out_y + out_h and out_x <= mx < out_x + out_w:
            self.active_focus = "output"
            return

        # F. Click outside Target while editing Target confirms target
        if self.active_focus == "target":
            is_valid, err = CommandBuilder.validate_target(
                self.target, is_file_scan=(self.profiles[self.selected_index].scan_type == "file")
            )
            if not is_valid:
                self.target = self._original_target
            self.target_error = ""
            self.active_focus = "options"

    def _handle_helper_click(self, mx: int):
        """Populates target when clicking an example from the helper row."""
        profile = self.profiles[self.selected_index]
        if profile.scan_type == "file":
            examples = ["targets.txt", "/home/user/hosts.list"]
        else:
            examples = ["192.168.1.1", "scanme.nmap.org", "10.0.0.0/24"]

        start_x = getattr(self.view, "rect_target_helper", (0, 0, 0))[1]
        for ex in examples:
            ex_len = len(ex)
            if start_x - 1 <= mx <= start_x + ex_len + 1:
                self.target = ex
                self.cursor_col = len(self.target)
                self.active_focus = "target"
                self.target_error = ""
                return
            start_x += ex_len + 3


def run_tui(target: str = "", profile: Optional[str] = None):
    """Entry point to launch the Nmap TUI."""
    # Ensure UTF-8 locale for Unicode box characters
    try:
        locale.setlocale(locale.LC_ALL, "")
    except Exception:
        pass

    def _wrapper(stdscr):
        app = NmapTUI(stdscr, initial_target=target, initial_profile=profile)
        app.run()

    # Switch to terminal alternate screen buffer to prevent ghost scrollback bleed-through
    try:
        sys.stdout.write("\033[?1049h\033[H")
        sys.stdout.flush()
    except Exception:
        pass

    try:
        curses.wrapper(_wrapper)
    except KeyboardInterrupt:
        pass
    finally:
        # Restore normal screen buffer and disable mouse tracking cleanly on exit
        try:
            curses.mousemask(0)
            sys.stdout.write("\033[?1000l\033[?1002l\033[?1049l")
            sys.stdout.flush()
        except Exception:
            pass


def run_headless(
    target: str = "",
    profile: Optional[str] = None,
    custom_args: str = "",
    target_file: str = "",
    no_color: bool = False,
) -> int:
    """Executes a scan headlessly without curses and streams output to stdout/stderr."""
    profiles = get_default_profiles()
    selected_prof = profiles[0]
    if profile:
        for idx, p in enumerate(profiles):
            if profile.lower() in p.name.lower() or profile == p.key:
                selected_prof = p
                break

    # Handle special profiles
    if selected_prof.scan_type == "history":
        hist = ScanHistory()
        records = hist.get_records()
        if not records:
            print("No scan history found.")
        else:
            for r in records:
                print(f"[{r.timestamp}] {r.profile} ({r.outcome}) - {r.target}: {r.command}")
        return 0

    if selected_prof.scan_type == "exit":
        return 0

    # Determine effective target
    eff_target = target
    if selected_prof.scan_type == "file":
        if target_file:
            eff_target = target_file
        elif not eff_target:
            eff_target = "/tmp/targets.txt"

    # Validate target
    is_file_scan = (selected_prof.scan_type == "file")
    is_valid, err_msg = CommandBuilder.validate_target(eff_target, is_file_scan=is_file_scan)
    if not is_valid:
        print(f"Error: {err_msg}", file=sys.stderr)
        return 1

    # Validate custom arguments if custom scan
    if selected_prof.scan_type == "custom" and custom_args:
        for token in custom_args.split():
            if token.isdigit() and int(token) > 65535:
                print(f"Error: Invalid port number: {token}", file=sys.stderr)
                return 1

    # Check if nmap is installed
    if not shutil.which("nmap"):
        print("Error: 'nmap' executable not found in PATH.", file=sys.stderr)
        return 1

    try:
        cmd_args = CommandBuilder.build_command(selected_prof, eff_target, custom_args)
        display_cmd = CommandBuilder.build_display_command(selected_prof, eff_target, custom_args)
    except ValidationError as ve:
        print(f"Error: {ve}", file=sys.stderr)
        return 1

    history = ScanHistory()
    runner = ScanRunner()

    RED = "" if no_color else "\033[0;31m"
    YELLOW = "" if no_color else "\033[1;33m"
    GREEN = "" if no_color else "\033[0;32m"
    CYAN = "" if no_color else "\033[0;36m"
    RESET = "" if no_color else "\033[0m"

    completed_event = threading.Event()

    def on_complete(r: ScanRunner):
        duration = r.end_time - r.start_time
        history.add_record(
            target=r.target,
            profile=r.profile_name,
            command=r.command_str,
            outcome=r.state,
            duration=duration,
            output_lines=r.get_output_copy(),
        )
        completed_event.set()

    printed_lines = 0
    runner.start_scan(
        command_args=cmd_args,
        command_str=display_cmd,
        target=eff_target,
        profile_name=selected_prof.name,
        on_complete=on_complete,
    )

    while not completed_event.is_set() or printed_lines < len(runner.output_lines):
        lines = runner.get_output_copy()
        while printed_lines < len(lines):
            line = lines[printed_lines]
            printed_lines += 1
            if no_color:
                print(line)
            else:
                if "[CRITICAL]" in line:
                    line = line.replace("[CRITICAL]", f"{RED}[CRITICAL]{RESET}")
                if "[HIGH]" in line:
                    line = line.replace("[HIGH]", f"{YELLOW}[HIGH]{RESET}")
                if "[MEDIUM]" in line:
                    line = line.replace("[MEDIUM]", f"{YELLOW}[MEDIUM]{RESET}")
                if "[LOW]" in line:
                    line = line.replace("[LOW]", f"{GREEN}[LOW]{RESET}")
                if "[INFO]" in line:
                    line = line.replace("[INFO]", f"{CYAN}[INFO]{RESET}")
                print(line)
        time.sleep(0.05)

    return 0 if runner.state == ScanState.COMPLETED else 1

