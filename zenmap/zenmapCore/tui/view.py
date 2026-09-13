#!/usr/bin/env python3
"""Rendering logic and panel layouts for the Nmap TUI."""

import curses
import os
import re
from typing import List, Optional
from zenmapCore.tui.profiles import ScanProfile


def safe_addstr(win, y: int, x: int, text: str, attr: int = 0):
    """Safely adds a string to a window, clipping if it exceeds window bounds."""
    max_y, max_x = win.getmaxyx()
    if y < 0 or y >= max_y or x < 0 or x >= max_x:
        return
    avail = max_x - x
    if avail <= 0:
        return
    # Use text[:avail] and handle curses bottom-right corner quirk
    to_print = text[:avail]
    try:
        if y == max_y - 1 and len(to_print) >= avail:
            win.addstr(y, x, to_print[:-1], attr)
        else:
            win.addstr(y, x, to_print, attr)
    except curses.error:
        pass


def draw_box(
    win,
    y: int,
    x: int,
    height: int,
    width: int,
    title: str = "",
    right_tag: str = "",
    border_attr: int = 0,
    title_attr: int = 0,
    tag_attr: int = 0,
    bg_attr: int = 0,
):
    """Draws a rounded or single-line box with an optional title and right-aligned tag."""
    max_y, max_x = win.getmaxyx()
    if y >= max_y or x >= max_x or height < 2 or width < 2:
        return

    # Box corners and edges (Unicode rounded borders)
    TL, TR, BL, BR = "╭", "╮", "╰", "╯"
    H, V = "─", "│"

    # Top border
    top_line = TL + (H * (width - 2)) + TR
    safe_addstr(win, y, x, top_line, border_attr)

    # Side borders and interior blank fill
    fill_spaces = " " * (width - 2) if width > 2 else ""
    for row in range(1, height - 1):
        if y + row < max_y:
            safe_addstr(win, y + row, x, V, border_attr)
            if fill_spaces:
                safe_addstr(win, y + row, x + 1, fill_spaces, bg_attr)
            safe_addstr(win, y + row, x + width - 1, V, border_attr)

    # Bottom border
    if y + height - 1 < max_y:
        bot_line = BL + (H * (width - 2)) + BR
        safe_addstr(win, y + height - 1, x, bot_line, border_attr)

    # Title
    if title and width > len(title) + 4:
        title_str = f" {title} "
        safe_addstr(win, y, x + 2, title_str, title_attr)

    # Right Tag
    if right_tag and width > len(title or "") + len(right_tag) + 6:
        tag_pos = x + width - len(right_tag) - 3
        safe_addstr(win, y, tag_pos, f" {right_tag} ", tag_attr)


class TUIView:
    """Manages full screen rendering matching the reference design."""

    def __init__(self, stdscr):
        self.stdscr = stdscr
        self._init_colors()

    def _init_colors(self):
        try:
            has_col = curses.has_colors()
        except curses.error:
            has_col = False

        if not has_col:
            self.C_CYAN = 0
            self.C_BORDER = 0
            self.C_HL = curses.A_REVERSE
            self.C_GREEN = 0
            self.C_YELLOW = 0
            self.C_DIM = 0
            self.C_WHITE = curses.A_BOLD
            self.C_NORMAL = 0
            self.C_RED = curses.A_BOLD
            self.C_BTN = curses.A_REVERSE
            self.C_HELPER = 0
            return

        try:
            curses.start_color()
        except curses.error:
            pass

        # Solid pitch-black background to eliminate ghost scrollback bleed-through
        bg = curses.COLOR_BLACK

        # Pair definitions
        # 1: Cyan / Border / Primary
        try:
            curses.init_pair(1, curses.COLOR_CYAN, bg)
            curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_CYAN)
            curses.init_pair(3, curses.COLOR_GREEN, bg)
            curses.init_pair(4, curses.COLOR_YELLOW, bg)
            curses.init_pair(5, curses.COLOR_BLUE, bg)
            curses.init_pair(6, curses.COLOR_WHITE, bg)
            curses.init_pair(7, curses.COLOR_RED, bg)
            curses.init_pair(8, curses.COLOR_BLACK, curses.COLOR_GREEN)
            curses.init_pair(9, curses.COLOR_WHITE, curses.COLOR_BLACK)
            curses.init_pair(10, curses.COLOR_WHITE, curses.COLOR_BLACK)
        except curses.error:
            pass

        self.C_BG = curses.color_pair(10)

        self.C_CYAN = curses.color_pair(1) | curses.A_BOLD
        self.C_BORDER = curses.color_pair(1)
        self.C_HL = curses.color_pair(2) | curses.A_BOLD
        self.C_GREEN = curses.color_pair(3) | curses.A_BOLD
        self.C_YELLOW = curses.color_pair(4) | curses.A_BOLD
        self.C_DIM = curses.color_pair(5)
        self.C_WHITE = curses.color_pair(6) | curses.A_BOLD
        self.C_NORMAL = curses.color_pair(6)
        self.C_RED = curses.color_pair(7) | curses.A_BOLD
        self.C_BTN = curses.color_pair(8) | curses.A_BOLD
        self.C_HELPER = curses.color_pair(9) | curses.A_DIM
        self.C_HELPER = curses.color_pair(9) | curses.A_DIM

    def render(
        self,
        profiles: List[ScanProfile],
        selected_index: int,
        target: str,
        custom_args: str,
        active_focus: str,  # "options", "target", "custom_args", "output", "button"
        output_lines: List[str],
        output_scroll: int,
        scan_state_str: str,
        cursor_col: int = 0,
        target_error: str = "",
        show_severity_legend: bool = False,
        is_scanning: bool = False,
        elapsed_secs: float = 0.0,
    ):
        """Renders the entire dashboard onto stdscr."""
        self.stdscr.erase()
        max_y, max_x = self.stdscr.getmaxyx()

        # Explicitly overwrite entire terminal buffer with solid black spaces to clear any ghost scrollback
        blank_row = " " * (max_x - 1) if max_x > 1 else ""
        bg_fill = getattr(self, "C_BG", 0)
        for r in range(max_y):
            safe_addstr(self.stdscr, r, 0, blank_row, bg_fill)

        if max_y < 22 or max_x < 75:
            # Render fallback message on tiny terminals
            msg = f"Terminal too small ({max_x}x{max_y}). Please resize to at least 80x24."
            safe_addstr(self.stdscr, max_y // 2, max(0, (max_x - len(msg)) // 2), msg, self.C_YELLOW)
            self.stdscr.refresh()
            return

        # 1. Header (y=0 to y=5, returns 6)
        header_height = self._render_header(max_x)

        # 2. Layout coordinates
        # Top half: 2 balanced columns side-by-side
        left_w = (max_x - 3) // 2
        right_w = max_x - left_w - 3
        left_x = 1
        right_x = left_x + left_w + 1

        main_top = header_height
        footer_height = 2

        # Target height: 6 (or 7 if custom scan)
        is_custom = (profiles[selected_index].scan_type == "custom")
        target_h = 7 if is_custom else 6

        # Allocate heights between top half and output panel
        avail_h = max_y - main_top - footer_height
        if avail_h >= 28:
            selected_h = 9
        elif avail_h >= 24:
            selected_h = 8
        else:
            selected_h = 7

        top_h = target_h + selected_h
        output_y = main_top + top_h
        output_h = max(5, max_y - output_y - footer_height)
        output_x = 1
        output_w = max_x - 2

        # Record bounding rects for mouse click hit testing
        self.rect_options = (main_top, left_x, top_h, left_w)
        self.rect_target = (main_top, right_x, target_h, right_w)
        self.rect_selected = (main_top + target_h, right_x, selected_h, right_w)
        self.rect_output = (output_y, output_x, output_h, output_w)

        # 3. Render Top-Left Panel — Scan Options
        self._render_scan_options(
            y=main_top,
            x=left_x,
            height=top_h,
            width=left_w,
            profiles=profiles,
            selected_index=selected_index,
            is_focused=(active_focus == "options"),
        )

        # 4. Render Top-Right Panel — Target Information
        target_cursor = self._render_target_info(
            y=main_top,
            x=right_x,
            height=target_h,
            width=right_w,
            target=target,
            custom_args=custom_args,
            profile=profiles[selected_index],
            active_focus=active_focus,
            cursor_col=cursor_col,
            target_error=target_error,
        )

        # 5. Render Middle-Right Panel — Selected Scan
        self._render_selected_scan(
            y=main_top + target_h,
            x=right_x,
            height=selected_h,
            width=right_w,
            profile=profiles[selected_index],
            target=target,
            custom_args=custom_args,
            button_focused=(active_focus == "button"),
            is_scanning=is_scanning,
        )

        # 6. Render Full-Width Bottom Panel — Output
        self._render_output_panel(
            y=output_y,
            x=output_x,
            height=output_h,
            width=output_w,
            output_lines=output_lines,
            output_scroll=output_scroll,
            scan_state_str=scan_state_str,
            is_focused=(active_focus == "output"),
            show_severity_legend=show_severity_legend,
            is_scanning=is_scanning,
            elapsed_secs=elapsed_secs,
        )

        # 7. Render Footer Bar
        self._render_footer(max_y - 1, max_x, active_focus)

        # Position hardware cursor when in text edit mode
        try:
            if active_focus in ("target", "custom_args"):
                curses.curs_set(1)
                if active_focus == "target":
                    self.stdscr.move(target_cursor[0], target_cursor[1])
            else:
                curses.curs_set(0)
        except curses.error:
            pass

        self.stdscr.refresh()

    def _render_header(self, max_x: int) -> int:
        """Renders stylized NMAP wordmark, feature tags, and version badge."""
        # Top-left stylized NMAP wordmark
        # Row 1: NMAP   T O O L K I T
        # Row 2: — Scan smarter. Discover more. —
        safe_addstr(self.stdscr, 1, 2, "NMAP", self.C_CYAN | curses.A_BOLD)
        safe_addstr(self.stdscr, 1, 8, "T O O L K I T", self.C_WHITE | curses.A_BOLD)
        safe_addstr(self.stdscr, 2, 2, "— Scan smarter. Discover more. —", self.C_DIM)

        # Far top-right boxed version badge
        # Row 0: ╭──────╮
        # Row 1: │ v1.0 │
        # Row 2: ╰──────╯
        # Row 3: By ajmine
        # Row 4: stay ethical
        if max_x >= 50:
            badge_w = 8
            badge_x = max_x - badge_w - 3
            draw_box(self.stdscr, 0, badge_x, 3, badge_w, border_attr=self.C_BORDER)
            safe_addstr(self.stdscr, 1, badge_x + 2, "v1.0", self.C_CYAN | curses.A_BOLD)
            safe_addstr(self.stdscr, 3, badge_x - 1, "By ajmine", self.C_YELLOW)
            safe_addstr(self.stdscr, 4, badge_x - 2, "stay ethical", self.C_DIM)

        # Row 5: Subtle horizontal divider line across the screen
        safe_addstr(self.stdscr, 5, 1, "─" * (max_x - 2), self.C_BORDER | curses.A_DIM)

        return 6

    def _render_scan_options(
        self,
        y: int,
        x: int,
        height: int,
        width: int,
        profiles: List[ScanProfile],
        selected_index: int,
        is_focused: bool,
    ):
        """Renders the top-left Scan Options list."""
        draw_box(
            self.stdscr,
            y,
            x,
            height,
            width,
            title="SCAN OPTIONS",
            border_attr=self.C_CYAN if is_focused else self.C_BORDER,
            title_attr=self.C_CYAN,
        )

        inner_w = width - 4
        start_y = y + 1

        DISPLAY_NAMES = {
            "Quick Scan": "Quick scan",
            "Service & Version": "Service & version",
            "Full Port Scan": "Full port scan",
            "OS Detection": "OS detection",
            "Aggressive Scan": "Aggressive scan",
            "UDP Scan": "UDP scan",
            "Custom Scan": "Custom scan",
            "Scan from File": "Scan from file",
            "Scan History": "Scan history",
            "Exit": "Exit",
        }

        # Show profiles 1..9 matching the reference design
        display_profiles = profiles[:9] if len(profiles) >= 9 else profiles

        for i, prof in enumerate(display_profiles):
            row_y = start_y + i
            if row_y >= y + height - 1:
                break

            prof_name = DISPLAY_NAMES.get(prof.name, prof.name)

            # Command preview without enclosing parentheses
            if prof.scan_type == "custom":
                cmd_preview = "custom args"
            elif prof.scan_type == "file":
                cmd_preview = "nmap -iL"
            elif prof.scan_type == "history":
                cmd_preview = "view past"
            elif prof.scan_type == "exit":
                cmd_preview = "quit toolkit"
            else:
                cmd_preview = prof.command_template

            is_selected = (i == selected_index)

            if is_selected:
                # Highlighted row: cyan bold text with '>'
                prefix = f"> {prof.key}  {prof_name}"
                safe_addstr(self.stdscr, row_y, x + 2, prefix, self.C_CYAN | curses.A_BOLD)
                if len(cmd_preview) + len(prefix) + 2 < inner_w:
                    cmd_x = x + 2 + inner_w - len(cmd_preview) - 1
                    safe_addstr(self.stdscr, row_y, cmd_x, cmd_preview, self.C_CYAN | curses.A_BOLD)
            else:
                num_str = f"  {prof.key}  "
                safe_addstr(self.stdscr, row_y, x + 2, num_str, self.C_CYAN)
                safe_addstr(self.stdscr, row_y, x + 2 + len(num_str), prof_name, self.C_WHITE)
                if len(cmd_preview) + len(num_str) + len(prof_name) + 2 < inner_w:
                    cmd_x = x + 2 + inner_w - len(cmd_preview) - 1
                    safe_addstr(self.stdscr, row_y, cmd_x, cmd_preview, self.C_HELPER)

    def _render_target_info(
        self,
        y: int,
        x: int,
        height: int,
        width: int,
        target: str,
        custom_args: str,
        profile: ScanProfile,
        active_focus: str,
        cursor_col: int,
        target_error: str = "",
    ):
        """Renders the top-right Target panel."""
        is_focused = (active_focus in ("target", "custom_args"))
        draw_box(
            self.stdscr,
            y,
            x,
            height,
            width,
            title="TARGET",
            border_attr=self.C_CYAN if is_focused else self.C_BORDER,
            title_attr=self.C_CYAN,
        )

        inner_box_y = y + 1
        inner_box_x = x + 2
        inner_box_w = width - 4
        inner_box_h = 3

        if target_error:
            t_border = self.C_RED
        elif active_focus == "target":
            t_border = self.C_CYAN
        else:
            t_border = self.C_BORDER | curses.A_DIM

        self.rect_target_input = (inner_box_y, inner_box_x, inner_box_h, inner_box_w)
        draw_box(self.stdscr, inner_box_y, inner_box_x, inner_box_h, inner_box_w, border_attr=t_border)

        text_y = inner_box_y + 1
        text_x = inner_box_x + 2
        avail_len = max(10, inner_box_w - 4)

        if cursor_col < avail_len:
            view_start = 0
        else:
            view_start = cursor_col - avail_len + 1

        visible_target = target[view_start : view_start + avail_len]
        visible_cursor_col = min(avail_len, cursor_col - view_start)

        safe_addstr(self.stdscr, text_y, text_x, visible_target, self.C_WHITE)

        # Draw block cursor on screen (solid block █)
        cursor_screen_x = text_x + visible_cursor_col
        if cursor_screen_x < inner_box_x + inner_box_w - 1:
            char_under = target[cursor_col] if cursor_col < len(target) else " "
            if active_focus == "target":
                safe_addstr(self.stdscr, text_y, cursor_screen_x, char_under if char_under != " " else "█", self.C_CYAN | curses.A_BOLD)
            else:
                safe_addstr(self.stdscr, text_y, cursor_screen_x, "█", self.C_CYAN)

        # Helper line below inner box
        helper_y = inner_box_y + 3
        self.rect_target_helper = (helper_y, x + 2, width - 4)
        if target_error:
            err_text = f"⚠ {target_error}"
            safe_addstr(self.stdscr, helper_y, x + 2, err_text[: width - 4], self.C_RED)
        else:
            helper = "192.168.1.1 · scanme.nmap.org · 10.0.0.0/24"
            if profile.scan_type == "file":
                helper = "targets.txt · /home/user/hosts.list"
            safe_addstr(self.stdscr, helper_y, x + 2, helper[: width - 4], self.C_HELPER)

        # If custom scan: show custom arguments
        if profile.scan_type == "custom" and height >= 7:
            c_label = "Custom args:"
            safe_addstr(self.stdscr, y + 4, x + 2, c_label, self.C_DIM)
            c_display = f"[ {custom_args} ]"
            safe_addstr(self.stdscr, y + 4, x + 2 + len(c_label) + 1, c_display[: width - len(c_label) - 5], self.C_YELLOW)

        return (text_y, text_x + visible_cursor_col)

    def _render_selected_scan(
        self,
        y: int,
        x: int,
        height: int,
        width: int,
        profile: ScanProfile,
        target: str,
        custom_args: str,
        button_focused: bool,
        is_scanning: bool = False,
    ):
        """Renders the middle-right Selected Scan panel."""
        needs_root = any(f in getattr(profile, "flags", []) for f in ("-O", "-A", "-sU")) or profile.scan_type in ("os", "aggressive", "udp")
        is_root = (hasattr(os, "geteuid") and os.geteuid() == 0)
        right_tag = "⚠ sudo required" if (needs_root and not is_root) else ""

        draw_box(
            self.stdscr,
            y,
            x,
            height,
            width,
            title="SELECTED SCAN",
            right_tag=right_tag,
            border_attr=self.C_BORDER,
            title_attr=self.C_CYAN,
            tag_attr=self.C_YELLOW,
        )

        inner_w = width - 4

        # 1. Type
        safe_addstr(self.stdscr, y + 1, x + 2, "Type", self.C_DIM)
        DISPLAY_NAMES = {
            "Quick Scan": "Quick scan",
            "Service & Version": "Service & version",
            "Full Port Scan": "Full port scan",
            "OS Detection": "OS detection",
            "Aggressive Scan": "Aggressive scan",
            "UDP Scan": "UDP scan",
            "Custom Scan": "Custom scan",
            "Scan from File": "Scan from file",
            "Scan History": "Scan history",
            "Exit": "Exit",
        }
        prof_name = DISPLAY_NAMES.get(profile.name, profile.name)
        name_x = x + width - 2 - len(prof_name)
        if name_x > x + 8:
            safe_addstr(self.stdscr, y + 1, name_x, prof_name, self.C_WHITE)

        # 2. Command label
        safe_addstr(self.stdscr, y + 2, x + 2, "Command", self.C_DIM)
        from zenmapCore.tui.builder import CommandBuilder
        preview_cmd = CommandBuilder.build_display_command(profile, target, custom_args)

        cmd_box_y = y + 3
        cmd_box_x = x + 2
        cmd_box_w = width - 4
        if height >= 10:
            draw_box(self.stdscr, cmd_box_y, cmd_box_x, 3, cmd_box_w, border_attr=self.C_YELLOW | curses.A_DIM)
            safe_addstr(self.stdscr, cmd_box_y + 1, cmd_box_x + 2, preview_cmd[:cmd_box_w - 4], self.C_YELLOW)
            next_y = cmd_box_y + 3
        else:
            cmd_line = f"[ {preview_cmd} ]"
            safe_addstr(self.stdscr, cmd_box_y, cmd_box_x, cmd_line[:cmd_box_w], self.C_YELLOW)
            next_y = cmd_box_y + 1

        # 3. Description
        desc = profile.description
        desc_avail = inner_w
        if len(desc) > desc_avail and height >= 10:
            safe_addstr(self.stdscr, next_y, x + 2, desc[:desc_avail], self.C_DIM)
            safe_addstr(self.stdscr, next_y + 1, x + 2, desc[desc_avail : desc_avail * 2], self.C_DIM)
        else:
            safe_addstr(self.stdscr, next_y, x + 2, desc[:desc_avail], self.C_DIM)

        # 4. Button: ▶ EXECUTE SCAN or ■ CANCEL SCAN
        if is_scanning:
            btn_box_text = "■ CANCEL SCAN"
            btn_flat_text = "[ ■ CANCEL SCAN ]"
            btn_color = self.C_RED | curses.A_BOLD
            box_border = self.C_RED
        else:
            btn_box_text = "▶ EXECUTE SCAN"
            btn_flat_text = "[ ▶ EXECUTE SCAN ]"
            btn_color = self.C_GREEN | curses.A_BOLD
            box_border = self.C_GREEN

        if height >= 10:
            btn_w = len(btn_box_text) + 4
            btn_h = 3
            btn_y = y + height - 4
            btn_x = x + 2
            self.rect_execute_btn = (btn_y, btn_x, btn_h, btn_w)
            draw_box(self.stdscr, btn_y, btn_x, btn_h, btn_w, border_attr=box_border)
            btn_attr = self.C_BTN if button_focused else btn_color
            safe_addstr(self.stdscr, btn_y + 1, btn_x + 2, btn_box_text, btn_attr)
        else:
            btn_w = len(btn_flat_text)
            btn_h = 1
            btn_x = x + 2
            btn_y = y + height - 2
            self.rect_execute_btn = (btn_y, btn_x, btn_h, btn_w)
            btn_attr = self.C_BTN if button_focused else btn_color
            safe_addstr(self.stdscr, btn_y, btn_x, btn_flat_text, btn_attr)

    def _render_output_panel(
        self,
        y: int,
        x: int,
        height: int,
        width: int,
        output_lines: List[str],
        output_scroll: int,
        scan_state_str: str,
        is_focused: bool,
        show_severity_legend: bool = False,
        is_scanning: bool = False,
        elapsed_secs: float = 0.0,
    ):
        """Renders the full-width bottom Output panel with live streaming output."""
        import time
        if is_scanning:
            spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
            s_idx = int(time.time() * 10) % len(spinner_frames)
            spinner = spinner_frames[s_idx]
            elapsed_m = int(elapsed_secs) // 60
            elapsed_s = int(elapsed_secs) % 60
            status_tag = f"{spinner} SCANNING [{elapsed_m:02d}:{elapsed_s:02d}]"
            status_color = self.C_YELLOW | curses.A_BOLD
        elif "Completed" in scan_state_str:
            status_tag = "✓ COMPLETED"
            status_color = self.C_GREEN | curses.A_BOLD
        elif "Scanning" in scan_state_str:
            status_tag = "● SCANNING..."
            status_color = self.C_YELLOW | curses.A_BOLD
        elif "Failed" in scan_state_str:
            status_tag = "✗ FAILED"
            status_color = self.C_RED | curses.A_BOLD
        elif "Cancelled" in scan_state_str:
            status_tag = "⊘ CANCELLED"
            status_color = self.C_YELLOW | curses.A_BOLD
        else:
            status_tag = ""
            status_color = self.C_DIM

        draw_box(
            self.stdscr,
            y,
            x,
            height,
            width,
            title="OUTPUT",
            right_tag=status_tag,
            border_attr=self.C_CYAN if is_focused else self.C_BORDER,
            title_attr=self.C_CYAN,
            tag_attr=status_color,
        )

        # Accent line directly under the top border
        safe_addstr(self.stdscr, y + 1, x + 1, "─" * (width - 2), self.C_CYAN)

        # Inner content bounds
        has_legend = (show_severity_legend and height >= 6)
        inner_h = max(1, height - (5 if has_legend else 3))
        inner_w = width - 6
        start_y = y + 2

        lines_to_render = list(output_lines)
        if is_scanning:
            spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
            s_idx = int(time.time() * 10) % len(spinner_frames)
            spinner = spinner_frames[s_idx]
            elapsed_m = int(elapsed_secs) // 60
            elapsed_s = int(elapsed_secs) % 60
            loading_row = f"  {spinner} Live scan in progress... [{elapsed_m:02d}:{elapsed_s:02d}]  (press 'c' to cancel)"
            lines_to_render.append(loading_row)

        if not lines_to_render:
            placeholder = "Ready to scan. Select an option above and press Enter or click Execute."
            safe_addstr(self.stdscr, start_y, x + 3, placeholder, self.C_HELPER)
        else:
            total_lines = len(lines_to_render)
            if output_scroll == 0:
                visible_start = max(0, total_lines - inner_h)
            else:
                visible_start = max(0, min(total_lines - inner_h, output_scroll))

            visible_slice = lines_to_render[visible_start : visible_start + inner_h]

            for idx, line in enumerate(visible_slice):
                row_y = start_y + idx

                # Live scan in progress row
                if "Live scan in progress..." in line:
                    safe_addstr(self.stdscr, row_y, x + 3, line[:inner_w], self.C_YELLOW | curses.A_BOLD)
                    continue

                # 1. Summary line rendering
                if line.startswith("Summary:"):
                    safe_addstr(self.stdscr, row_y, x + 3, "Summary: ", self.C_WHITE)
                    sum_x = x + 3 + len("Summary: ")
                    remainder = line[len("Summary:"):].strip()
                    tokens = remainder.split("·")
                    for t_idx, token in enumerate(tokens):
                        t_str = token.strip()
                        t_col = self.C_NORMAL
                        if "CRITICAL" in t_str:
                            t_col = self.C_RED
                        elif "HIGH" in t_str:
                            t_col = self.C_YELLOW
                        elif "MEDIUM" in t_str:
                            t_col = self.C_YELLOW
                        elif "LOW" in t_str:
                            t_col = self.C_GREEN
                        elif "INFO" in t_str:
                            t_col = self.C_CYAN

                        if sum_x < x + width - 3:
                            safe_addstr(self.stdscr, row_y, sum_x, t_str[:x + width - 3 - sum_x], t_col)
                            sum_x += len(t_str)
                        if t_idx < len(tokens) - 1 and sum_x < x + width - 3:
                            sep = "  ·  "
                            safe_addstr(self.stdscr, row_y, sum_x, sep[:x + width - 3 - sum_x], self.C_DIM)
                            sum_x += len(sep)
                    continue

                # 2. Check for severity tag
                tag_match = re.search(r"(\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\])", line)
                if tag_match:
                    prefix = line[:tag_match.start()]
                    tag_str = tag_match.group(1)
                    sev_type = tag_match.group(2)
                    suffix = line[tag_match.end():]

                    tag_color = {
                        "CRITICAL": self.C_RED,
                        "HIGH": self.C_YELLOW,
                        "MEDIUM": self.C_YELLOW,
                        "LOW": self.C_GREEN,
                        "INFO": self.C_CYAN,
                    }.get(sev_type, self.C_CYAN)

                    safe_addstr(self.stdscr, row_y, x + 3, prefix[:inner_w], self.C_NORMAL)
                    tag_x = x + 3 + len(prefix)
                    if tag_x < x + width - 3:
                        avail_tag = x + width - 3 - tag_x
                        safe_addstr(self.stdscr, row_y, tag_x, tag_str[:avail_tag], tag_color)
                        if suffix and tag_x + len(tag_str) < x + width - 3:
                            safe_addstr(
                                self.stdscr,
                                row_y,
                                tag_x + len(tag_str),
                                suffix[:x + width - 3 - tag_x - len(tag_str)],
                                self.C_NORMAL,
                            )
                    continue

                # 3. Default line highlighting for standard lines
                line_attr = self.C_NORMAL
                if "[▶]" in line:
                    line_attr = self.C_YELLOW
                elif "[✓]" in line:
                    line_attr = self.C_GREEN
                elif "[✗]" in line:
                    line_attr = self.C_RED
                elif "PORT" in line and "STATE" in line:
                    line_attr = self.C_CYAN | curses.A_BOLD
                elif "/tcp" in line or "/udp" in line:
                    if "open" in line:
                        line_attr = self.C_GREEN
                    elif "closed" in line or "filtered" in line:
                        line_attr = self.C_DIM
                elif "Nmap done:" in line:
                    line_attr = self.C_GREEN

                safe_addstr(self.stdscr, row_y, x + 3, line[:inner_w], line_attr)

            # Show scroll indicators if output exceeds panel height
            if total_lines > inner_h:
                scroll_info = f"[{visible_start + 1}-{min(total_lines, visible_start + inner_h)}/{total_lines}]"
                safe_addstr(self.stdscr, y, x + width - len(scroll_info) - len(status_tag) - 6, scroll_info, self.C_HELPER)

        # 4. Divider and Legend at bottom of Output panel
        if has_legend:
            div_y = y + height - 3
            safe_addstr(self.stdscr, div_y, x + 1, "─" * (width - 2), self.C_BORDER | curses.A_DIM)

            legend_y = y + height - 2
            curr_x = x + 3
            legend_items = [
                ("■ Critical", self.C_RED),
                ("■ High", self.C_YELLOW),
                ("■ Medium", self.C_YELLOW),
                ("■ Low", self.C_GREEN),
                ("■ Info", self.C_CYAN),
            ]
            for text, color in legend_items:
                if curr_x + len(text) < x + width - 2:
                    safe_addstr(self.stdscr, legend_y, curr_x, text, color)
                    curr_x += len(text) + 2

            disclaimer_full = "heuristic severity, not a full vuln scan"
            avail_disclaimer = (x + width - 3) - curr_x
            if avail_disclaimer >= len(disclaimer_full):
                safe_addstr(self.stdscr, legend_y, x + width - len(disclaimer_full) - 3, disclaimer_full, self.C_HELPER)

    def _render_footer(self, y: int, width: int, active_focus: str = "options"):
        """Renders the safe-use reminder and keyboard legend."""
        tip = "Use only on authorized targets."
        safe_addstr(self.stdscr, y, 2, tip, self.C_DIM)

        if active_focus in ("target", "custom_args"):
            legend_full = "Enter Confirm  Esc Cancel  ← → Cursor  Backspace Delete"
            legend_short = "Enter Confirm  Esc Cancel"
        else:
            legend_full = "↑ ↓ Navigate  Enter Select  q Exit"
            legend_short = "↑ ↓ Nav  Enter Select  q Exit"

        avail_for_legend = width - len(tip) - 4
        if avail_for_legend >= len(legend_full):
            safe_addstr(self.stdscr, y, width - len(legend_full) - 2, legend_full, self.C_DIM)
        elif avail_for_legend >= len(legend_short):
            safe_addstr(self.stdscr, y, width - len(legend_short) - 2, legend_short, self.C_DIM)
