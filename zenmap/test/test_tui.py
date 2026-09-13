import os
import sys
import tempfile
import time
import unittest

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from zenmapCore.tui.profiles import get_default_profiles, ScanProfile
from zenmapCore.tui.builder import CommandBuilder, ValidationError
from zenmapCore.tui.runner import ScanRunner, ScanState
from zenmapCore.tui.history import ScanHistory, ScanRecord


class TestScanProfiles(unittest.TestCase):
    def test_default_profiles_count_and_keys(self):
        profiles = get_default_profiles()
        self.assertEqual(len(profiles), 10)
        expected_keys = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0"]
        self.assertEqual([p.key for p in profiles], expected_keys)

    def test_profile_names_and_commands(self):
        profiles = get_default_profiles()
        self.assertEqual(profiles[0].name, "Quick Scan")
        self.assertEqual(profiles[0].command_template, "nmap -T4 -F")
        self.assertEqual(profiles[1].name, "Service & Version")
        self.assertEqual(profiles[1].command_template, "nmap -sV")
        self.assertEqual(profiles[2].name, "Full Port Scan")
        self.assertEqual(profiles[2].command_template, "nmap -p-")
        self.assertEqual(profiles[3].name, "OS Detection")
        self.assertEqual(profiles[3].command_template, "nmap -O")
        self.assertEqual(profiles[4].name, "Aggressive Scan")
        self.assertEqual(profiles[4].command_template, "nmap -A")
        self.assertEqual(profiles[5].name, "UDP Scan")
        self.assertEqual(profiles[5].command_template, "nmap -sU")
        self.assertEqual(profiles[6].name, "Custom Scan")
        self.assertEqual(profiles[7].name, "Scan from File")
        self.assertEqual(profiles[8].name, "Scan History")
        self.assertEqual(profiles[9].name, "Exit")

    def test_display_command(self):
        profiles = get_default_profiles()
        self.assertEqual(profiles[0].get_display_command("127.0.0.1"), "nmap -T4 -F 127.0.0.1")
        self.assertEqual(profiles[8].get_display_command(), "(view past scans)")
        self.assertEqual(profiles[9].get_display_command(), "(quit application)")


class TestCommandBuilder(unittest.TestCase):
    def setUp(self):
        self.profiles = get_default_profiles()

    def test_target_validation_valid(self):
        valid_targets = [
            "127.0.0.1",
            "192.168.1.100",
            "::1",
            "localhost",
            "scanme.nmap.org",
            "10.0.0.0/24",
            "192.168.1.1-50",
            "192.168.1.1 192.168.1.2",
        ]
        for t in valid_targets:
            is_valid, msg = CommandBuilder.validate_target(t)
            self.assertTrue(is_valid, f"Expected '{t}' to be valid, got error: {msg}")

    def test_target_validation_invalid(self):
        invalid_targets = [
            "",
            "   ",
            "not a valid host!@#$",
            "999.999.999.999",
        ]
        for t in invalid_targets:
            is_valid, _ = CommandBuilder.validate_target(t)
            self.assertFalse(is_valid, f"Expected '{t}' to be invalid")

    def test_file_target_validation(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.write("127.0.0.1\n192.168.1.1\n")
            tmp_path = tmp.name

        try:
            is_valid, _ = CommandBuilder.validate_target(tmp_path, is_file_scan=True)
            self.assertTrue(is_valid)

            is_valid_nonexist, err = CommandBuilder.validate_target("/nonexistent/file/targets.txt", is_file_scan=True)
            self.assertFalse(is_valid_nonexist)
            self.assertIn("does not exist", err)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_build_command_quick_scan(self):
        cmd = CommandBuilder.build_command(self.profiles[0], "127.0.0.1")
        self.assertTrue(cmd[0].endswith("nmap"))
        self.assertIn("-T4", cmd)
        self.assertIn("-F", cmd)
        self.assertEqual(cmd[-1], "127.0.0.1")

    def test_build_command_custom_scan(self):
        cmd = CommandBuilder.build_command(self.profiles[6], "127.0.0.1", custom_args="-p 80,443 -sC")
        self.assertTrue(cmd[0].endswith("nmap"))
        self.assertIn("-p", cmd)
        self.assertIn("80,443", cmd)
        self.assertIn("-sC", cmd)
        self.assertIn("127.0.0.1", cmd)

    def test_build_command_invalid_target_raises(self):
        with self.assertRaises(ValidationError):
            CommandBuilder.build_command(self.profiles[0], "")


class TestScanRunner(unittest.TestCase):
    def test_scan_execution_and_streaming(self):
        runner = ScanRunner()
        cmd = ["echo", "Starting test scan\nPORT 80/tcp open\nNmap done"]
        runner.start_scan(cmd, "echo test", "127.0.0.1", "Test Profile")

        # Wait for completion
        for _ in range(50):
            if not runner.is_running():
                break
            time.sleep(0.05)

        self.assertEqual(runner.state, ScanState.COMPLETED)
        output = runner.get_output_copy()
        self.assertTrue(any("Starting test scan" in line for line in output))
        self.assertTrue(any("Scan completed" in line for line in output))

    def test_scan_cancellation(self):
        runner = ScanRunner()
        cmd = ["sleep", "5"]
        runner.start_scan(cmd, "sleep 5", "127.0.0.1", "Sleep Scan")
        time.sleep(0.1)
        self.assertTrue(runner.is_running())

        runner.cancel()
        time.sleep(0.2)
        self.assertFalse(runner.is_running())
        self.assertEqual(runner.state, ScanState.CANCELLED)

    def test_missing_binary(self):
        runner = ScanRunner()
        cmd = ["/bin/nonexistent_nmap_binary_xyz", "127.0.0.1"]
        runner.start_scan(cmd, "invalid", "127.0.0.1", "Invalid")
        time.sleep(0.1)
        self.assertEqual(runner.state, ScanState.FAILED)
        output = runner.get_output_copy()
        self.assertTrue(any("not found in PATH" in line or "failed" in line for line in output))


class TestScanHistory(unittest.TestCase):
    def test_history_persistence(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            history = ScanHistory(history_file=tmp_path)
            self.assertEqual(len(history.records), 0)

            rec = history.add_record(
                target="127.0.0.1",
                profile="Quick Scan",
                command="nmap -T4 -F 127.0.0.1",
                outcome=ScanState.COMPLETED,
                duration=0.5,
                output_lines=["Starting Nmap", "PORT 22/tcp open ssh", "Nmap done"],
            )
            self.assertEqual(rec.record_id, 1)
            self.assertEqual(len(history.records), 1)

            # Reload from disk
            history2 = ScanHistory(history_file=tmp_path)
            self.assertEqual(len(history2.records), 1)
            self.assertEqual(history2.records[0].target, "127.0.0.1")
            self.assertEqual(history2.records[0].profile, "Quick Scan")
            self.assertEqual(history2.records[0].outcome, ScanState.COMPLETED)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


class TestTargetInputEditing(unittest.TestCase):
    class MockWin:
        def __init__(self, h=28, w=100):
            self.h, self.w = h, w
        def getmaxyx(self):
            return self.h, self.w
        def erase(self): pass
        def refresh(self): pass
        def addstr(self, y, x, text, attr=0): pass
        def move(self, y, x): pass
        def timeout(self, ms): pass

    def setUp(self):
        from zenmapCore.tui.app import NmapTUI
        self.app = NmapTUI(self.MockWin())

    def test_initial_empty_target(self):
        self.assertEqual(self.app.target, "")
        self.assertEqual(self.app.active_focus, "options")

    def test_focus_and_typing_target(self):
        # Press Tab to focus target
        self.app._handle_options_input(ord("\t"))
        self.assertEqual(self.app.active_focus, "target")

        # Type 10.10.10.10
        for ch in "10.10.10.10":
            self.app._handle_target_input(ord(ch))
        self.assertEqual(self.app.target, "10.10.10.10")

        # Confirm via Enter
        self.app._handle_target_input(10)
        self.assertEqual(self.app.active_focus, "options")
        self.assertEqual(self.app.target, "10.10.10.10")

        # Preview reflects typed target
        prof = self.app.profiles[self.app.selected_index]
        disp = CommandBuilder.build_display_command(prof, self.app.target)
        self.assertEqual(disp, "nmap -T4 -F 10.10.10.10")

        # CommandBuilder uses typed target
        cmd = CommandBuilder.build_command(prof, self.app.target)
        self.assertEqual(cmd[-1], "10.10.10.10")

    def test_number_keys_distinction(self):
        # In options mode, '3' jumps to Full Port Scan
        self.app._handle_options_input(ord("3"))
        self.assertEqual(self.app.profiles[self.app.selected_index].name, "Full Port Scan")

        # Enter target mode using 't'
        self.app._handle_options_input(ord("t"))
        self.assertEqual(self.app.active_focus, "target")

        # In target mode, '5' is typed as a digit, not jumping to Aggressive Scan
        self.app._handle_target_input(ord("5"))
        self.assertEqual(self.app.target, "5")
        self.assertEqual(self.app.profiles[self.app.selected_index].name, "Full Port Scan")

    def test_cursor_movement_and_editing(self):
        import curses
        self.app._handle_options_input(ord("t"))
        for ch in "192.168.1.1":
            self.app._handle_target_input(ord(ch))

        # Left arrow moves cursor
        self.app._handle_target_input(curses.KEY_LEFT)
        self.assertEqual(self.app.cursor_col, len("192.168.1.1") - 1)

        # Backspace deletes
        self.app._handle_target_input(127)
        self.assertEqual(self.app.target, "192.168.11")

        # Esc restores original value
        self.app._handle_target_input(27)
        self.assertEqual(self.app.active_focus, "options")
        self.assertEqual(self.app.target, "")

    def test_empty_target_blocked_with_inline_error(self):
        self.app.target = ""
        self.app._execute_selected_action()
        self.assertTrue(bool(self.app.target_error))
        self.assertIn("empty", self.app.target_error.lower())
        self.assertFalse(self.app.runner.is_running())

    def test_invalid_target_blocked_with_inline_error(self):
        self.app.target = "abc!!"
        self.app._execute_selected_action()
        self.assertTrue(bool(self.app.target_error))
        self.assertIn("invalid", self.app.target_error.lower())
        self.assertFalse(self.app.runner.is_running())

    def test_cli_target_prefilling(self):
        from zenmapCore.tui.app import NmapTUI
        app = NmapTUI(self.MockWin(), initial_target="10.10.10.10")
        self.assertEqual(app.target, "10.10.10.10")
        # Can still be edited
        app._handle_options_input(ord("t"))
        self.assertEqual(app.active_focus, "target")
        import curses
        app._handle_target_input(curses.KEY_BACKSPACE)
        self.assertEqual(app.target, "10.10.10.1")


class TestSeverityTagging(unittest.TestCase):
    def test_evaluate_service_severity_signatures(self):
        from zenmapCore.tui.severity import (
            evaluate_service_severity,
            CRITICAL,
            HIGH,
            MEDIUM,
            LOW,
            INFO,
        )
        # Critical signatures
        self.assertEqual(evaluate_service_severity("ftp", "vsftpd 2.3.4 (known backdoor)"), CRITICAL)
        self.assertEqual(evaluate_service_severity("microsoft-ds", "smb-vuln-ms17-010 vulnerable"), CRITICAL)

        # High signatures
        self.assertEqual(evaluate_service_severity("mysql", "MySQL 5.5.9 (outdated, unauth access)"), HIGH)
        self.assertEqual(evaluate_service_severity("ftp", "ProFTPD 1.3.3c"), HIGH)
        self.assertEqual(evaluate_service_severity("rlogin", ""), HIGH)

        # Medium signatures
        self.assertEqual(evaluate_service_severity("http", "Apache 2.4.41"), MEDIUM)
        self.assertEqual(evaluate_service_severity("telnet", ""), MEDIUM)
        self.assertEqual(evaluate_service_severity("vnc", "VNC protocol"), MEDIUM)
        self.assertEqual(evaluate_service_severity("snmp", ""), MEDIUM)

        # Low signatures
        self.assertEqual(evaluate_service_severity("ssh", "OpenSSH 8.9"), LOW)
        self.assertEqual(evaluate_service_severity("https", "nginx 1.18.0"), LOW)
        self.assertEqual(evaluate_service_severity("domain", "BIND 9.16"), LOW)

        # Unrecognized / unknown service falls back to INFO
        self.assertEqual(evaluate_service_severity("custom-proto", "1.0"), INFO)

    def test_tag_port_line(self):
        from zenmapCore.tui.severity import tag_port_line, CRITICAL, HIGH, MEDIUM, LOW

        line1 = "21/tcp open ftp vsftpd 2.3.4 (known backdoor)"
        tagged1, sev1 = tag_port_line(line1)
        self.assertEqual(sev1, CRITICAL)
        self.assertTrue(tagged1.endswith("[CRITICAL]"))

        line2 = "22/tcp open ssh OpenSSH 8.9"
        tagged2, sev2 = tag_port_line(line2)
        self.assertEqual(sev2, LOW)
        self.assertTrue(tagged2.endswith("[LOW]"))

        line3 = "80/tcp open http Apache 2.4.41"
        tagged3, sev3 = tag_port_line(line3)
        self.assertEqual(sev3, MEDIUM)
        self.assertTrue(tagged3.endswith("[MEDIUM]"))

        line4 = "3306/tcp open mysql MySQL 5.5.9"
        tagged4, sev4 = tag_port_line(line4)
        self.assertEqual(sev4, HIGH)
        self.assertTrue(tagged4.endswith("[HIGH]"))

        # Closed or filtered ports should not be tagged
        line_closed = "25/tcp closed smtp"
        tagged_closed, sev_closed = tag_port_line(line_closed)
        self.assertIsNone(sev_closed)
        self.assertEqual(tagged_closed, line_closed)

        # Non-port lines should not be tagged
        line_scan = "Nmap scan report for 10.10.10.10 — host is up"
        tagged_scan, sev_scan = tag_port_line(line_scan)
        self.assertIsNone(sev_scan)
        self.assertEqual(tagged_scan, line_scan)

    def test_supports_service_tagging(self):
        from zenmapCore.tui.severity import supports_service_tagging

        self.assertTrue(supports_service_tagging(["nmap", "-sV", "10.10.10.10"]))
        self.assertTrue(supports_service_tagging(["nmap", "-A", "10.10.10.10"]))
        self.assertTrue(supports_service_tagging(["nmap", "--script", "vuln", "10.10.10.10"]))

        # Bare port scans should NOT support service tagging
        self.assertFalse(supports_service_tagging(["nmap", "-T4", "-F", "10.10.10.10"]))
        self.assertFalse(supports_service_tagging(["nmap", "-p-", "10.10.10.10"]))
        self.assertFalse(supports_service_tagging(["nmap", "-O", "10.10.10.10"]))
        self.assertFalse(supports_service_tagging(["nmap", "-sU", "10.10.10.10"]))

    def test_parse_script_vuln_severity(self):
        from zenmapCore.tui.severity import (
            parse_script_vuln_severity,
            CRITICAL,
            HIGH,
            MEDIUM,
            LOW,
        )
        self.assertEqual(parse_script_vuln_severity("|_  CVE-2017-0143: 9.3"), CRITICAL)
        self.assertEqual(parse_script_vuln_severity("|_  CVE-2021-41773  7.5  https://..."), HIGH)
        self.assertEqual(parse_script_vuln_severity("|_  CVE-2018-1234  5.0"), MEDIUM)
        self.assertEqual(parse_script_vuln_severity("|_  CVE-2019-5678  2.1"), LOW)
        self.assertEqual(parse_script_vuln_severity("|   State: VULNERABLE"), HIGH)
        self.assertIsNone(parse_script_vuln_severity("|_  Nothing found here"))

    def test_view_render_with_severity_and_legend(self):
        from zenmapCore.tui.view import TUIView
        from zenmapCore.tui.profiles import get_default_profiles

        class MockStdscr:
            def __init__(self):
                self.calls = []
            def getmaxyx(self):
                return (30, 120)
            def erase(self):
                pass
            def refresh(self):
                pass
            def addstr(self, y, x, s, attr=0):
                self.calls.append((y, x, s, attr))
            def move(self, y, x):
                pass

        mock_win = MockStdscr()
        view = TUIView(mock_win)
        profiles = get_default_profiles()
        output_lines = [
            "Nmap scan report for 10.10.10.10 — host is up",
            "22/tcp open ssh OpenSSH 8.9  [LOW]",
            "80/tcp open http Apache 2.4.41  [MEDIUM]",
            "443/tcp open https nginx 1.18.0  [LOW]",
            "21/tcp open ftp vsftpd 2.3.4 (known backdoor)  [CRITICAL]",
            "3306/tcp open mysql MySQL 5.5.9 (outdated, unauth access)  [HIGH]",
            "",
            "Summary: 1 CRITICAL  ·  1 HIGH  ·  1 MEDIUM  ·  2 LOW",
        ]

        # Render with show_severity_legend=True
        view.render(
            profiles=profiles,
            selected_index=1,
            target="10.10.10.10",
            custom_args="",
            active_focus="options",
            output_lines=output_lines,
            output_scroll=0,
            scan_state_str="Completed",
            show_severity_legend=True,
        )

        all_text = " ".join(call[2] for call in mock_win.calls)
        self.assertIn("■ Critical", all_text)
        self.assertIn("■ High", all_text)
        self.assertIn("■ Medium", all_text)
        self.assertIn("■ Low", all_text)
        self.assertIn("■ Info", all_text)
        self.assertIn("heuristic severity", all_text)
        self.assertIn("Summary:", all_text)
        self.assertIn("[CRITICAL]", all_text)
        self.assertIn("By ajmine", all_text)
        self.assertNotIn("By You", all_text)

    def test_runner_severity_tagging_live_and_upgrade(self):
        from zenmapCore.tui.runner import ScanRunner
        runner = ScanRunner()
        py_code = (
            "import sys; "
            "print('Starting Nmap'); "
            "print('21/tcp open ftp vsftpd 2.3.4 (known backdoor)'); "
            "print('80/tcp open http test 1.0'); "
            "print('|_  CVE-2023-1234: 9.8'); "
            "print('Nmap done: 1 IP address scanned'); "
            "sys.stdout.flush()"
        )
        cmd_args = [sys.executable, "-c", py_code, "-sV"]
        runner.start_scan(cmd_args, "nmap -sV 10.10.10.10", "10.10.10.10", "Service & Version")
        runner._thread.join(timeout=3.0)

        out = runner.get_output_copy()
        out_str = "\n".join(out)
        self.assertTrue(runner.has_severity_tags)
        self.assertEqual(runner.severity_counts["CRITICAL"], 2)
        self.assertIn("21/tcp open ftp vsftpd 2.3.4 (known backdoor)  [CRITICAL]", out_str)
        self.assertIn("80/tcp open http test 1.0  [CRITICAL]", out_str)
        self.assertIn("Summary: 2 CRITICAL", out_str)

    def test_runner_no_tagging_on_quick_scan(self):
        from zenmapCore.tui.runner import ScanRunner
        runner_quick = ScanRunner()
        py_code_quick = (
            "import sys; "
            "print('Starting Nmap'); "
            "print('22/tcp open ssh'); "
            "print('Nmap done: 1 IP address scanned'); "
            "sys.stdout.flush()"
        )
        cmd_args_quick = [sys.executable, "-c", py_code_quick, "-T4", "-F"]
        runner_quick.start_scan(cmd_args_quick, "nmap -T4 -F 10.10.10.10", "10.10.10.10", "Quick Scan")
        runner_quick._thread.join(timeout=3.0)

        out_quick = runner_quick.get_output_copy()
        out_quick_str = "\n".join(out_quick)
        self.assertFalse(runner_quick.has_severity_tags)
        self.assertNotIn("[LOW]", out_quick_str)
        self.assertNotIn("Summary:", out_quick_str)


class TestMouseAndLiveScanning(unittest.TestCase):
    def setUp(self):
        self.profiles = get_default_profiles()

    def test_live_scanning_rendering(self):
        from zenmapCore.tui.view import TUIView

        class MockStdscr:
            def __init__(self):
                self.calls = []
            def getmaxyx(self):
                return (30, 120)
            def erase(self):
                pass
            def refresh(self):
                pass
            def addstr(self, y, x, s, attr=0):
                self.calls.append((y, x, s, attr))
            def move(self, y, x):
                pass

        mock_win = MockStdscr()
        view = TUIView(mock_win)
        output_lines = ["Starting Nmap scan..."]

        view.render(
            profiles=self.profiles,
            selected_index=0,
            target="10.10.10.10",
            custom_args="",
            active_focus="options",
            output_lines=output_lines,
            output_scroll=0,
            scan_state_str="Scanning...",
            is_scanning=True,
            elapsed_secs=14.0,
        )

        all_text = " ".join(call[2] for call in mock_win.calls)
        self.assertIn("SCANNING [00:14]", all_text)
        self.assertIn("Live scan in progress... [00:14]", all_text)
        self.assertIn("CANCEL SCAN", all_text)

    def test_mouse_interactions(self):
        import curses
        from zenmapCore.tui.app import NmapTUI

        class MockStdscr:
            def __init__(self):
                self.calls = []
            def getmaxyx(self):
                return (30, 120)
            def erase(self):
                pass
            def refresh(self):
                pass
            def addstr(self, y, x, s, attr=0):
                self.calls.append((y, x, s, attr))
            def move(self, y, x):
                pass
            def timeout(self, ms):
                pass

        mock_win = MockStdscr()
        app = NmapTUI(mock_win, initial_target="127.0.0.1")

        # Initial render to set up view rects
        app.view.render(
            profiles=app.profiles,
            selected_index=app.selected_index,
            target=app.target,
            custom_args=app.custom_args,
            active_focus=app.active_focus,
            output_lines=app.output_lines,
            output_scroll=app.output_scroll,
            scan_state_str=app.scan_state_str,
        )

        # 1. Test clicking Target input box
        in_y, in_x, in_h, in_w = app.view.rect_target_input
        app.active_focus = "options"
        app._handle_mouse_event(in_x + 5, in_y + 1, curses.BUTTON1_CLICKED)
        self.assertEqual(app.active_focus, "target")

        # 2. Test clicking helper example (scanme.nmap.org)
        hlp_y, hlp_x, hlp_w = app.view.rect_target_helper
        # "192.168.1.1 · scanme.nmap.org · 10.0.0.0/24"
        # scanme.nmap.org is located ~15 chars after start_x
        app._handle_mouse_event(hlp_x + 20, hlp_y, curses.BUTTON1_CLICKED)
        self.assertEqual(app.target, "scanme.nmap.org")
        self.assertEqual(app.active_focus, "target")

        # 3. Test clicking Scan Options item 3 (Full Port Scan, index 2)
        opt_y, opt_x, opt_h, opt_w = app.view.rect_options
        app._handle_mouse_event(opt_x + 10, opt_y + 3, curses.BUTTON1_CLICKED)
        self.assertEqual(app.selected_index, 2)
        self.assertEqual(app.profiles[app.selected_index].name, "Full Port Scan")


if __name__ == "__main__":
    unittest.main()

