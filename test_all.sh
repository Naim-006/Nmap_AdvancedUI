#!/usr/bin/env bash
#
# test_all.sh — Runs the full Nmap TUI test checklist and prints pass/fail
# per step. Safe targets only: defaults to 127.0.0.1. Some steps need sudo
# (OS Detection, Aggressive Scan, UDP Scan) — they are skipped with a clear
# note if not run as root, rather than silently failing.
#
# Usage:
#   ./test_all.sh                  # run everything against 127.0.0.1
#   TARGET=127.0.0.1 ./test_all.sh # override target
#   ./test_all.sh --skip-sudo      # skip steps that require root
#
# Exit code: 0 if all non-skipped steps passed, 1 otherwise.

set -u

TARGET="${TARGET:-127.0.0.1}"
TUI_BIN="${TUI_BIN:-./nmap-tui}"
ZENMAP_BIN="${ZENMAP_BIN:-./zenmap/zenmap}"
SKIP_SUDO=0
[[ "${1:-}" == "--skip-sudo" ]] && SKIP_SUDO=1

PASS=0
FAIL=0
SKIP=0
FAILED_STEPS=()

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); FAILED_STEPS+=("$1"); }
skip() { echo -e "${YELLOW}[SKIP]${NC} $1"; SKIP=$((SKIP+1)); }
section() { echo -e "\n${CYAN}== $1 ==${NC}"; }

run_ok() {
    # run_ok "description" cmd args...
    local desc="$1"; shift
    if "$@" >/tmp/test_all_out.log 2>&1; then
        pass "$desc"
    else
        fail "$desc (see /tmp/test_all_out.log)"
    fi
}

run_expect_fail() {
    # for cases where a non-zero exit / clean error IS the correct behavior
    local desc="$1"; shift
    if "$@" >/tmp/test_all_out.log 2>&1; then
        fail "$desc (expected a clean failure/error, but command succeeded)"
    else
        if grep -qiE "traceback|panic" /tmp/test_all_out.log; then
            fail "$desc (raw traceback leaked instead of a clean error)"
        else
            pass "$desc"
        fi
    fi
}

echo "Nmap TUI — full test run"
echo "Target: $TARGET"
echo "TUI binary: $TUI_BIN"
echo "Zenmap binary: $ZENMAP_BIN"

# ---------------------------------------------------------------------------
section "1. Automated test suites"
# ---------------------------------------------------------------------------
run_ok "pytest test_tui.py"          python -m pytest zenmap/test/test_tui.py -q
run_ok "zenmap existing test suite"  python zenmap/test/run_tests.py

# ---------------------------------------------------------------------------
section "2. Original CLI regression"
# ---------------------------------------------------------------------------
run_ok "zenmap --help"                         "$ZENMAP_BIN" --help
run_ok "zenmap -v"                             "$ZENMAP_BIN" -v
run_ok "zenmap -f"                             "$ZENMAP_BIN" -f
run_ok "zenmap CLI scan (Service & Version)"   "$ZENMAP_BIN" -t "$TARGET" -p "Service & Version"

# ---------------------------------------------------------------------------
section "3. TUI launch + target input"
# ---------------------------------------------------------------------------
if [[ -x "$TUI_BIN" ]]; then
    pass "TUI binary is present and executable"
else
    fail "TUI binary missing or not executable at $TUI_BIN"
fi
run_ok "TUI with -t/-p pre-fill (Quick Scan)" "$TUI_BIN" -t "$TARGET" -p "Quick Scan" --headless

# ---------------------------------------------------------------------------
section "4. Scan profiles + severity tags"
# ---------------------------------------------------------------------------
run_ok "Quick Scan"              "$TUI_BIN" -t "$TARGET" -p "Quick Scan" --headless
run_ok "Service & Version"       "$TUI_BIN" -t "$TARGET" -p "Service & Version" --headless
run_ok "Full Port Scan"          "$TUI_BIN" -t "$TARGET" -p "Full Port Scan" --headless
run_ok "Custom Scan (--script vuln)" "$TUI_BIN" -t "$TARGET" -p "Custom Scan" --args "-sV --script vuln" --headless

if [[ -f /tmp/targets.txt ]] || printf "127.0.0.1\nscanme.nmap.org\n" > /tmp/targets.txt; then
    run_ok "Scan from File" "$TUI_BIN" -p "Scan from File" --file /tmp/targets.txt --headless
fi

if [[ "$EUID" -eq 0 && "$SKIP_SUDO" -eq 0 ]]; then
    run_ok "OS Detection (sudo)"    "$TUI_BIN" -t "$TARGET" -p "OS Detection" --headless
    run_ok "Aggressive Scan (sudo)" "$TUI_BIN" -t "$TARGET" -p "Aggressive Scan" --headless
    run_ok "UDP Scan (sudo)"        "$TUI_BIN" -t "$TARGET" -p "UDP Scan" --headless
else
    skip "OS Detection (needs sudo — rerun as root or without --skip-sudo)"
    skip "Aggressive Scan (needs sudo)"
    skip "UDP Scan (needs sudo)"
fi

# ---------------------------------------------------------------------------
section "5. Failure handling"
# ---------------------------------------------------------------------------
run_expect_fail "Invalid custom scan args rejected cleanly" \
    "$TUI_BIN" -t "$TARGET" -p "Custom Scan" --args "-p 99999999" --headless

run_expect_fail "Invalid target rejected cleanly" \
    "$TUI_BIN" -t "not_a_valid_host!!" -p "Quick Scan" --headless

run_expect_fail "Missing target-list file rejected cleanly" \
    "$TUI_BIN" -p "Scan from File" --file /tmp/does_not_exist.txt --headless

# ---------------------------------------------------------------------------
section "6. Nmap-not-installed behavior"
# ---------------------------------------------------------------------------
NMAP_PATH="$(command -v nmap || true)"
if [[ "$EUID" -eq 0 && -n "$NMAP_PATH" && "$SKIP_SUDO" -eq 0 ]]; then
    sudo mv "$NMAP_PATH" "${NMAP_PATH}.bak" 2>/tmp/test_all_out.log
    run_expect_fail "Clean 'nmap not installed' error (no traceback)" \
        "$TUI_BIN" -t "$TARGET" -p "Quick Scan" --headless
    sudo mv "${NMAP_PATH}.bak" "$NMAP_PATH" 2>/tmp/test_all_out.log
else
    skip "Nmap-not-installed test (needs sudo to move the binary, or nmap not found)"
fi

# ---------------------------------------------------------------------------
section "7. Plain-text / --no-color mode"
# ---------------------------------------------------------------------------
OUT=$("$TUI_BIN" --no-color -t "$TARGET" -p "Service & Version" --headless 2>&1)
if echo "$OUT" | grep -qE '\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]'; then
    pass "--no-color output shows bracketed severity words"
else
    fail "--no-color output missing bracketed severity tags"
fi

# ---------------------------------------------------------------------------
section "8. Scan History"
# ---------------------------------------------------------------------------
run_ok "Scan History readable after prior runs" "$TUI_BIN" -p "Scan History" --headless

# ---------------------------------------------------------------------------
section "Summary"
# ---------------------------------------------------------------------------
echo -e "\n${GREEN}Passed: $PASS${NC}  ${RED}Failed: $FAIL${NC}  ${YELLOW}Skipped: $SKIP${NC}"
if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}Failed steps:${NC}"
    for step in "${FAILED_STEPS[@]}"; do
        echo "  - $step"
    done
    exit 1
fi
exit 0
