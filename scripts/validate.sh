#!/bin/bash
# Validate project structure, syntax, and configuration without requiring root.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

PASS=0
FAIL=0
WARN=0

pass() { echo "  [PASS] $1"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL + 1)); }
warn() { echo "  [WARN] $1"; WARN=$((WARN + 1)); }

echo "=== Docker Security Monitoring — Validation ==="
echo ""

# --- Python eBPF scripts ---
echo "Python eBPF scripts:"
for f in ebpf/*.py; do
    if python3 -m py_compile "$f" 2>/dev/null; then
        pass "$(basename "$f")"
    else
        fail "$(basename "$f") — syntax error"
    fi
done
echo ""

# --- Shell scripts ---
echo "Shell trigger scripts:"
for f in ebpf_shell_scripts/*.sh "falco_rules_shell _scripts"/*.sh; do
    if bash -n "$f" 2>/dev/null; then
        pass "$(basename "$f")"
    else
        fail "$(basename "$f") — syntax error"
    fi
done
echo ""

# --- Falco YAML rules ---
echo "Falco YAML rules:"
for f in falco_rules/rules.d/*.yaml; do
    if python3 -c "import yaml; yaml.safe_load(open('$f'))" 2>/dev/null; then
        pass "$(basename "$f")"
    else
        fail "$(basename "$f") — invalid YAML"
    fi
done
echo ""

# --- Required files ---
echo "Required project files:"
for f in README.md requirements.txt docs/ARCHITECTURE.md docs/RUNNING.md LICENSE; do
    if [ -f "$f" ]; then
        pass "$f exists"
    else
        fail "$f missing"
    fi
done
echo ""

# --- Directory structure ---
echo "Directory structure:"
for d in ebpf ebpf_shell_scripts falco_rules/rules.d "falco_rules_shell _scripts" images docs scripts docker; do
    if [ -d "$d" ]; then
        pass "$d/"
    else
        fail "$d/ missing"
    fi
done
echo ""

# --- Count checks ---
EBPF_COUNT=$(ls -1 ebpf/*.py 2>/dev/null | wc -l)
FALCO_COUNT=$(ls -1 falco_rules/rules.d/*.yaml 2>/dev/null | wc -l)
EBPF_SH_COUNT=$(ls -1 ebpf_shell_scripts/*.sh 2>/dev/null | wc -l)
FALCO_SH_COUNT=$(ls -1 "falco_rules_shell _scripts"/*.sh 2>/dev/null | wc -l)

echo "Inventory:"
echo "  eBPF monitors:      $EBPF_COUNT"
echo "  Falco rules:        $FALCO_COUNT"
echo "  eBPF test scripts:  $EBPF_SH_COUNT"
echo "  Falco test scripts: $FALCO_SH_COUNT"
echo ""

# --- Shebang checks ---
echo "Shebang checks:"
for f in ebpf/*.py; do
    if head -1 "$f" | grep -q '#!/usr/bin/env python3'; then
        pass "$(basename "$f") has shebang"
    else
        warn "$(basename "$f") missing shebang"
    fi
done
echo ""

# --- Summary ---
echo "=== Summary ==="
echo "  Passed:   $PASS"
echo "  Failed:   $FAIL"
echo "  Warnings: $WARN"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "Validation FAILED."
    exit 1
else
    echo "Validation PASSED."
    exit 0
fi
