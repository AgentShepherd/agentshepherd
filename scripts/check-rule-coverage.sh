#!/usr/bin/env bash
# check-rule-coverage.sh - Verify each security rule has test and fuzz coverage
#
# This script extracts all rule names from security.yaml and verifies each rule:
# 1. Has a COVERS marker in fuzz_test.go (fuzz coverage)
# 2. Has its name mentioned in test files (unit test coverage)
#
# It also warns about orphaned COVERS markers for deleted rules.
#
# To add coverage for a rule:
#   1. Add fuzz seeds and marker: // COVERS: rule-name
#   2. Add unit test that mentions the rule name
#
# Exit codes:
#   0 - All rules have coverage
#   1 - Some rules are missing coverage

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

SECURITY_YAML="$ROOT_DIR/internal/rules/builtin/security.yaml"
RULES_DIR="$ROOT_DIR/internal/rules"

if [[ ! -f "$SECURITY_YAML" ]]; then
    echo "ERROR: security.yaml not found at $SECURITY_YAML"
    exit 1
fi

if [[ ! -d "$RULES_DIR" ]]; then
    echo "ERROR: rules directory not found at $RULES_DIR"
    exit 1
fi

# Extract rule names from security.yaml
mapfile -t RULES < <(grep -E '^\s+-\s+name:\s+' "$SECURITY_YAML" | sed 's/.*name:\s*//' | tr -d ' ')

echo "=== Rule Coverage Check ==="
echo ""
echo "Rules in security.yaml: ${#RULES[@]}"
echo ""

# Check fuzz coverage (COVERS markers)
FUZZ_TEST="$RULES_DIR/fuzz_test.go"
mapfile -t COVERS_MARKERS < <(grep -E '//\s*COVERS:\s*' "$FUZZ_TEST" 2>/dev/null | sed 's/.*COVERS:\s*//' | tr -d ' ' || true)
FUZZ_COVERED=$(printf '%s\n' "${COVERS_MARKERS[@]}" | tr '\n' ' ')

FUZZ_MISSING=()
UNIT_MISSING=()
ALL_OK=()

for rule in "${RULES[@]}"; do
    fuzz_ok=false
    unit_ok=false

    # Check fuzz coverage - rule name in COVERS markers
    if echo " $FUZZ_COVERED " | grep -qF " $rule "; then
        fuzz_ok=true
    fi

    # Check unit test coverage - rule name appears in any test file
    # Use grep directly on files instead of a variable
    if grep -rqF "$rule" "$RULES_DIR"/*_test.go 2>/dev/null; then
        unit_ok=true
    fi

    if $fuzz_ok && $unit_ok; then
        ALL_OK+=("$rule")
    else
        if ! $fuzz_ok; then
            FUZZ_MISSING+=("$rule")
        fi
        if ! $unit_ok; then
            UNIT_MISSING+=("$rule")
        fi
    fi
done

# Check for orphaned COVERS markers (rules deleted from security.yaml)
ORPHANED=()
for marker in "${COVERS_MARKERS[@]}"; do
    found=false
    for rule in "${RULES[@]}"; do
        if [[ "$marker" == "$rule" ]]; then
            found=true
            break
        fi
    done
    if ! $found; then
        ORPHANED+=("$marker")
    fi
done

# Report results
if [[ ${#ALL_OK[@]} -gt 0 ]]; then
    echo "Fully covered rules (${#ALL_OK[@]}):"
    for r in "${ALL_OK[@]}"; do
        echo "  [OK] $r"
    done
fi

HAS_ERRORS=false

if [[ ${#FUZZ_MISSING[@]} -gt 0 ]]; then
    echo ""
    echo "MISSING fuzz coverage (${#FUZZ_MISSING[@]}):"
    for r in "${FUZZ_MISSING[@]}"; do
        echo "  [FUZZ] $r"
    done
    HAS_ERRORS=true
fi

if [[ ${#UNIT_MISSING[@]} -gt 0 ]]; then
    echo ""
    echo "MISSING unit test coverage (${#UNIT_MISSING[@]}):"
    for r in "${UNIT_MISSING[@]}"; do
        echo "  [UNIT] $r"
    done
    HAS_ERRORS=true
fi

if [[ ${#ORPHANED[@]} -gt 0 ]]; then
    echo ""
    echo "ORPHANED COVERS markers (rule deleted from security.yaml):"
    for r in "${ORPHANED[@]}"; do
        echo "  [ORPHAN] $r"
    done
    echo "  Please remove these markers from fuzz_test.go"
    HAS_ERRORS=true
fi

if $HAS_ERRORS; then
    echo ""
    echo "To fix fuzz coverage, add to fuzz_test.go:"
    echo "  // COVERS: rule-name"
    echo "  f.Add(\"Bash\", \`{\"command\": \"...\"}\`)"
    echo ""
    echo "To fix unit test coverage, add a test case that mentions the rule name:"
    echo "  // Tests rule: rule-name"
    exit 1
fi

echo ""
echo "All ${#RULES[@]} rules have full test and fuzz coverage."
exit 0
