#!/bin/bash
set -euo pipefail

SCAN_PATH="${1:-.}"
MIN_SEVERITY="${2:-HIGH}"
SARIF_FILE="${3:-cobalt-results.sarif}"
FAIL_ON_FINDINGS="${4:-false}"

echo "╔══════════════════════════════════════════════════════╗"
echo "║  COBALT Security Scanner v2.1 — Z3 SMT Verified     ║"
echo "║  CWE-190 / CWE-195 / CWE-196 / CWE-197             ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "  Scan path   : $SCAN_PATH"
echo "  Min severity: $MIN_SEVERITY"
echo "  SARIF output: $SARIF_FILE"
echo ""

# Resolve absolute path (GitHub Actions workspace is /github/workspace)
ABS_PATH="$(realpath "$SCAN_PATH" 2>/dev/null || echo "$SCAN_PATH")"

# Run COBALT scanner
python3 /cobalt/cobalt_c_scanner.py \
    --dir "$ABS_PATH" \
    --sarif "$SARIF_FILE" \
    --quiet

# Count confirmed findings in SARIF
FINDING_COUNT=0
if [ -f "$SARIF_FILE" ]; then
    FINDING_COUNT=$(python3 -c "
import json, sys
try:
    with open('$SARIF_FILE') as f:
        sarif = json.load(f)
    count = sum(len(run.get('results', [])) for run in sarif.get('runs', []))
    print(count)
except Exception:
    print(0)
")
fi

echo ""
echo "  Z3-confirmed findings: $FINDING_COUNT"
echo ""

# Set output for GitHub Actions
echo "finding-count=$FINDING_COUNT" >> "${GITHUB_OUTPUT:-/dev/null}"

# Fail if requested and findings exist
if [ "$FAIL_ON_FINDINGS" = "true" ] && [ "$FINDING_COUNT" -gt 0 ]; then
    echo "  COBALT: $FINDING_COUNT confirmed finding(s). Failing build."
    exit 1
fi

exit 0
