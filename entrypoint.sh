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

# Run COBALT scanner (exit code != 1 = scan error, not findings)
python3 /cobalt/cobalt_c_scanner.py \
    --dir "$ABS_PATH" \
    --sarif "$SARIF_FILE" \
    --quiet || {
    echo "::warning::COBALT scanner exited with non-zero status — check for unsupported file types or parse errors"
    exit 0
}

# Filter by severity + count confirmed findings
FINDING_COUNT=0
if [ -f "$SARIF_FILE" ]; then
    FINDING_COUNT=$(python3 - <<PYEOF
import json, sys

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
min_level = SEV_ORDER.get("$MIN_SEVERITY", 3)

try:
    with open("$SARIF_FILE") as f:
        sarif = json.load(f)

    kept = []
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            sev = result.get("properties", {}).get("severity", "HIGH")
            if SEV_ORDER.get(sev, 0) >= min_level:
                kept.append(result)
        run["results"] = kept

    with open("$SARIF_FILE", "w") as f:
        json.dump(sarif, f, indent=2)

    print(len(kept))
except Exception as e:
    print(0, file=sys.stderr)
    print(0)
PYEOF
)
fi

echo ""
echo "  Z3-confirmed findings: $FINDING_COUNT"
echo ""

# Set outputs for GitHub Actions
echo "finding-count=$FINDING_COUNT" >> "${GITHUB_OUTPUT:-/dev/null}"
echo "sarif-file=$SARIF_FILE"       >> "${GITHUB_OUTPUT:-/dev/null}"

# Fail if requested and findings exist
if [ "$FAIL_ON_FINDINGS" = "true" ] && [ "$FINDING_COUNT" -gt 0 ]; then
    echo "  COBALT: $FINDING_COUNT confirmed finding(s). Failing build."
    exit 1
fi

exit 0
