# COBALT Security Scanner — GitHub Action

[![Self-test](https://github.com/dom-omg/cobalt-action/actions/workflows/self-test.yml/badge.svg)](https://github.com/dom-omg/cobalt-action/actions/workflows/self-test.yml)

**Z3-verified integer overflow detection for C/C++ repositories.**

Every finding is formally proven reachable by the Z3 SMT solver — zero false positives. Results appear as native GitHub Code Scanning annotations, inline in your PRs.

Detects:
- **CWE-190** — Integer Overflow
- **CWE-195** — Signed/Unsigned Conversion Error
- **CWE-196** — Unsigned to Signed Conversion Error
- **CWE-197** — Numeric Truncation Error

---

## Quick Start

```yaml
# .github/workflows/cobalt.yml
name: COBALT Security Scan

on: [push, pull_request]

permissions:
  security-events: write
  contents: read

jobs:
  cobalt:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5

      - name: Run COBALT
        uses: dom-omg/cobalt-action@v1
        with:
          path: src/
          severity: HIGH

      - name: Upload to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: cobalt-results.sarif
```

Findings appear inline in your PR diff, powered by GitHub Code Scanning — no dashboard, no setup, no API keys.

---

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Directory to scan | `.` (repo root) |
| `severity` | Minimum severity to report: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` | `HIGH` |
| `sarif-file` | SARIF 2.1.0 output path | `cobalt-results.sarif` |
| `fail-on-findings` | Exit 1 if confirmed findings are found | `false` |

## Outputs

| Output | Description |
|--------|-------------|
| `sarif-file` | Path to the generated SARIF file |
| `finding-count` | Number of Z3-confirmed findings |

---

## How It Works

COBALT uses **libclang** to parse your C/C++ AST and extract every integer arithmetic operation. Each candidate is submitted to the **Z3 SMT solver**, which either:

- **SAT** — constructs a concrete counterexample proving the overflow is reachable → reported
- **UNSAT** — formally proves the overflow cannot occur → suppressed

This is why COBALT has zero false positives: every finding ships with a Z3-generated witness value that triggers the bug.

---

## Example Finding

```
src/crypto/tls_server.c:539 [HIGH] CWE-190
  unsigned int + unsigned int → potential overflow
  Z3 SAT: a=4294967295, b=1 → wraps to 0
```

---

## Real-World Findings

COBALT has been validated against production open-source codebases:

| Project | Finding | Status |
|---------|---------|--------|
| strongSwan | `tls_server.c:539` — attacker-controlled `alloca` (CWE-190) | Disclosed |
| OpenVPN | CWE-195 signed/unsigned truncation | Disclosed |
| wolfSSL | Integer overflow in crypto primitives | Disclosed |
| FreeRTOS / Amazon | CWE-190 in task scheduler | Disclosed |
| Mozilla NSS | `sec_CreateRSAPSSParameters` CWE-191 underflow | Patched same-day |

---

## Supported Languages

- C (`.c`, `.h`)
- C++ (`.cpp`, `.cxx`, `.cc`, `.hpp`)

---

## Advanced Usage

### Fail the build on findings

```yaml
- name: Run COBALT
  id: cobalt
  uses: dom-omg/cobalt-action@v1
  with:
    fail-on-findings: 'true'
    severity: CRITICAL
```

### Use the finding count in subsequent steps

```yaml
- name: Run COBALT
  id: cobalt
  uses: dom-omg/cobalt-action@v1

- name: Comment on PR
  if: steps.cobalt.outputs.finding-count > 0
  run: echo "${{ steps.cobalt.outputs.finding-count }} Z3-confirmed findings"
```

---

## Built by QreativeLab

COBALT is developed by [QreativeLab](https://qreativelab.io).

Enterprise support, custom integrations, audit engagements: **dominik@qreativelab.io**
