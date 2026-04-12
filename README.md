# COBALT Security Scanner — GitHub Action

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
      - uses: actions/checkout@v4

      - name: Run COBALT
        uses: dom-omg/cobalt-action@v1
        with:
          path: src/
          severity: HIGH

      - name: Upload to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: cobalt-results.sarif
```

That's it. Findings appear inline in your PR diff, powered by GitHub Code Scanning.

---

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Directory to scan | `.` (repo root) |
| `severity` | Minimum severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` | `HIGH` |
| `sarif-file` | SARIF output path | `cobalt-results.sarif` |
| `fail-on-findings` | Fail the build if findings are found | `false` |

## Outputs

| Output | Description |
|--------|-------------|
| `sarif-file` | Path to the generated SARIF file |
| `finding-count` | Number of Z3-confirmed findings |

---

## How It Works

COBALT uses **libclang** to parse your C/C++ AST and extract every integer arithmetic operation. Each candidate is then submitted to the **Z3 SMT solver**, which either:

- **SAT** — constructs a concrete counterexample proving the overflow is reachable (reported)
- **UNSAT** — formally proves the overflow cannot occur (suppressed)

This eliminates the false positive problem that plagues traditional static analysis tools.

---

## Example Finding

```
src/crypto/tls.c:539 [HIGH] CWE-190
  unsigned int + unsigned int → potential overflow
  Z3 SAT: a=4294967295, b=1 → wraps to 0
```

---

## Supported Languages

- C (`.c`, `.h`)
- C++ (`.cpp`, `.cxx`, `.cc`, `.hpp`)

---

## Built by QreativeLab

COBALT is developed by [QreativeLab](https://qreativelab.io).

**Findings portfolio**: strongSwan, OpenVPN, wolfSSL, FreeRTOS, NSS, and more.

For enterprise support, custom integrations, or audit engagements: **dominik@qreativelab.io**
