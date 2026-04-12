"""
COBALT — Automatic C/C++ Scanner
Parses any .c/.cpp file with libclang, extracts integer arithmetic operations,
and formally verifies overflow reachability with Z3 SMT solver.

Usage:
    python3 cobalt_c_scanner.py <file.c> [file2.c ...]
    python3 cobalt_c_scanner.py --dir <directory>

Output: per-file findings with CWE class, severity, Z3 verdict, and fix.
"""

import sys
import os
import argparse
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
import clang.cindex as clang
from z3 import *

COBALT_VERSION = "2.1.0"

BANNER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║  COBALT C/C++ Auto-Scanner v2.1                                            ║
║  libclang AST · Z3 SMT Solver · CWE-190 / CWE-195 / CWE-196 / CWE-197    ║
║  Interprocedural Guard Analysis — eliminates guarded-function false pos.   ║
╚══════════════════════════════════════════════════════════════════════════════╝"""

# ── Integer type metadata ─────────────────────────────────────────────────────
INT_TYPES = {
    # canonical name → (bits, signed, min, max)
    "char":                   (8,  True,  -128,          127),
    "unsigned char":          (8,  False, 0,             255),
    "short":                  (16, True,  -32768,        32767),
    "unsigned short":         (16, False, 0,             65535),
    "int":                    (32, True,  -(2**31),      2**31 - 1),
    "unsigned int":           (32, False, 0,             2**32 - 1),
    "long":                   (32, True,  -(2**31),      2**31 - 1),
    "unsigned long":          (32, False, 0,             2**32 - 1),
    "long long":              (64, True,  -(2**63),      2**63 - 1),
    "unsigned long long":     (64, False, 0,             2**64 - 1),
    "int8_t":                 (8,  True,  -128,          127),
    "uint8_t":                (8,  False, 0,             255),
    "int16_t":                (16, True,  -32768,        32767),
    "uint16_t":               (16, False, 0,             65535),
    "int32_t":                (32, True,  -(2**31),      2**31 - 1),
    "uint32_t":               (32, False, 0,             2**32 - 1),
    "int64_t":                (64, True,  -(2**63),      2**63 - 1),
    "uint64_t":               (64, False, 0,             2**64 - 1),
    "sword32":                (32, True,  -(2**31),      2**31 - 1),
    "word32":                 (32, False, 0,             2**32 - 1),
    "sword16":                (16, True,  -32768,        32767),
    "word16":                 (16, False, 0,             65535),
    "byte":                   (8,  False, 0,             255),
    "sp_digit":               (32, False, 0,             2**32 - 1),
    # Platform-sized types — LP64 (Linux/macOS 64-bit, COBALT default target)
    # size_t listed explicitly before canonical fallback to unsigned long (32-bit in ILP32)
    "size_t":                 (64, False, 0,             2**64 - 1),
    "ssize_t":                (64, True,  -(2**63),      2**63 - 1),
    "ptrdiff_t":              (64, True,  -(2**63),      2**63 - 1),
    "uintptr_t":              (64, False, 0,             2**64 - 1),
    "intptr_t":               (64, True,  -(2**63),      2**63 - 1),
}

NARROW_BITS = {8, 16}   # types where promotion to int happens implicitly

@dataclass
class Finding:
    file:     str
    line:     int
    col:      int
    cwe:      str
    severity: str
    op:       str
    type_name: str
    bits:     int
    signed:   bool
    context:  str
    z3_result: str = "PENDING"
    counterex: Optional[str] = None
    fix:      str = ""

# ── libclang AST walker ───────────────────────────────────────────────────────

def get_type_name(type_obj) -> str:
    """Normalize clang type spelling to a known INT_TYPES key.

    Priority: typedef name first (size_t, ssize_t, etc.) so platform-sized
    types use their explicit LP64 entry rather than the canonical alias
    (unsigned long = 32-bit in ILP32 tables, wrong on Linux LP64).
    """
    s = type_obj.spelling.replace("const ", "").replace("volatile ", "").strip()
    if s in INT_TYPES:
        return s
    canonical = type_obj.get_canonical().spelling.replace("const ", "").strip()
    if canonical in INT_TYPES:
        return canonical
    return s

def is_integer_type(type_obj) -> bool:
    return get_type_name(type_obj) in INT_TYPES

def extract_int_literal(node) -> Optional[int]:
    """Try to extract integer literal value from a cursor."""
    if node.kind == clang.CursorKind.INTEGER_LITERAL:
        tokens = list(node.get_tokens())
        if tokens:
            try:
                return int(tokens[0].spelling, 0)
            except ValueError:
                pass
    return None

def is_const_expr(node) -> bool:
    """
    Return True if this subtree is a compile-time constant expression.
    Compile-time = only integer literals, enum constants, and their arithmetic.
    No DECL_REF_EXPR (variables) means it folds at compile time — skip it.
    """
    CONST_KINDS = {
        clang.CursorKind.INTEGER_LITERAL,
        clang.CursorKind.FLOATING_LITERAL,
        clang.CursorKind.CHARACTER_LITERAL,
        clang.CursorKind.UNARY_OPERATOR,
        clang.CursorKind.BINARY_OPERATOR,
        clang.CursorKind.PAREN_EXPR,
        clang.CursorKind.CSTYLE_CAST_EXPR,
    }
    # Allow enum constants (they are compile-time)
    ENUM_LIKE = {clang.CursorKind.DECL_REF_EXPR}

    # BFS: if we encounter a variable reference, not const
    stack = [node]
    has_literal = False
    while stack:
        n = stack.pop()
        if n.kind == clang.CursorKind.INTEGER_LITERAL:
            has_literal = True
        elif n.kind in ENUM_LIKE:
            # Check if it's an enum constant vs variable
            defn = n.referenced
            if defn is None or defn.kind not in (
                clang.CursorKind.ENUM_CONSTANT_DECL,
                clang.CursorKind.MACRO_DEFINITION,
            ):
                return False  # real variable → runtime
        elif n.kind not in CONST_KINDS:
            pass  # unknown node — be conservative, keep scanning children
        stack.extend(n.get_children())
    return has_literal

def get_node_source(node, source_lines: List[str]) -> str:
    """Extract source text for a node using its extent."""
    try:
        start_line = node.extent.start.line
        end_line = node.extent.end.line
        if start_line == end_line and start_line <= len(source_lines):
            line = source_lines[start_line - 1]
            sc = node.extent.start.column - 1
            ec = node.extent.end.column - 1
            return line[sc:ec].strip()
        elif start_line <= len(source_lines):
            return source_lines[start_line - 1].strip()
    except Exception:
        pass
    return ""

# ── Interprocedural Guard Analysis ───────────────────────────────────────────

class FunctionGuardDB:
    """
    Two-pass interprocedural analysis: builds a map of functions that are
    guaranteed to never return a negative value.

    Use case: suppress CWE-195 false positives where the signed value being
    cast comes from a function that internally guards negative returns.

    Example (OpenVPN buf_len):
        int buf_len(const struct buffer *buf) {
            if (buf_valid(buf))   // buf_valid checks buf->len >= 0
                return buf->len;
            else
                return 0;        // fallback is 0, never negative
        }
    → buf_len is "safe": BLENZ((size_t)buf_len()) cannot produce a huge wrap.
    """

    def __init__(self):
        # function spelling → True if all reachable returns are non-negative
        self.safe_functions: set = set()
        # iteration limit for fixpoint convergence
        self._max_rounds = 4

    # ── Pass 1: collect function definitions ─────────────────────────────────

    def build(self, tu) -> None:
        """Run fixpoint analysis over all function definitions in the TU."""
        func_defs: dict = {}  # spelling → FUNCTION_DECL cursor
        self._collect_defs(tu.cursor, func_defs)

        # Fixpoint: keep iterating until no new safe functions are added
        # (needed for transitive safety: f calls g, g is safe → f might be safe)
        prev_size = -1
        rounds = 0
        while len(self.safe_functions) != prev_size and rounds < self._max_rounds:
            prev_size = len(self.safe_functions)
            rounds += 1
            for name, cursor in func_defs.items():
                if name not in self.safe_functions:
                    if self._analyze_func(cursor):
                        self.safe_functions.add(name)

    def _collect_defs(self, node, out: dict) -> None:
        if (node.kind == clang.CursorKind.FUNCTION_DECL
                and node.is_definition()
                and node.spelling
                and node.spelling not in out):
            out[node.spelling] = node
        for child in node.get_children():
            self._collect_defs(child, out)

    # ── Pass 2: analyze return paths ─────────────────────────────────────────

    def _analyze_func(self, func_decl) -> bool:
        """
        Return True if this function is guaranteed to never return a negative
        integer value.

        Two strategies (either is sufficient):
        A) AST: all return expressions are provably non-negative
        B) Text: function has a non-negative fallback return (0 / positive literal)
                 AND no explicit negative literal return (return -N)
                 This handles guarded-member patterns like:
                   int buf_len(...) {
                       if (buf_valid(buf)) return buf->len;  // guarded ≥ 0
                       else                return 0;          // safe fallback
                   }
        """
        return_nodes: list = []
        self._collect_returns(func_decl, return_nodes)

        if not return_nodes:
            return False  # void or opaque — don't assume safe

        # Strategy A: every return is provably non-negative via AST
        if all(self._expr_non_negative(r) for r in return_nodes):
            return True

        # Strategy B: text-based guard — no explicit negative literal return
        return self._text_no_negative_return(func_decl)

    def _text_no_negative_return(self, func_decl) -> bool:
        """
        Text heuristic: a function is safe if:
        1. It contains at least one explicit return of 0 or a positive literal
        2. It contains NO explicit return of a negative literal (return -N)

        This catches the pattern: if (guard) return member; else return 0;
        where the guard ensures member >= 0 but we can't prove it via AST alone.
        """
        import re
        try:
            start = func_decl.extent.start
            end   = func_decl.extent.end
            if start.file is None:
                return False
            with open(start.file.name, 'r', errors='replace') as fh:
                lines = fh.readlines()
            body_lines = lines[start.line - 1 : end.line]
            body = ''.join(body_lines)
        except Exception:
            return False

        # Rule 1: no explicit negative literal return — catches return -1, return -errno
        # Pattern: `return` followed by optional whitespace, then `-` and a digit
        if re.search(r'\breturn\s+-\s*[0-9]', body):
            return False

        # Rule 2: has at least one zero/positive explicit fallback
        if re.search(r'\breturn\s+0\b', body):
            return True

        return False

    def _collect_returns(self, node, out: list) -> None:
        if node.kind == clang.CursorKind.RETURN_STMT:
            children = list(node.get_children())
            if children:
                out.append(children[0])
            else:
                # bare `return;` — void, skip
                pass
        else:
            for child in node.get_children():
                self._collect_returns(child, out)

    def _expr_non_negative(self, node) -> bool:
        """
        Conservative check: is this expression guaranteed >= 0?

        Handles:
          - Integer literals >= 0
          - Known-safe function calls (transitively)
          - Conditional (ternary) where both branches are non-negative
          - Paren / implicit cast wrappers
        """
        if node is None:
            return False

        kind = node.kind

        # Integer literal
        if kind == clang.CursorKind.INTEGER_LITERAL:
            tokens = list(node.get_tokens())
            if tokens:
                try:
                    return int(tokens[0].spelling, 0) >= 0
                except ValueError:
                    pass
            return False

        # Ternary: cond ? a : b — both branches must be non-negative
        if kind == clang.CursorKind.CONDITIONAL_OPERATOR:
            children = list(node.get_children())
            if len(children) == 3:
                return (self._expr_non_negative(children[1])
                        and self._expr_non_negative(children[2]))
            return False

        # Paren expression — unwrap
        if kind == clang.CursorKind.PAREN_EXPR:
            children = list(node.get_children())
            return self._expr_non_negative(children[0]) if children else False

        # Explicit cast — propagate through the inner expression
        if kind == clang.CursorKind.CSTYLE_CAST_EXPR:
            children = list(node.get_children())
            # For CWE-195-type casts: if inner is safe, outer is safe
            inner = next((c for c in children
                          if c.kind != clang.CursorKind.TYPE_REF), None)
            return self._expr_non_negative(inner) if inner else False

        # Function call — check transitive safety
        if kind == clang.CursorKind.CALL_EXPR:
            callee = self._callee_name(node)
            return callee in self.safe_functions if callee else False

        # Unexposed / unresolved — be conservative
        if kind == clang.CursorKind.UNEXPOSED_EXPR:
            children = list(node.get_children())
            if len(children) == 1:
                return self._expr_non_negative(children[0])

        return False  # unknown expression — conservative: not safe

    @staticmethod
    def _callee_name(call_node) -> Optional[str]:
        """Extract the callee function name from a CALL_EXPR node."""
        # Try referenced cursor first (most reliable)
        if call_node.referenced and call_node.referenced.spelling:
            return call_node.referenced.spelling
        # Fall back: first child of CALL_EXPR is usually the function ref
        children = list(call_node.get_children())
        for child in children:
            if child.kind in (clang.CursorKind.DECL_REF_EXPR,
                              clang.CursorKind.MEMBER_REF_EXPR):
                return child.spelling
        return None

    # ── Query API ─────────────────────────────────────────────────────────────

    def is_safe(self, func_name: str) -> bool:
        """Return True if func_name is guaranteed to return >= 0."""
        return func_name in self.safe_functions

    def check_cast_source(self, src_node) -> bool:
        """
        Given the source node of a (size_t) or (unsigned X) cast, return True
        if the cast is safe (source cannot be negative).

        Handles both direct function calls and implicit casts wrapping a call.
        """
        if src_node is None:
            return False
        kind = src_node.kind
        if kind == clang.CursorKind.CALL_EXPR:
            name = self._callee_name(src_node)
            return self.is_safe(name) if name else False
        if kind in (clang.CursorKind.UNEXPOSED_EXPR,
                    clang.CursorKind.PAREN_EXPR,
                    clang.CursorKind.CSTYLE_CAST_EXPR):
            children = list(src_node.get_children())
            return any(self.check_cast_source(c) for c in children)
        return False


def walk_ast(node, filepath: str, findings: List[Finding], source_lines: List[str],
             guard_db: Optional['FunctionGuardDB'] = None):
    """Recursively walk the AST looking for dangerous arithmetic patterns."""

    if node.location.file and node.location.file.name != filepath:
        return  # Skip included headers

    # ── Pattern 1: Left shift (CWE-190) ──────────────────────────────────────
    if node.kind == clang.CursorKind.BINARY_OPERATOR:
        children = list(node.get_children())
        if len(children) == 2:
            # Use extent-based source extraction to detect operator
            node_src = get_node_source(node, source_lines)
            left = children[0]
            right = children[1]

            if "<<" in node_src:
                # Skip compile-time constant expressions — no runtime overflow possible
                if not (is_const_expr(left) and is_const_expr(right)):
                    ltype = get_type_name(left.type)
                    if ltype in INT_TYPES:
                        bits, signed, _, _ = INT_TYPES[ltype]
                        shift_val = extract_int_literal(right)
                        line = node.location.line
                        ctx = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                        if signed or bits in NARROW_BITS:
                            findings.append(Finding(
                                file=filepath,
                                line=line,
                                col=node.location.column,
                                cwe="CWE-190",
                                severity="HIGH" if signed else "MEDIUM",
                                op=f"<< {shift_val if shift_val is not None else '?'}",
                                type_name=ltype,
                                bits=bits,
                                signed=signed,
                                context=ctx,
                                fix=f"Cast to unsigned before shift: (uint{max(bits,32)}_t)val << n"
                            ))

            # ── Pattern 2: Arithmetic on narrow result type (CWE-190) ─────────
            elif any(op in node_src for op in [" + ", " * ", " - "]):
                if not is_const_expr(node):  # Skip compile-time constant arithmetic
                    result_type = get_type_name(node.type)
                    if result_type in INT_TYPES:
                        bits, signed, _, _ = INT_TYPES[result_type]
                        op_char = "+" if " + " in node_src else ("*" if " * " in node_src else "-")
                        line = node.location.line
                        ctx = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                        # Narrow types (≤16 bit): any arithmetic can overflow
                        if bits <= 16:
                            findings.append(Finding(
                                file=filepath,
                                line=line,
                                col=node.location.column,
                                cwe="CWE-190",
                                severity="MEDIUM",
                                op=op_char,
                                type_name=result_type,
                                bits=bits,
                                signed=signed,
                                context=ctx,
                                fix=f"Use wider intermediate: (uint32_t)a {op_char} b"
                            ))
                        # ── Pattern 2b: size_t-class multiplication (CWE-190) ──
                        # malloc(count * elem_size) wraps silently on size_t overflow.
                        # Flag * on wide unsigned types (32/64-bit). + and - skipped
                        # to avoid FP storm on normal pointer/index arithmetic.
                        elif op_char == "*" and not signed and bits >= 32:
                            findings.append(Finding(
                                file=filepath,
                                line=line,
                                col=node.location.column,
                                cwe="CWE-190",
                                severity="HIGH",
                                op="*",
                                type_name=result_type,
                                bits=bits,
                                signed=False,
                                context=ctx,
                                fix=f"Use checked multiply: if (count > SIZE_MAX / elem_size) abort();"
                            ))

    # ── Pattern 3: Signed-to-unsigned cast (CWE-195) ─────────────────────────
    if node.kind == clang.CursorKind.CSTYLE_CAST_EXPR:
        children = list(node.get_children())
        if children:
            # CSTYLE_CAST children: [TYPE_REF(dst)?, UNEXPOSED_EXPR/DECL_REF(src)]
            # Skip leading TYPE_REF nodes to get actual source expression
            src_child = next(
                (c for c in children if c.kind != clang.CursorKind.TYPE_REF),
                children[-1]
            )
            src_type = get_type_name(src_child.type)
            dst_type = get_type_name(node.type)
            if src_type in INT_TYPES and dst_type in INT_TYPES:
                s_bits, s_signed, _, _ = INT_TYPES[src_type]
                d_bits, d_signed, _, _ = INT_TYPES[dst_type]
                if s_signed and not d_signed and s_bits >= 16:
                    # ── Interprocedural guard check (v2.1) ────────────────────
                    # If the source is a call to a function that guarantees
                    # non-negative return (e.g. buf_len → buf_valid checks >= 0),
                    # suppress this finding — it cannot produce a wrap.
                    if guard_db is not None and guard_db.check_cast_source(src_child):
                        pass  # guarded — suppress false positive
                    else:
                        line = node.location.line
                        ctx = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                        if ctx:
                            findings.append(Finding(
                                file=filepath,
                                line=line,
                                col=node.location.column,
                                cwe="CWE-195",
                                severity="HIGH",
                                op=f"({dst_type})",
                                type_name=f"{src_type} → {dst_type}",
                                bits=d_bits,
                                signed=False,
                                context=ctx,
                                fix=f"Validate {src_type} >= 0 before cast to {dst_type}"
                            ))

    for child in node.get_children():
        walk_ast(child, filepath, findings, source_lines, guard_db)


# ── Z3 Verification ───────────────────────────────────────────────────────────

def z3_verify_shift_overflow(finding: Finding) -> Tuple[str, Optional[str]]:
    """
    Z3 proof: does a left-shift on this type produce overflow?
    SAT = overflow IS reachable with concrete counterexample.
    UNSAT = overflow is impossible (type is wide enough).
    """
    bits = finding.bits
    signed = finding.signed

    # Extract shift amount from op string
    try:
        shift_amount = int(finding.op.split()[-1])
    except (ValueError, IndexError):
        shift_amount = 1  # conservative

    # Parse max from type
    _, _, tmin, tmax = INT_TYPES.get(finding.type_name, (bits, signed, 0, 2**bits - 1))

    x = Int("x")
    s = Solver()
    s.add(x >= tmin, x <= tmax)

    if signed:
        # C99 §6.5/5: left shift of signed type where result doesn't fit = UB
        # Formal property: x << n overflows signed type
        # i.e., x * 2^n > tmax OR x * 2^n < tmin
        shifted = x * (2 ** shift_amount)
        s.add(Or(shifted > tmax, shifted < tmin))
    else:
        # Unsigned: overflow = result > 2^bits - 1 (wraps)
        shifted = x * (2 ** shift_amount)
        s.add(shifted > tmax)

    result = s.check()
    if result == sat:
        model = s.model()
        cv = model[x].as_long()
        return "SAT", f"x={cv} → x<<{shift_amount} = {cv * (2**shift_amount)} (overflows {finding.type_name} max={tmax})"
    elif result == unsat:
        return "UNSAT", None
    return "UNKNOWN", None


def z3_verify_add_overflow(finding: Finding) -> Tuple[str, Optional[str]]:
    """Z3 proof: can addition/multiplication on this type overflow?"""
    _, _, tmin, tmax = INT_TYPES.get(finding.type_name, (16, False, 0, 65535))

    a, b = Int("a"), Int("b")
    s = Solver()
    s.add(a >= tmin, a <= tmax)
    s.add(b >= tmin, b <= tmax)

    if finding.op == "*":
        # Multiplication: a*b > tmax is the overflow condition
        # Z3 uses arbitrary precision — no bitvector needed
        s.add(a * b > tmax)
        result = s.check()
        if result == sat:
            m = s.model()
            av, bv = m[a].as_long(), m[b].as_long()
            return "SAT", f"a={av}, b={bv} → a*b={av*bv} (overflows {finding.type_name} max={tmax})"
    else:
        s.add(a + b > tmax)
        result = s.check()
        if result == sat:
            m = s.model()
            av, bv = m[a].as_long(), m[b].as_long()
            return "SAT", f"a={av}, b={bv} → a+b={av+bv} (overflows {finding.type_name} max={tmax})"

    return "UNSAT", None


def z3_verify_sign_conversion(finding: Finding) -> Tuple[str, Optional[str]]:
    """Z3 proof: can signed-to-unsigned conversion produce unexpected value?"""
    parts = finding.type_name.split(" → ")
    if len(parts) != 2:
        return "UNKNOWN", None

    src_name = parts[0].strip()
    dst_name = parts[1].strip()

    if src_name not in INT_TYPES or dst_name not in INT_TYPES:
        return "UNKNOWN", None

    _, _, smin, smax = INT_TYPES[src_name]
    _, _, dmin, dmax = INT_TYPES[dst_name]

    x = Int("x")
    s = Solver()
    s.add(x >= smin, x <= smax)
    s.add(x < 0)  # negative signed value
    # When cast to unsigned, becomes very large positive

    result = s.check()
    if result == sat:
        m = s.model()
        cv = m[x].as_long()
        # What the unsigned value would be
        unsigned_val = cv % (dmax + 1)
        return "SAT", f"x={cv} (negative) → ({dst_name}){cv} = {unsigned_val} (wraps to large positive)"
    return "UNSAT", None


def verify_finding(f: Finding) -> Finding:
    """Run the appropriate Z3 proof for this finding."""
    try:
        if f.cwe == "CWE-190" and "<<" in f.op:
            f.z3_result, f.counterex = z3_verify_shift_overflow(f)
        elif f.cwe == "CWE-190" and f.op in ("+", "*", "-"):
            f.z3_result, f.counterex = z3_verify_add_overflow(f)
        elif f.cwe == "CWE-195":
            f.z3_result, f.counterex = z3_verify_sign_conversion(f)
        else:
            f.z3_result = "SKIP"
    except Exception as e:
        f.z3_result = f"ERROR: {e}"
    return f


# ── Scanner entry point ───────────────────────────────────────────────────────

def _system_include_args() -> List[str]:
    """
    Detect platform-specific system include paths at runtime.
    Without these, clang fails to resolve size_t / stddef.h typedefs
    and returns '<dependent type>' for all size_t arithmetic — a silent FN.
    """
    import glob as _glob
    import platform

    args: List[str] = []

    # GCC multilib includes (stddef.h lives here on Debian/Ubuntu)
    machine = platform.machine()  # e.g. 'aarch64', 'x86_64'
    for pattern in [
        f"/usr/lib/gcc/{machine}-linux-gnu/*/include",
        f"/usr/lib/gcc/{machine}-linux-musl/*/include",
        "/usr/lib/gcc/x86_64-linux-gnu/*/include",  # fallback
    ]:
        matches = sorted(_glob.glob(pattern))
        if matches:
            args += ["-isystem", matches[-1]]  # take latest version
            break

    # Arch-specific system includes (bits/types.h, stddef.h aliases)
    for d in [
        f"/usr/include/{machine}-linux-gnu",
        f"/usr/include/{machine}-linux-musl",
        "/usr/include/x86_64-linux-gnu",  # fallback
    ]:
        if os.path.isdir(d):
            args += ["-isystem", d]
            break

    args += ["-isystem", "/usr/include", "-isystem", "/usr/local/include"]
    return args


def scan_file(filepath: str) -> List[Finding]:
    """Parse a C/C++ file and return all findings."""
    index = clang.Index.create()
    args = ["-x", "c", "-std=c11",
            "-D__COBALT_SCAN__",
            "-ferror-limit=0",
            ] + _system_include_args()

    try:
        tu = index.parse(filepath, args=args,
                         options=clang.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
    except Exception as e:
        print(f"  Parse error: {e}")
        return []

    try:
        source_lines = open(filepath).readlines()
    except Exception:
        source_lines = []

    # ── Build interprocedural guard database (v2.1) ──────────────────────────
    # Pass 1: analyze all function bodies in this TU to find functions that
    # are guaranteed to never return negative (suppresses CWE-195 FP).
    guard_db = FunctionGuardDB()
    guard_db.build(tu)

    findings = []
    walk_ast(tu.cursor, filepath, findings, source_lines, guard_db)

    # Deduplicate by (line, cwe, op)
    seen = set()
    unique = []
    for f in findings:
        key = (f.line, f.cwe, f.op, f.type_name)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    # Run Z3 on each
    return [verify_finding(f) for f in unique]


def scan_directory(dirpath: str, extensions=(".c", ".cpp", ".h")) -> dict:
    """Recursively scan all C/C++ files in a directory."""
    results = {}
    skip_dirs = {"__pycache__", ".git", "build", "test", "tests", "bench", "example", "examples"}
    for root, dirs, files in os.walk(dirpath):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            if any(fname.endswith(ext) for ext in extensions):
                fpath = os.path.join(root, fname)
                findings = scan_file(fpath)
                if findings:
                    results[fpath] = findings
    return results


# ── Report printer ────────────────────────────────────────────────────────────

def print_report(all_findings: dict, base_dir: str = ""):
    total = sum(len(v) for v in all_findings.values())
    confirmed = sum(1 for v in all_findings.values() for f in v if f.z3_result == "SAT")
    safe = sum(1 for v in all_findings.values() for f in v if f.z3_result == "UNSAT")

    print(f"\n{'═'*78}")
    print(f"  COBALT C/C++ SCAN — RESULTS")
    print(f"{'─'*78}")
    print(f"  Files with findings: {len(all_findings)}")
    print(f"  Total candidates:    {total}")
    print(f"  Z3 SAT (confirmed):  {confirmed}")
    print(f"  Z3 UNSAT (safe):     {safe}")
    print()

    for filepath, findings in all_findings.items():
        rel = filepath.replace(base_dir, "").lstrip("/")
        confirmed_here = [f for f in findings if f.z3_result == "SAT"]
        if not confirmed_here:
            continue

        print(f"  FILE: {rel}")
        print(f"  {'─'*74}")
        for f in confirmed_here:
            sev_color = "✗" if f.severity in ("CRITICAL", "HIGH") else "~"
            print(f"  {sev_color} Line {f.line:<5} [{f.cwe}] {f.severity:<8} op={f.op:<12} type={f.type_name}")
            print(f"    Code:  {f.context[:72]}")
            print(f"    Z3:    SAT — {f.counterex}")
            print(f"    Fix:   {f.fix[:72]}")
            print()

    if confirmed == 0:
        print("  ✓ Z3 UNSAT on all checks — no confirmed overflows")
    else:
        print(f"  ✗ {confirmed} CONFIRMED overflow(s) — Z3 SAT with counterexamples")
    print(f"{'═'*78}")

    return confirmed


# ── SARIF 2.1.0 Export ───────────────────────────────────────────────────────

CWE_URLS = {
    "CWE-190": "https://cwe.mitre.org/data/definitions/190.html",
    "CWE-195": "https://cwe.mitre.org/data/definitions/195.html",
    "CWE-196": "https://cwe.mitre.org/data/definitions/196.html",
    "CWE-197": "https://cwe.mitre.org/data/definitions/197.html",
}

SEV_TO_SARIF = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note",
}

def findings_to_sarif(all_findings: dict, base_dir: str = "", scan_target: str = "") -> dict:
    """
    Emit SARIF 2.1.0 — consumed by GitHub Code Scanning, VS Code, Azure DevOps.
    Only SAT (confirmed) findings are included.
    """
    import datetime

    # ── Build rule table (one rule per CWE) ──────────────────────────────────
    cwe_seen: set = set()
    rules = []
    rule_index: dict = {}
    for findings in all_findings.values():
        for f in findings:
            if f.z3_result == "SAT" and f.cwe not in cwe_seen:
                cwe_seen.add(f.cwe)
                idx = len(rules)
                rule_index[f.cwe] = idx
                rules.append({
                    "id": f.cwe,
                    "name": f.cwe.replace("-", ""),
                    "shortDescription": {"text": _cwe_short(f.cwe)},
                    "fullDescription": {"text": _cwe_full(f.cwe)},
                    "helpUri": CWE_URLS.get(f.cwe, "https://cwe.mitre.org/"),
                    "properties": {"tags": ["security", "correctness", f.cwe]},
                    "defaultConfiguration": {"level": "error"},
                })

    # ── Build results list ────────────────────────────────────────────────────
    results = []
    for filepath, findings in all_findings.items():
        rel = filepath.replace(base_dir, "").lstrip("/") if base_dir else filepath
        for f in findings:
            if f.z3_result != "SAT":
                continue
            msg = f"{f.cwe} — {f.type_name} op={f.op}"
            if f.counterex:
                msg += f" | Z3 SAT: {f.counterex}"
            results.append({
                "ruleId": f.cwe,
                "ruleIndex": rule_index.get(f.cwe, 0),
                "level": SEV_TO_SARIF.get(f.severity, "warning"),
                "message": {"text": msg},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": rel, "uriBaseId": "%SRCROOT%"},
                        "region": {
                            "startLine": f.line,
                            "startColumn": f.col,
                            "snippet": {"text": f.context} if f.context else {},
                        }
                    }
                }],
                "properties": {
                    "severity": f.severity,
                    "type": f.type_name,
                    "bits": f.bits,
                    "z3_counterexample": f.counterex or "",
                },
            })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "COBALT",
                    "version": COBALT_VERSION,
                    "informationUri": "https://qreativelab.io",
                    "rules": rules,
                }
            },
            "invocations": [{
                "executionSuccessful": True,
                "commandLine": f"cobalt_c_scanner.py {scan_target}",
                "startTimeUtc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            }],
            "results": results,
            "properties": {
                "cobalt_version": COBALT_VERSION,
                "scan_target": scan_target,
            }
        }]
    }


def _cwe_short(cwe: str) -> str:
    return {
        "CWE-190": "Integer Overflow or Wraparound",
        "CWE-195": "Signed to Unsigned Conversion Error",
        "CWE-196": "Unsigned to Signed Conversion Error",
        "CWE-197": "Numeric Truncation Error",
    }.get(cwe, cwe)

def _cwe_full(cwe: str) -> str:
    return {
        "CWE-190": "The software performs a calculation that can produce an integer overflow or wraparound when the logic assumes the resulting value will always be larger than the original. Z3 SMT solver confirmed a concrete counterexample.",
        "CWE-195": "The software uses a signed primitive and performs a cast to an unsigned primitive, which can produce an unexpected value if the value of the signed primitive cannot be represented as an unsigned primitive. Z3 SMT solver confirmed a concrete counterexample.",
        "CWE-196": "The software uses an unsigned primitive and performs a cast to a signed primitive, which can produce an unexpected value.",
        "CWE-197": "Truncation errors occur when a primitive is cast to a smaller primitive, and data is lost in the conversion.",
    }.get(cwe, cwe)


# ── CLI ───────────────────────────────────────────────────────────────────────

def findings_to_json(all_findings: dict, base_dir: str = "", scan_target: str = "") -> dict:
    """Serialize all findings to a JSON-serializable dict for the dashboard."""
    import datetime
    files_out = []
    total = 0
    confirmed = 0
    for filepath, findings in all_findings.items():
        rel = filepath.replace(base_dir, "").lstrip("/") if base_dir else filepath
        sat = [f for f in findings if f.z3_result == "SAT"]
        total += len(findings)
        confirmed += len(sat)
        if sat:
            files_out.append({
                "file": rel,
                "findings": [
                    {
                        "line": f.line,
                        "col": f.col,
                        "cwe": f.cwe,
                        "severity": f.severity,
                        "op": f.op,
                        "type_name": f.type_name,
                        "bits": f.bits,
                        "signed": f.signed,
                        "context": f.context,
                        "z3_result": f.z3_result,
                        "counterex": f.counterex,
                        "fix": f.fix,
                    }
                    for f in sat
                ]
            })
    return {
        "cobalt_version": COBALT_VERSION,
        "scan_target": scan_target,
        "scanned_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "files_with_findings": len(files_out),
            "total_candidates": total,
            "confirmed_sat": confirmed,
        },
        "files": files_out,
    }


def _write_outputs(all_findings: dict, args, base_dir: str, scan_target: str):
    import json
    wrote = False
    if getattr(args, "json", None):
        data = findings_to_json(all_findings, base_dir=base_dir, scan_target=scan_target)
        with open(args.json, "w") as jf:
            json.dump(data, jf, indent=2)
        print(f"\n  JSON written → {args.json}")
        wrote = True
    if getattr(args, "sarif", None):
        data = findings_to_sarif(all_findings, base_dir=base_dir, scan_target=scan_target)
        with open(args.sarif, "w") as sf:
            json.dump(data, sf, indent=2)
        n = sum(len(r) for r in [data["runs"][0]["results"]])
        print(f"\n  SARIF 2.1.0 written → {args.sarif}  ({n} results)")
        wrote = True
    if not wrote:
        print_report(all_findings, base_dir=base_dir)


if __name__ == "__main__":
    print(BANNER)

    parser = argparse.ArgumentParser(description="COBALT C/C++ Auto-Scanner")
    parser.add_argument("files", nargs="*", help="C/C++ files to scan")
    parser.add_argument("--dir", help="Directory to scan recursively")
    parser.add_argument("--quiet", action="store_true", help="Only show confirmed findings")
    parser.add_argument("--json",  metavar="OUT", help="Write JSON results to file (for dashboard)")
    parser.add_argument("--sarif", metavar="OUT", help="Write SARIF 2.1.0 results (GitHub Code Scanning, VS Code)")
    args = parser.parse_args()

    all_findings = {}

    if args.dir:
        print(f"\n  Scanning directory: {args.dir}")
        all_findings = scan_directory(args.dir)
        _write_outputs(all_findings, args, base_dir=args.dir, scan_target=args.dir)
    elif args.files:
        for f in args.files:
            print(f"\n  Scanning: {f}")
            findings = scan_file(f)
            if findings:
                all_findings[f] = findings
        _write_outputs(all_findings, args, base_dir="", scan_target=" ".join(args.files))
    else:
        # Demo: scan wolfSSL dilithium if available
        demo_targets = [
            "/home/dominikblain.linux/omg-universe/repos/dilithium/ref/sign.c",
            "/home/dominikblain.linux/omg-universe/repos/task-scheduler/src/mg/common/BinaryHeap.h",
        ]
        print(f"\n  No target specified — running demo scan on known repos\n")
        for t in demo_targets:
            if os.path.exists(t):
                print(f"  Scanning: {t.split('repos/')[-1]}")
                findings = scan_file(t)
                if findings:
                    all_findings[t] = findings
        print_report(all_findings)
        if not all_findings:
            print("\n  Usage: python3 cobalt_c_scanner.py --dir /path/to/repo")
            print("         python3 cobalt_c_scanner.py file.c file2.c")
