"""Inventory audit — read-only static analysis for the cleanup project.

Generates docs/_audit/CLEANUP_INVENTORY.md with:
  1. modules/ + utils/ → which entry points (registry / runner / scanner / api / tests) reach them
  2. Dead code candidates (modules never imported anywhere)
  3. Stub functions (pass-only or return-None-only) excluding test fixtures
  4. Suspect duplicate-pair fingerprints (function-name overlap %)
  5. Per-file unused-import count

Run:
  python3 scripts/inventory_audit.py
"""
from __future__ import annotations

import ast
import collections
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXCLUDE_DIRS = {
    "venv", ".venv", "__pycache__", ".git", "node_modules",
    ".ruff_cache", ".pytest_cache", "tools/mcp-for-security",
    "scans", "data",
}
TARGET_DIRS = ("modules", "utils", "core")


def is_excluded(path: Path) -> bool:
    parts = set(path.relative_to(ROOT).parts)
    if parts & EXCLUDE_DIRS:
        return True
    rel = str(path.relative_to(ROOT))
    return any(rel.startswith(d + os.sep) for d in EXCLUDE_DIRS)


def collect_py_files() -> list[Path]:
    out: list[Path] = []
    for p in ROOT.rglob("*.py"):
        if is_excluded(p):
            continue
        out.append(p)
    return out


def parse_imports(src: str) -> list[tuple[str, str]]:
    """Return [(module, name), ...] for every import statement."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []
    out: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for alias in node.names:
                out.append((mod, alias.name))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                out.append(("", alias.name))
    return out


def collect_top_level_functions(tree: ast.AST) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    """Module- and class-level function defs (one level deep)."""
    out: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    if not isinstance(tree, ast.Module):
        return out
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append(node)
        elif isinstance(node, ast.ClassDef):
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    out.append(sub)
    return out


def is_stub(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    body = fn.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        body = body[1:]
    if not body:
        return "EMPTY"
    if len(body) == 1:
        s = body[0]
        if isinstance(s, ast.Pass):
            return "PASS_ONLY"
        if isinstance(s, ast.Return):
            v = s.value
            if v is None:
                return "RETURN_NONE"
            if isinstance(v, ast.Constant) and v.value in (None, False, True, "", 0):
                return "RETURN_CONST"
            if isinstance(v, (ast.List, ast.Set, ast.Tuple)) and not v.elts:
                return "RETURN_EMPTY_COLL"
            if isinstance(v, ast.Dict) and not v.keys:
                return "RETURN_EMPTY_COLL"
        if isinstance(s, ast.Raise) and isinstance(s.exc, ast.Call):
            fn_name = getattr(s.exc.func, "id", "")
            if fn_name == "NotImplementedError":
                return "NOT_IMPL"
    return None


def module_dotted_names(path: Path) -> list[str]:
    """Return possible dotted-import names for a file under target dirs."""
    rel = path.relative_to(ROOT)
    parts = list(rel.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    if not parts:
        return []
    return [".".join(parts), parts[-1]]


def main() -> int:
    files = collect_py_files()
    file_imports: dict[Path, list[tuple[str, str]]] = {}
    for p in files:
        try:
            file_imports[p] = parse_imports(p.read_text())
        except (OSError, UnicodeDecodeError):
            file_imports[p] = []

    # ---- 1. orphan detection ------------------------------------------------
    orphan_candidates: list[Path] = []
    for p in files:
        rel_parts = p.relative_to(ROOT).parts
        if not rel_parts or rel_parts[0] not in TARGET_DIRS:
            continue
        if p.name == "__init__.py":
            continue
        names = module_dotted_names(p)
        # any other file that imports any of these names?
        referenced = False
        for op, imports in file_imports.items():
            if op == p:
                continue
            for mod, name in imports:
                full = f"{mod}.{name}" if mod else name
                if any(n == mod or n == name or full.endswith("." + n) or n == full for n in names):
                    referenced = True
                    break
            if referenced:
                break
        if not referenced:
            orphan_candidates.append(p)

    # ---- 2. stub functions --------------------------------------------------
    stubs: list[tuple[Path, int, str, str]] = []
    for p in files:
        if p.parts[-2] == "tests":
            continue
        try:
            tree = ast.parse(p.read_text())
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        for fn in collect_top_level_functions(tree):
            kind = is_stub(fn)
            if kind:
                stubs.append((p, fn.lineno, fn.name, kind))

    # ---- 3. unused imports per file (heuristic) -----------------------------
    unused_per_file: list[tuple[Path, int, list[str]]] = []
    for p in files:
        try:
            src = p.read_text()
            tree = ast.parse(src)
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        imported: dict[str, str] = {}  # local-name -> "from X import Y"
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for a in node.names:
                    imported[a.asname or a.name] = f"from {node.module or ''} import {a.name}"
            elif isinstance(node, ast.Import):
                for a in node.names:
                    imported[(a.asname or a.name).split(".")[0]] = f"import {a.name}"
        used: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                used.add(node.id)
            elif isinstance(node, ast.Attribute):
                o = node.value
                while isinstance(o, ast.Attribute):
                    o = o.value
                if isinstance(o, ast.Name):
                    used.add(o.id)
        # also check for usage in __all__
        all_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id == "__all__":
                        if isinstance(node.value, (ast.List, ast.Tuple)):
                            for el in node.value.elts:
                                if isinstance(el, ast.Constant) and isinstance(el.value, str):
                                    all_names.add(el.value)
        unused = sorted(set(imported) - used - all_names - {"annotations", "*"})
        if unused:
            unused_per_file.append((p, len(unused), unused))

    # ---- 4. duplicate-pair fingerprint --------------------------------------
    suspect_pairs = [
        ("modules/sqli.py", "modules/sqli_exploit.py"),
        ("modules/lfi.py", "modules/lfi_exploit.py"),
        ("modules/cmdi.py", "modules/cmdi_shell.py"),
        ("modules/ssrf.py", "modules/ssrf_exploit.py"),
        ("modules/xss.py", "modules/xss_exploit.py"),
        ("modules/crawler.py", "modules/dynamic_crawler.py"),
        ("modules/payloads.py", "modules/smart_payload.py"),
        ("modules/smart_payload.py", "modules/smart_payload_inject.py"),
        ("utils/agent_framework.py", "utils/agent_orchestrator.py"),
        ("utils/ai.py", "utils/ai_exploit_agent.py"),
        ("utils/ai_intent_agent.py", "utils/ai_waf_agent.py"),
        ("utils/waf.py", "utils/waf_evasion.py"),
        ("utils/waf_evasion.py", "utils/waf_exhaustion.py"),
    ]

    def funcset(path: Path) -> set[str]:
        try:
            tree = ast.parse(path.read_text())
        except Exception:
            return set()
        return {n.name for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}

    pair_report: list[dict] = []
    for a, b in suspect_pairs:
        pa, pb = ROOT / a, ROOT / b
        if not (pa.exists() and pb.exists()):
            continue
        fa, fb = funcset(pa), funcset(pb)
        overlap = fa & fb
        loc_a = len(pa.read_text().splitlines())
        loc_b = len(pb.read_text().splitlines())
        pair_report.append({
            "a": a, "b": b,
            "loc_a": loc_a, "loc_b": loc_b,
            "fns_a": len(fa), "fns_b": len(fb),
            "overlap_count": len(overlap),
            "overlap_names": sorted(overlap)[:10],
            "overlap_pct_of_a": round(100 * len(overlap) / max(1, len(fa)), 1),
            "overlap_pct_of_b": round(100 * len(overlap) / max(1, len(fb)), 1),
        })

    # ---- 5. registry/runner reachability -----------------------------------
    runner_text = (ROOT / "core" / "module_runners.py").read_text()
    registry_text = (ROOT / "core" / "module_registry.py").read_text()
    scanner_text = (ROOT / "scanner.py").read_text()
    api_text = (ROOT / "api_server.py").read_text()

    # Build inter-file import map: for every file, which OTHER files reference its module path?
    importers_of: dict[str, list[str]] = collections.defaultdict(list)
    for p in files:
        rel_parts = p.relative_to(ROOT).parts
        if not rel_parts or rel_parts[0] not in ("modules", "utils"):
            continue
        if p.name == "__init__.py":
            continue
        modname = p.stem
        pkg = rel_parts[0]
        dotted_full = f"{pkg}.{modname}"
        rel = str(p.relative_to(ROOT))
        for op, imports in file_imports.items():
            if op == p:
                continue
            for mod, name in imports:
                # match `from modules.cmdi import X` or `import modules.cmdi`
                if mod == dotted_full or mod.startswith(dotted_full + "."):
                    importers_of[rel].append(str(op.relative_to(ROOT)))
                    break
                # match `from modules import cmdi` (rare)
                if mod == pkg and name == modname:
                    importers_of[rel].append(str(op.relative_to(ROOT)))
                    break

    reachability: list[tuple[str, dict]] = []
    for p in sorted(files):
        rel_parts = p.relative_to(ROOT).parts
        if not rel_parts or rel_parts[0] not in ("modules", "utils"):
            continue
        if p.name == "__init__.py":
            continue
        modname = p.stem
        rel = str(p.relative_to(ROOT))
        importers = sorted(set(importers_of.get(rel, [])))
        info = {
            "in_module_runners": f"{rel_parts[0]}.{modname}" in runner_text or f"from {rel_parts[0]}.{modname}" in runner_text,
            "in_module_registry": modname in registry_text,
            "in_scanner_py": modname in scanner_text,
            "in_api_server": modname in api_text,
            "test_file": (ROOT / "tests" / f"test_{modname}.py").exists(),
            "importers": importers,
        }
        reachability.append((rel, info))

    # ---- write report -------------------------------------------------------
    out = ROOT / "docs" / "_audit" / "CLEANUP_INVENTORY.md"
    lines: list[str] = []
    lines.append("# Cleanup Inventory — auto-generated")
    lines.append("")
    lines.append(f"_Run: `python3 scripts/inventory_audit.py`_")
    lines.append("")
    lines.append("## 1. Orphan Modules (defined but never imported anywhere)")
    lines.append("")
    if not orphan_candidates:
        lines.append("_None._")
    for p in sorted(orphan_candidates):
        lines.append(f"- `{p.relative_to(ROOT)}`")
    lines.append("")

    lines.append("## 2. Stub / Empty / NotImpl Functions (excluding tests/)")
    lines.append("")
    for p, lineno, name, kind in sorted(stubs):
        lines.append(f"- `{p.relative_to(ROOT)}:{lineno}` — `{name}` ({kind})")
    lines.append("")

    lines.append("## 3. Unused Imports (heuristic, F401-style)")
    lines.append("")
    lines.append(f"Total files with ≥1 unused import: **{len(unused_per_file)}**")
    lines.append("")
    lines.append("Top offenders (≥3 unused):")
    lines.append("")
    for p, n, names in sorted(unused_per_file, key=lambda x: -x[1]):
        if n < 3:
            continue
        lines.append(f"- `{p.relative_to(ROOT)}`: {n} unused → `{', '.join(names[:8])}`{'…' if n > 8 else ''}")
    lines.append("")

    lines.append("## 4. Suspect Duplicate Pairs — function-name overlap")
    lines.append("")
    lines.append("| A | B | LOC A | LOC B | overlap fns | %A | %B |")
    lines.append("|---|---|---|---|---|---|---|")
    for r in pair_report:
        lines.append(
            f"| `{r['a']}` | `{r['b']}` | {r['loc_a']} | {r['loc_b']} "
            f"| {r['overlap_count']} | {r['overlap_pct_of_a']} | {r['overlap_pct_of_b']} |"
        )
    lines.append("")
    lines.append("Overlap names per pair (first 10):")
    lines.append("")
    for r in pair_report:
        if r["overlap_names"]:
            lines.append(f"- `{r['a']}` ↔ `{r['b']}`: `{', '.join(r['overlap_names'])}`")
    lines.append("")

    lines.append("## 5. Module Reachability Map")
    lines.append("")
    lines.append("Legend: R=registry, U=module_runners, S=scanner.py, A=api_server.py, T=test file")
    lines.append("")
    lines.append("| File | R | U | S | A | T |")
    lines.append("|---|---|---|---|---|---|")
    for rel, info in reachability:
        def y(b: bool) -> str:
            return "✓" if b else " "
        lines.append(
            f"| `{rel}` | {y(info['in_module_registry'])} "
            f"| {y(info['in_module_runners'])} | {y(info['in_scanner_py'])} "
            f"| {y(info['in_api_server'])} | {y(info['test_file'])} |"
        )
    lines.append("")

    lines.append("## 6. Cleanup Decision Hints")
    lines.append("")
    lines.append("### 6a. TRULY ORPHAN — no entry point AND no inter-module importers")
    lines.append("")
    lines.append("Top candidates for orphan removal (still verify with `grep -r`):")
    lines.append("")
    truly_orphan = [
        (rel, info) for rel, info in reachability
        if not (info["in_module_registry"] or info["in_module_runners"]
                or info["in_scanner_py"] or info["in_api_server"])
        and not info["importers"]
    ]
    if truly_orphan:
        for rel, info in truly_orphan:
            test_marker = " (HAS TEST)" if info["test_file"] else ""
            lines.append(f"- `{rel}`{test_marker}")
    else:
        lines.append("_None._")
    lines.append("")

    lines.append("### 6b. INDIRECTLY REACHED — no direct entry, but other modules import it")
    lines.append("")
    indirect = [
        (rel, info) for rel, info in reachability
        if not (info["in_module_registry"] or info["in_module_runners"]
                or info["in_scanner_py"] or info["in_api_server"])
        and info["importers"]
    ]
    for rel, info in indirect:
        lines.append(f"- `{rel}` ← imported by: `{', '.join(info['importers'][:5])}`"
                     f"{' …' if len(info['importers']) > 5 else ''}")
    lines.append("")

    lines.append("### 6c. ZERO IMPORTERS WITH TEST FILE (test-only orphans?)")
    lines.append("")
    test_only = [
        (rel, info) for rel, info in reachability
        if info["test_file"]
        and not info["importers"]
        and not (info["in_module_registry"] or info["in_module_runners"]
                 or info["in_scanner_py"] or info["in_api_server"])
    ]
    for rel, info in test_only:
        lines.append(f"- `{rel}` (test exists but module unreachable from any prod entry point)")
    if not test_only:
        lines.append("_None._")
    lines.append("")

    out.write_text("\n".join(lines))
    print(f"WROTE: {out}")
    print(f"  orphans={len(orphan_candidates)}  stubs={len(stubs)}  "
          f"unused-import-files={len(unused_per_file)}  "
          f"duplicate-pairs-checked={len(pair_report)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
