"""AST / IR-based code analysis for vulnerability scanning.

Provides per-language import resolution and call-site tracking so the
pipeline can discover *which* symbols from a vulnerable package are
actually used — even when the advisory text lists no specific function
names.

Supported languages
-------------------
* **Python** — full ``ast`` module (stdlib) parsing.
* **JavaScript / TypeScript** — regex-based import/require parsing.
* **Java** — regex-based ``import`` / method-call parsing.
* **C / C++** — regex-based ``#include`` / function-call parsing.
"""

from __future__ import annotations

import ast
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Tuple

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# Data types
# ------------------------------------------------------------------ #


@dataclass
class ImportInfo:
    """A single import of the vulnerable component."""

    file: str  # relative path inside the repo
    line: int
    module: str  # the import source, e.g. "path-to-regexp"
    symbols: list[str]  # what's imported: ["compile", "parse"] or ["*"]
    alias: str | None = None  # alias for namespace / default imports
    kind: str = "named"  # "default", "named", "namespace", "side_effect"
    is_type_only: bool = False  # TS ``import type`` — no runtime usage


@dataclass
class CallSite:
    """A call to an imported symbol from the vulnerable component."""

    file: str  # relative path inside the repo
    line: int
    symbol: str  # what's called: "compile", "ptr.compile", etc.
    context: str  # the source line
    enclosing: str = "<module>"  # enclosing scope: "def handler", "class Foo"


@dataclass
class SymbolGraph:
    """Aggregated results of AST analysis across a repository."""

    imports: list[ImportInfo] = field(default_factory=list)
    calls: list[CallSite] = field(default_factory=list)
    resolved_symbols: list[str] = field(default_factory=list)
    files_analyzed: int = 0
    language_stats: dict[str, int] = field(default_factory=dict)


# ------------------------------------------------------------------ #
# Constants
# ------------------------------------------------------------------ #

_SKIP_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        "__pycache__",
        "vendor",
        "dist",
        "build",
        ".venv",
        "venv",
        "env",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "target",
    }
)


def _build_lang_by_ext() -> dict[str, str]:
    from src.languages import registry as _lang_registry

    return {
        ext: plugin.name
        for plugin in _lang_registry.all_plugins()
        for ext in plugin.file_extensions
    }


_LANG_BY_EXT: dict[str, str] | None = None


def _get_lang_by_ext() -> dict[str, str]:
    global _LANG_BY_EXT
    if _LANG_BY_EXT is None:
        _LANG_BY_EXT = _build_lang_by_ext()
    return _LANG_BY_EXT


# ------------------------------------------------------------------ #
# CWE → code-pattern heuristics
# ------------------------------------------------------------------ #

_CWE_PATTERNS: dict[str, list[str]] = {
    # ReDoS
    "CWE-1333": [
        "regex",
        "regexp",
        "compile",
        "match",
        "test",
        "exec",
        "search",
        "replace",
        "split",
        "Pattern",
        "Matcher",
    ],
    # SQL injection
    "CWE-89": ["query", "execute", "raw", "sql", "cursor", "prepare", "Statement"],
    # XSS
    "CWE-79": [
        "innerHTML",
        "dangerouslySetInnerHTML",
        "document.write",
        "render",
        "html",
        "template",
        "escape",
        "sanitize",
    ],
    # Command injection
    "CWE-78": [
        "exec",
        "spawn",
        "system",
        "popen",
        "subprocess",
        "shell",
        "eval",
        "Runtime",
    ],
    # Path traversal
    "CWE-22": ["path", "join", "resolve", "readFile", "open", "access", "normalize"],
    # Deserialization
    "CWE-502": [
        "deserialize",
        "unmarshal",
        "pickle",
        "yaml.load",
        "JSON.parse",
        "unserialize",
        "ObjectInputStream",
    ],
    # XXE
    "CWE-611": [
        "parse",
        "SAXParser",
        "DocumentBuilder",
        "XMLReader",
        "etree",
        "lxml",
        "xml",
    ],
    # SSRF
    "CWE-918": [
        "fetch",
        "request",
        "get",
        "post",
        "urlopen",
        "http",
        "urllib",
        "axios",
        "HttpClient",
    ],
    # Prototype pollution
    "CWE-1321": [
        "merge",
        "extend",
        "assign",
        "defaults",
        "clone",
        "deepCopy",
        "prototype",
        "__proto__",
    ],
    # Buffer overflow
    "CWE-120": [
        "memcpy",
        "strcpy",
        "strcat",
        "sprintf",
        "gets",
        "scanf",
        "read",
        "recv",
        "buffer",
    ],
    # Integer overflow
    "CWE-190": ["parseInt", "atoi", "strtol", "size_t", "length", "count"],
    # Use after free
    "CWE-416": ["free", "delete", "release", "close", "destroy", "dispose"],
    # Input validation
    "CWE-20": [
        "parse",
        "validate",
        "check",
        "verify",
        "sanitize",
        "filter",
        "input",
        "decode",
        "encode",
    ],
}


# ------------------------------------------------------------------ #
# Component-name variant generation
# ------------------------------------------------------------------ #


def _component_variants(component_name: str) -> list[str]:
    """Generate plausible variants of a package name for cross-language matching.

    E.g. "path-to-regexp" → ["path-to-regexp", "path_to_regexp",
    "pathToRegexp", "PathToRegexp", "pathtoregexp"].
    """
    if not component_name:
        return []
    variants: set[str] = set()
    # Strip npm scope
    bare = component_name.split("/")[-1] if "/" in component_name else component_name
    variants.add(bare)
    # Underscore form (Python convention)
    variants.add(bare.replace("-", "_"))
    # No-separator lowercase
    no_sep = re.sub(r"[-_]", "", bare).lower()
    variants.add(no_sep)
    # camelCase
    parts = re.split(r"[-_]", bare)
    if len(parts) > 1:
        camel = parts[0].lower() + "".join(p.capitalize() for p in parts[1:])
        variants.add(camel)
        # PascalCase
        variants.add("".join(p.capitalize() for p in parts))
    # Keep original with scope
    variants.add(component_name)
    return sorted(variants)


# ================================================================== #
#  Main entry points
# ================================================================== #


def analyze_repository(
    repo_path: str,
    component_name: str,
    known_symbols: list[str] | None = None,
) -> SymbolGraph:
    """Scan a repository for imports of *component_name* and trace call sites.

    Parameters
    ----------
    repo_path
        Absolute path to the cloned repository.
    component_name
        Package name as it appears in the advisory (e.g. ``path-to-regexp``).
    known_symbols
        Symbols already identified from the advisory (may be empty).

    Returns
    -------
    SymbolGraph
        Aggregated import + call information across all source files.
    """
    graph = SymbolGraph()
    variants = _component_variants(component_name)
    if not variants:
        return graph

    known = set(known_symbols or [])
    lang_counts: dict[str, int] = {}

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            lang = _get_lang_by_ext().get(ext)
            if lang is None:
                continue
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, repo_path)
            lang_counts[lang] = lang_counts.get(lang, 0) + 1
            try:
                with open(fpath, "r", errors="ignore") as fh:
                    source = fh.read()
            except Exception:
                continue
            if not any(v in source for v in variants):
                # Fast skip: file doesn't mention the component at all.
                continue
            try:
                imports, calls = _dispatch(lang, source, rel, variants, known)
            except Exception:
                logger.debug("AST analysis failed for %s", rel, exc_info=True)
                continue
            graph.imports.extend(imports)
            graph.calls.extend(calls)

    # Collect unique resolved symbols (from imports) excluding "*".
    seen: set[str] = set()
    for imp in graph.imports:
        for sym in imp.symbols:
            if sym != "*" and sym not in seen:
                seen.add(sym)
                graph.resolved_symbols.append(sym)
    # Include aliases
    for imp in graph.imports:
        if imp.alias and imp.alias not in seen:
            seen.add(imp.alias)
            graph.resolved_symbols.append(imp.alias)

    graph.files_analyzed = sum(lang_counts.values())
    graph.language_stats = lang_counts

    logger.info(
        "[ast_analyzer] Analyzed %d files (%s), found %d imports, %d calls, "
        "%d resolved symbols",
        graph.files_analyzed,
        ", ".join(f"{l}={n}" for l, n in sorted(lang_counts.items())),
        len(graph.imports),
        len(graph.calls),
        len(graph.resolved_symbols),
    )
    return graph


def infer_symbols_from_cwe(cwe_ids: list[str]) -> list[str]:
    """Return candidate search patterns based on CWE identifiers.

    When an advisory provides no vulnerable function names, these heuristic
    patterns give the scanner additional keywords to look for.
    """
    patterns: list[str] = []
    seen: set[str] = set()
    for cwe in cwe_ids:
        for pat in _CWE_PATTERNS.get(cwe, []):
            if pat not in seen:
                seen.add(pat)
                patterns.append(pat)
    return patterns


def format_for_llm(graph: SymbolGraph) -> str:
    """Format AST analysis results as context for inclusion in an LLM prompt."""
    if not graph.imports and not graph.calls:
        return ""
    sections: list[str] = []
    if graph.imports:
        lines = ["IMPORT ANALYSIS (AST-resolved):"]
        for imp in graph.imports:
            syms = ", ".join(imp.symbols)
            alias_s = f" as {imp.alias}" if imp.alias else ""
            type_s = " (type-only)" if imp.is_type_only else ""
            lines.append(
                f"  {imp.file}:{imp.line} — "
                f"imports [{syms}]{alias_s} from '{imp.module}'{type_s}"
            )
        sections.append("\n".join(lines))
    if graph.calls:
        lines = ["CALL SITES (AST-resolved):"]
        for cs in graph.calls:
            lines.append(f"  {cs.file}:{cs.line} — {cs.symbol}() in {cs.enclosing}")
            lines.append(f"    {cs.context}")
        sections.append("\n".join(lines))
    if graph.resolved_symbols:
        sections.append(
            f"DISCOVERED SYMBOLS (from imports): {', '.join(graph.resolved_symbols)}"
        )
    return "\n\n".join(sections)


# ================================================================== #
#  Language dispatch
# ================================================================== #


def _dispatch(
    lang: str,
    source: str,
    rel_path: str,
    variants: list[str],
    known_symbols: set[str],
) -> Tuple[list[ImportInfo], list[CallSite]]:
    """Route to the correct per-language analyzer."""
    if lang == "python":
        return _analyze_python(source, rel_path, variants, known_symbols)
    if lang in ("javascript", "typescript"):
        return _analyze_javascript(
            source,
            rel_path,
            variants,
            known_symbols,
            is_typescript=(lang == "typescript"),
        )
    if lang == "java":
        return _analyze_java(source, rel_path, variants, known_symbols)
    if lang in ("c", "cpp"):
        return _analyze_c_cpp(source, rel_path, variants, known_symbols)
    return [], []


# ================================================================== #
#  Python — full AST parsing
# ================================================================== #


class _PythonVisitor(ast.NodeVisitor):
    """Walk a Python AST to collect imports and call sites."""

    def __init__(
        self,
        variants: list[str],
        source_lines: list[str],
        known_symbols: set[str],
    ):
        self.variants = variants
        self.source_lines = source_lines
        self.known_symbols = known_symbols
        self.imports: list[ImportInfo] = []
        self.calls: list[CallSite] = []
        # Map local_name → original_module_symbol for tracking calls.
        self._imported_names: dict[str, str] = {}
        # Stack tracking the current scope for reporting.
        self._scope_stack: list[str] = []

    # ---- imports ----

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if self._matches(alias.name):
                local = alias.asname or alias.name.split(".")[-1]
                self.imports.append(
                    ImportInfo(
                        file="",  # filled later
                        line=node.lineno,
                        module=alias.name,
                        symbols=["*"],
                        alias=alias.asname,
                        kind="namespace",
                    )
                )
                self._imported_names[local] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        if not self._matches(mod):
            self.generic_visit(node)
            return
        names = node.names or []
        syms = [a.name for a in names]
        self.imports.append(
            ImportInfo(
                file="",
                line=node.lineno,
                module=mod,
                symbols=syms if syms else ["*"],
                alias=None,
                kind="named" if syms else "side_effect",
            )
        )
        for a in names:
            local = a.asname or a.name
            self._imported_names[local] = f"{mod}.{a.name}"
        self.generic_visit(node)

    # ---- scope tracking ----

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._scope_stack.append(f"def {node.name}")
        self.generic_visit(node)
        self._scope_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scope_stack.append(f"class {node.name}")
        self.generic_visit(node)
        self._scope_stack.pop()

    # ---- call tracking ----

    def visit_Call(self, node: ast.Call) -> None:
        name = self._resolve_call_name(node.func)
        if name:
            root = name.split(".")[0]
            if root in self._imported_names or root in self.known_symbols:
                ctx = ""
                if 1 <= node.lineno <= len(self.source_lines):
                    ctx = self.source_lines[node.lineno - 1].strip()
                self.calls.append(
                    CallSite(
                        file="",
                        line=node.lineno,
                        symbol=name,
                        context=ctx,
                        enclosing=self._scope_stack[-1]
                        if self._scope_stack
                        else "<module>",
                    )
                )
        self.generic_visit(node)

    # Also track plain attribute access on imported modules (e.g. ``lib.CONSTANT``).
    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.value, ast.Name) and node.value.id in self._imported_names:
            # Record the attribute name as a discovered symbol.
            self.known_symbols.add(node.attr)
        self.generic_visit(node)

    # ---- helpers ----

    def _matches(self, module_name: str) -> bool:
        return any(v in module_name for v in self.variants)

    @staticmethod
    def _resolve_call_name(node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = _PythonVisitor._resolve_call_name(node.value)
            return f"{base}.{node.attr}" if base else None
        return None


def _analyze_python(
    source: str,
    rel_path: str,
    variants: list[str],
    known_symbols: set[str],
) -> Tuple[list[ImportInfo], list[CallSite]]:
    try:
        tree = ast.parse(source, filename=rel_path)
    except SyntaxError:
        return [], []

    visitor = _PythonVisitor(variants, source.splitlines(), set(known_symbols))
    visitor.visit(tree)

    # Fill in file paths.
    for imp in visitor.imports:
        imp.file = rel_path
    for cs in visitor.calls:
        cs.file = rel_path
    return visitor.imports, visitor.calls


# ================================================================== #
#  JavaScript / TypeScript — regex-based
# ================================================================== #

# ES6: import default from 'pkg'
#       import { a, b } from 'pkg'
#       import { a as x } from 'pkg'
#       import * as ns from 'pkg'
#       import 'pkg'
# We do NOT use a single giant regex — we match candidate lines then parse.

_JS_FROM_RE = re.compile(
    r"""import\s+                # import keyword
    (type\s+)?                   # optional TS 'type' qualifier (captured)
    (.+?)\s+from\s+              # binding clause
    ['"]([^'"]+)['"]             # module specifier
    """,
    re.VERBOSE,
)

_JS_SIDE_EFFECT_RE = re.compile(
    r"""import\s+['"]([^'"]+)['"]""",
)

_JS_REQUIRE_RE = re.compile(
    r"""(?:const|let|var)\s+     # variable keyword
    ([^=]+?)\s*                  # binding
    =\s*require\s*\(\s*          # = require(
    ['"]([^'"]+)['"]             # module specifier
    \s*\)                        # )
    """,
    re.VERBOSE,
)


def _parse_js_bindings(clause: str) -> Tuple[list[str], str | None, bool]:
    """Parse the binding clause of an ES6 import statement.

    Returns ``(named_symbols, default_or_namespace_alias, is_type_only)``.
    """
    clause = clause.strip()
    is_type = clause.startswith("type ")
    if is_type:
        clause = clause[5:].strip()

    named: list[str] = []
    alias: str | None = None

    # Namespace: * as ns
    ns_m = re.match(r"\*\s+as\s+(\w+)", clause)
    if ns_m:
        return ["*"], ns_m.group(1), is_type

    # Named: { a, b as c }
    brace_m = re.search(r"\{([^}]+)\}", clause)
    if brace_m:
        for part in brace_m.group(1).split(","):
            part = part.strip()
            if not part:
                continue
            # "a as b"
            as_m = re.match(r"(\w+)\s+as\s+(\w+)", part)
            if as_m:
                named.append(as_m.group(1))
            else:
                named.append(part)

    # Default import: the identifier before any braces / namespace
    remainder = clause
    if brace_m:
        remainder = clause[: brace_m.start()].rstrip(" ,")
    default_m = re.match(r"(\w+)", remainder)
    if default_m and default_m.group(1) not in ("type",):
        alias = default_m.group(1)
        if not named:
            named = ["default"]

    if not named and not alias:
        named = ["*"]

    return named, alias, is_type


def _parse_require_bindings(binding: str) -> Tuple[list[str], str | None]:
    """Parse the left-hand side of ``const X = require('...')``.

    Returns ``(named_symbols, namespace_alias)``.
    """
    binding = binding.strip()
    # Destructured: { a, b }
    brace_m = re.search(r"\{([^}]+)\}", binding)
    if brace_m:
        names: list[str] = []
        for part in brace_m.group(1).split(","):
            part = part.strip()
            if not part:
                continue
            as_m = re.match(r"(\w+)\s*:\s*(\w+)", part)
            if as_m:
                names.append(as_m.group(1))
            else:
                m = re.match(r"(\w+)", part)
                if m:
                    names.append(m.group(1))
        return names, None
    # Direct: const foo = require(...)
    m = re.match(r"(\w+)", binding)
    if m:
        return ["*"], m.group(1)
    return ["*"], None


def _analyze_javascript(
    source: str,
    rel_path: str,
    variants: list[str],
    known_symbols: set[str],
    is_typescript: bool = False,
) -> Tuple[list[ImportInfo], list[CallSite]]:
    imports: list[ImportInfo] = []
    local_names: dict[str, str] = {}  # local_name → original

    lines = source.splitlines()

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()

        # ES6 import ... from '...'
        m = _JS_FROM_RE.search(stripped)
        if m:
            type_kw, clause, mod = m.group(1), m.group(2), m.group(3)
            if not any(v in mod for v in variants):
                continue
            named, alias, _clause_type = _parse_js_bindings(clause)
            is_type = bool(type_kw) or _clause_type
            imports.append(
                ImportInfo(
                    file=rel_path,
                    line=lineno,
                    module=mod,
                    symbols=named,
                    alias=alias,
                    kind="namespace"
                    if "*" in named and alias
                    else "default"
                    if alias and named == ["default"]
                    else "named",
                    is_type_only=is_type,
                )
            )
            if alias:
                local_names[alias] = mod
            for sym in named:
                if sym not in ("*", "default"):
                    local_names[sym] = f"{mod}.{sym}"
            continue

        # Side-effect import: import 'pkg'
        m = _JS_SIDE_EFFECT_RE.match(stripped)
        if m:
            mod = m.group(1)
            if any(v in mod for v in variants):
                imports.append(
                    ImportInfo(
                        file=rel_path,
                        line=lineno,
                        module=mod,
                        symbols=[],
                        kind="side_effect",
                    )
                )
            continue

        # CommonJS require
        m = _JS_REQUIRE_RE.search(stripped)
        if m:
            binding, mod = m.group(1), m.group(2)
            if not any(v in mod for v in variants):
                continue
            named, alias = _parse_require_bindings(binding)
            imports.append(
                ImportInfo(
                    file=rel_path,
                    line=lineno,
                    module=mod,
                    symbols=named,
                    alias=alias,
                    kind="namespace" if alias and "*" in named else "named",
                )
            )
            if alias:
                local_names[alias] = mod
            for sym in named:
                if sym not in ("*",):
                    local_names[sym] = f"{mod}.{sym}"
            continue

    # Scan for call sites of imported symbols.
    calls = _scan_calls_by_name(lines, rel_path, local_names, known_symbols)
    return imports, calls


# ================================================================== #
#  Java — regex-based
# ================================================================== #

_JAVA_IMPORT_RE = re.compile(
    r"import\s+(?:static\s+)?([a-zA-Z_][\w.]*(?:\.\*)?)\s*;",
)


def _analyze_java(
    source: str,
    rel_path: str,
    variants: list[str],
    known_symbols: set[str],
) -> Tuple[list[ImportInfo], list[CallSite]]:
    imports: list[ImportInfo] = []
    local_names: dict[str, str] = {}

    lines = source.splitlines()
    for lineno, line in enumerate(lines, 1):
        m = _JAVA_IMPORT_RE.search(line)
        if not m:
            continue
        full_import = m.group(1)  # e.g. "com.google.common.io.Files"
        if not any(v.lower() in full_import.lower() for v in variants):
            continue
        # Extract the class name (last segment, unless wildcard).
        parts = full_import.rsplit(".", 1)
        if parts[-1] == "*":
            sym = "*"
            alias = parts[0].rsplit(".", 1)[-1] if "." in parts[0] else parts[0]
        else:
            sym = parts[-1]
            alias = None
        imports.append(
            ImportInfo(
                file=rel_path,
                line=lineno,
                module=full_import,
                symbols=[sym],
                alias=alias,
                kind="namespace" if sym == "*" else "named",
            )
        )
        if sym != "*":
            local_names[sym] = full_import

    calls = _scan_calls_by_name(lines, rel_path, local_names, known_symbols)
    return imports, calls


# ================================================================== #
#  C / C++ — regex-based
# ================================================================== #

_C_INCLUDE_RE = re.compile(r'#\s*include\s+[<"]([^>"]+)[>"]')


def _analyze_c_cpp(
    source: str,
    rel_path: str,
    variants: list[str],
    known_symbols: set[str],
) -> Tuple[list[ImportInfo], list[CallSite]]:
    imports: list[ImportInfo] = []
    local_names: dict[str, str] = {}

    lines = source.splitlines()
    for lineno, line in enumerate(lines, 1):
        m = _C_INCLUDE_RE.search(line)
        if not m:
            continue
        header = m.group(1)  # e.g. "openssl/ssl.h"
        if not any(v.lower() in header.lower() for v in variants):
            continue
        imports.append(
            ImportInfo(
                file=rel_path,
                line=lineno,
                module=header,
                symbols=["*"],
                kind="namespace",
            )
        )

    # For C/C++ we cannot easily resolve exported symbols from a header
    # without actually parsing it.  We fall back to scanning for any known
    # symbols or patterns that might come from advisory + CWE heuristics.
    calls = _scan_calls_by_name(lines, rel_path, local_names, known_symbols)
    return imports, calls


# ================================================================== #
#  Shared call-site scanner
# ================================================================== #


def _scan_calls_by_name(
    lines: list[str],
    rel_path: str,
    local_names: dict[str, str],
    known_symbols: set[str],
) -> list[CallSite]:
    """Scan *lines* for function call patterns matching any imported or known symbol."""
    if not local_names and not known_symbols:
        return []

    # Build a combined set of names to look for.
    all_names = set(local_names.keys()) | known_symbols

    # Build a single regex that matches any of the names followed by ``(``.
    # Also match ``name.method(`` for namespace/default imports.
    # Escape special regex chars just in case.
    escaped = [re.escape(n) for n in sorted(all_names, key=len, reverse=True)]
    if not escaped:
        return []
    call_re = re.compile(
        r"(?<![A-Za-z0-9_])(" + "|".join(escaped) + r")(?:\.[A-Za-z_]\w*)?\s*\(",
    )

    calls: list[CallSite] = []
    enclosing = "<module>"
    # Lightweight scope tracking via indentation heuristics.
    scope_re = re.compile(
        r"^\s*(?:def|function|fn|func|async\s+def|async\s+function|"
        r"class|struct|impl)\s+(\w+)",
    )
    for lineno, line in enumerate(lines, 1):
        # Update scope.
        sm = scope_re.match(line)
        if sm:
            enclosing = sm.group(0).strip()
        for m in call_re.finditer(line):
            # Skip if inside a comment (rough heuristic).
            prefix = line[: m.start()]
            if _in_comment(prefix, line):
                continue
            calls.append(
                CallSite(
                    file=rel_path,
                    line=lineno,
                    symbol=m.group(0).rstrip("( "),
                    context=line.strip(),
                    enclosing=enclosing,
                )
            )
    return calls


def _in_comment(prefix: str, full_line: str) -> bool:
    """Rough check whether current position is inside a comment."""
    s = prefix.lstrip()
    if s.startswith("//") or s.startswith("#") or s.startswith("--"):
        return True
    # Very rough block-comment check: ``/* ... */``
    if "/*" in prefix and "*/" not in prefix:
        return True
    return False
