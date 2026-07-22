"""Source-code scanner agent.

1. Walks the repo and collects *relevant* source snippets — files that
   mention the component name or any known vulnerable symbol.
2. Collects broader structural context (imports, function/class signatures,
   and call-site references) from files that touch the component so the LLM
   can reason about invocation paths.
3. Sends everything to the LLM, which determines whether the vulnerable
   code-paths are reachable from production entry-points and traces the
   invocation chain.

The scanner is **language-agnostic**: it uses grep + lightweight regex
heuristics to extract structural cues from any source file, then delegates
the deep understanding to the LLM which can read most popular languages.
"""

import logging
import os
import re
from typing import Any, Dict, List

from src.agents.web_research import generate_with_research
from src.llm.prompt_registry import get_prompt_value

logger = logging.getLogger(__name__)

# Maximum characters of source context we feed into one LLM prompt.
_MAX_CONTEXT_CHARS = 24_000
# Extra budget for structural context (imports + signatures).
_MAX_STRUCTURE_CHARS = 8_000
# Ignore unexpectedly large source files from untrusted repositories. This
# bounds memory/LLM-context work and avoids following generated-file bait.
_MAX_SOURCE_FILE_BYTES = 1_000_000
# Context lines around a hit to include.
_CONTEXT_LINES = 5

_RESEARCH_ADDENDUM = get_prompt_value("common", "web_research_addendum")
_REACHABILITY_RESPONSE_CONTRACT = get_prompt_value(
    "code_reachability", "response_contract"
)
_DEEP_RESPONSE_CONTRACT = get_prompt_value("deep_analysis", "response_contract")
_TRANSITIVE_RESPONSE_CONTRACT = get_prompt_value(
    "transitive_analysis", "response_contract"
)

# ---------------------------------------------------------------------------
# Supported source extensions (extendable).
# ---------------------------------------------------------------------------
_SOURCE_EXTS = (
    # Python
    ".py",
    # JavaScript / TypeScript
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    # JVM
    ".java",
    ".kt",
    ".kts",
    ".scala",
    ".groovy",
    # Go
    ".go",
    # Rust
    ".rs",
    # C / C++
    ".c",
    ".cpp",
    ".cc",
    ".cxx",
    ".h",
    ".hpp",
    ".hxx",
    # C#
    ".cs",
    # Ruby
    ".rb",
    # PHP
    ".php",
    # Swift / Objective-C
    ".swift",
    ".m",
    ".mm",
    # Elixir / Erlang
    ".ex",
    ".exs",
    ".erl",
)

# Directories to always skip.
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        "node_modules",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "dist",
        "build",
        "vendor",
        "venv",
        ".venv",
        "target",
    }
)

# ---------------------------------------------------------------------------
# Language-agnostic regex patterns for structural extraction.
#
# These intentionally stay simple — the LLM handles the nuance.  Each
# pattern maps to a *kind* label used in the compact output.  The first
# capture group (if any) is included in the output line.
# ---------------------------------------------------------------------------
_IMPORT_RE = re.compile(
    r"^\s*(?:"
    r"(?:from\s+\S+\s+)?import\s+.+"  # Python
    r"|require\s*\(.+"  # JS/Ruby require()
    r"|using\s+.+"  # C#/C++
    r"|include\s+.+"  # C/PHP/Ruby
    r"|#include\s+.+"  # C/C++
    r"|use\s+.+"  # Rust/PHP/Perl
    r"|extern\s+crate\s+.+"  # Rust
    r"|package\s+.+"  # Go/Java package decl
    r")",
    re.MULTILINE,
)

_SIGNATURE_RE = re.compile(
    r"^\s*(?:"
    r"(?:export\s+)?(?:async\s+)?(?:def|function|fn|func|fun|sub|proc)\s+\w+"  # Python/JS/Rust/Go/Kotlin/…
    r"|(?:(?:public|private|protected|internal|static|abstract|override|virtual|async)\s+)*"
    r"(?:\w+(?:<[^>]+>)?(?:\[\])?\s+)?\w+\s*\([^)]*\)"  # Java/C#/C++ method
    r"|class\s+\w+"  # class
    r"|struct\s+\w+"  # struct
    r"|interface\s+\w+"  # interface
    r"|trait\s+\w+"  # trait
    r"|impl(?:\s+\w+)?\s+(?:for\s+)?\w+"  # Rust impl
    r"|module\s+\w+"  # module
    r")",
    re.MULTILINE,
)


# ---------------------------------------------------------------------------
# Language-agnostic helpers
# ---------------------------------------------------------------------------
def _is_source_file(fname: str) -> bool:
    """Check if *fname* has a recognised source extension."""
    _, ext = os.path.splitext(fname)
    return ext.lower() in _SOURCE_EXTS


def _is_safe_repo_file(file_path: str, repo_path: str) -> bool:
    """Return whether a source candidate is a bounded file inside the repo.

    Git repositories are untrusted input. Refuse symlinks so a checkout cannot
    make the scanner copy host files into an LLM prompt, and cap source size to
    prevent a single generated file from consuming excessive resources.
    """
    try:
        if os.path.islink(file_path) or not os.path.isfile(file_path):
            return False
        repo_real = os.path.realpath(repo_path)
        file_real = os.path.realpath(file_path)
        if os.path.commonpath((repo_real, file_real)) != repo_real:
            return False
        return os.path.getsize(file_path) <= _MAX_SOURCE_FILE_BYTES
    except (OSError, ValueError):
        return False


def _extract_structure(file_path: str, repo_path: str) -> str | None:
    """Extract imports and function/class signatures from any source file.

    Uses lightweight regex patterns — intentionally imprecise so that it
    works across languages.  The LLM receives the compact output and does
    the real semantic analysis.
    """
    if not _is_safe_repo_file(file_path, repo_path):
        return None
    try:
        with open(file_path, "r", errors="ignore") as f:
            source = f.read()
    except Exception:
        return None

    rel = os.path.relpath(file_path, repo_path)
    lines: List[str] = [f"=== {rel} ==="]

    # Collect import-like lines (deduplicated, order preserved).
    for m in _IMPORT_RE.finditer(source):
        lines.append(f"  {m.group().strip()}")

    # Collect function / class / struct signatures with line numbers.
    for m in _SIGNATURE_RE.finditer(source):
        lineno = source[: m.start()].count("\n") + 1
        sig = m.group().strip()
        # Truncate overly long signatures (e.g. long C++ template params).
        if len(sig) > 120:
            sig = sig[:117] + "…"
        lines.append(f"  {sig}  [line {lineno}]")

    if len(lines) <= 1:
        return None
    return "\n".join(lines)


def search_usage(repo_path: str, component_name: str, symbols: List[str]) -> List[str]:
    """Walk the repo and return grep-style hit lines.

    Language-agnostic: scans every recognised source file for textual
    matches of the component name or vulnerable symbols.
    """
    hits: List[str] = []
    if not component_name:
        logger.warning("search_usage called with empty component_name — skipping")
        return ["No direct usage found"]
    search_terms = [t for t in ([component_name] + symbols) if t]
    logger.info(
        "Scanning %s for %d terms (%s + %d symbols)",
        repo_path,
        len(search_terms),
        component_name,
        len(symbols),
    )
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fname in files:
            if not _is_source_file(fname):
                continue
            fpath = os.path.join(root, fname)
            if not _is_safe_repo_file(fpath, repo_path):
                continue
            try:
                with open(fpath, "r", errors="ignore") as f:
                    for i, line in enumerate(f, start=1):
                        for term in search_terms:
                            if term in line:
                                hits.append(f"{fpath}:{i}: {line.strip()}")
                                break  # one hit per line is enough
            except Exception:
                pass
    if not hits:
        return ["No direct usage found"]
    return hits


def collect_snippets(
    repo_path: str,
    component_name: str,
    symbols: List[str],
) -> List[Dict[str, Any]]:
    """Collect source-code snippets around every hit for LLM context.

    Returns a list of ``{"file": ..., "line": ..., "snippet": ...}`` dicts
    trimmed so the total doesn't exceed ``_MAX_CONTEXT_CHARS``.
    """
    hits = search_usage(repo_path, component_name, symbols)
    if hits == ["No direct usage found"]:
        return []

    snippets: List[Dict[str, Any]] = []
    total_chars = 0

    for hit in hits:
        # Parse "path:line: text"
        parts = hit.split(":", 2)
        if len(parts) < 2:
            continue
        fpath, lineno_s = parts[0], parts[1]
        if not _is_safe_repo_file(fpath, repo_path):
            continue
        try:
            lineno = int(lineno_s.strip())
        except ValueError:
            continue

        try:
            with open(fpath, "r", errors="ignore") as f:
                all_lines = f.readlines()
        except Exception:
            continue

        start = max(0, lineno - 1 - _CONTEXT_LINES)
        end = min(len(all_lines), lineno + _CONTEXT_LINES)
        snippet = "".join(all_lines[start:end])

        if total_chars + len(snippet) > _MAX_CONTEXT_CHARS:
            break

        rel_path = os.path.relpath(fpath, repo_path)
        snippets.append({"file": rel_path, "line": lineno, "snippet": snippet})
        total_chars += len(snippet)

    logger.info(
        "Collected %d snippets (%d chars) for LLM analysis", len(snippets), total_chars
    )
    return snippets


def collect_structure(
    repo_path: str,
    component_name: str,
    symbols: List[str],
) -> str:
    """Collect structural context (imports + signatures) from source files
    that reference the component or vulnerable symbols.

    Language-agnostic: processes any file with a recognised source extension.
    The LLM uses this to trace invocation paths without a dedicated
    call-graph engine.
    """
    search_terms = [t for t in ([component_name] + symbols) if t]
    if not search_terms:
        return ""

    structures: List[str] = []
    total_chars = 0

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fname in files:
            if not _is_source_file(fname):
                continue
            fpath = os.path.join(root, fname)
            if not _is_safe_repo_file(fpath, repo_path):
                continue
            try:
                with open(fpath, "r", errors="ignore") as f:
                    source = f.read()
            except Exception:
                continue

            if not any(term in source for term in search_terms):
                continue

            struct = _extract_structure(fpath, repo_path)
            if struct and total_chars + len(struct) <= _MAX_STRUCTURE_CHARS:
                structures.append(struct)
                total_chars += len(struct)

    logger.info(
        "Collected structural context from %d files (%d chars)",
        len(structures),
        total_chars,
    )
    return "\n\n".join(structures)


_SYSTEM_PROMPT = get_prompt_value("code_reachability", "system")

_ANALYSIS_PROTOCOL = get_prompt_value("code_reachability", "analysis_protocol")


async def analyze_with_llm(
    ollama: Any,
    vuln_id: str,
    advisory_summary: str,
    snippets: List[Dict[str, Any]],
    structure: str = "",
) -> Dict[str, Any]:
    """Ask the LLM whether the code is vulnerable based on snippets and structure.

    The LLM traces invocation paths itself using the structural context
    (imports + function signatures + call edges) rather than relying on
    a separate call-graph engine.

    Returns ``{"reachable": bool, "reasoning": str, "risk_areas": [str],
               "invocation_paths": [str]}``.
    """
    if not snippets and not structure:
        return {
            "reachable": False,
            "reasoning": "No code references to the component or vulnerable symbols were found.",
            "risk_areas": [],
            "invocation_paths": [],
        }

    snippet_text = "\n\n".join(
        f"--- {s['file']}:{s['line']} ---\n{s['snippet']}" for s in snippets
    )

    structure_block = ""
    if structure:
        structure_block = f"\nSTRUCTURE:\n{structure}\n"

    prompt = f"""{_ANALYSIS_PROTOCOL}
Now analyze the following:
VULNERABILITY: {vuln_id}
ADVISORY: {advisory_summary}
SNIPPETS:
{snippet_text}
{structure_block}
{_REACHABILITY_RESPONSE_CONTRACT}"""

    logger.info(
        "[code_scanner] Asking LLM to analyze %d snippets + structure for %s",
        len(snippets),
        vuln_id,
    )
    try:
        raw, research_log = await generate_with_research(
            ollama,
            prompt,
            system=_SYSTEM_PROMPT + _RESEARCH_ADDENDUM,
        )
        result = _parse_llm_response(raw)
        if research_log:
            result["research_log"] = research_log
        return result
    except Exception as e:
        logger.error("LLM analysis failed: %s", e)
        return {
            "reachable": False,
            "reasoning": f"LLM analysis unavailable: {e}",
            "error": str(e),
            "risk_areas": [],
            "invocation_paths": [],
        }


def _parse_llm_response(raw: str) -> Dict[str, Any]:
    """Parse the structured LLM response.

    Handles models that put extra text before/after the fields and
    multi-line REASONING or INVOCATION_PATHS.
    """
    reachable = False
    reasoning = ""
    risk_areas: List[str] = []
    invocation_paths: List[str] = []
    current_field: str | None = None

    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        upper = stripped.upper()

        if upper.startswith("REACHABLE:"):
            reachable = "YES" in upper.split(":", 1)[1].upper()
            current_field = None
        elif upper.startswith("RISK_AREAS:"):
            val = stripped.split(":", 1)[1].strip()
            if val.upper() != "NONE":
                risk_areas = [a.strip() for a in val.split(",") if a.strip()]
            current_field = None
        elif upper.startswith("INVOCATION_PATHS:"):
            val = stripped.split(":", 1)[1].strip()
            if val and val.upper() != "NONE":
                invocation_paths.append(val)
            current_field = "paths"
        elif upper.startswith("REASONING:"):
            reasoning = stripped.split(":", 1)[1].strip()
            current_field = "reasoning"
        elif current_field == "paths":
            # Continuation lines for invocation paths (indented arrow chains).
            if "→" in stripped or "->" in stripped:
                invocation_paths.append(stripped)
            else:
                current_field = None
        elif current_field == "reasoning":
            reasoning += " " + stripped

    if not reasoning:
        reasoning = raw.strip()

    return {
        "reachable": reachable,
        "reasoning": reasoning,
        "risk_areas": risk_areas,
        "invocation_paths": invocation_paths,
    }


def classify_reachability(hits: List[str]) -> str:
    """Heuristic fallback when LLM is unavailable."""
    if not hits or hits == ["No direct usage found"]:
        return "Not Reachable"
    prod_hits = [
        h for h in hits if "/test/" not in h and "/tests/" not in h and "test_" not in h
    ]
    if prod_hits:
        return "Reachable"
    return "Potentially Reachable"


# ---------------------------------------------------------------------------
# Second-pass deep analysis — extract code along identified paths and
# send it to the LLM for focused reasoning about exploitability.
# ---------------------------------------------------------------------------

# Budget for the deep-analysis context (larger than the first pass since
# we are sending fewer, more targeted files).
_MAX_DEEP_CONTEXT_CHARS = 32_000


def _parse_file_line_ref(ref: str) -> tuple[str, int | None]:
    """Parse ``file.py:42`` or ``file.py`` into (path, line_or_None)."""
    if ":" in ref:
        parts = ref.rsplit(":", 1)
        try:
            return parts[0].strip(), int(parts[1])
        except ValueError:
            return ref.strip(), None
    return ref.strip(), None


def _parse_path_references(
    invocation_paths: List[str],
    risk_areas: List[str],
) -> set[str]:
    """Extract unique file path candidates from invocation paths and risk areas.

    Invocation-path lines look like:
        [PRODUCTION] src/app.py::main → src/client.py::handle_request → libfoo.parse_header()
    Risk areas look like:
        src/client.py:42

    Some LLMs also produce module-style references (``module.submodule``) or
    bare filenames without directory prefixes.  We collect *all* plausible
    candidates here; resolution against the actual repo is done later.
    """
    files: set[str] = set()

    for area in risk_areas:
        fpath, _ = _parse_file_line_ref(area)
        if fpath:
            files.add(fpath)

    for path_line in invocation_paths:
        # Strip label like [PRODUCTION] / [TEST]
        cleaned = re.sub(r"\[(?:PRODUCTION|TEST)\]\s*", "", path_line)
        # Split on arrow separators
        for segment in re.split(r"\s*[→\->]+\s*", cleaned):
            segment = segment.strip()
            if not segment:
                continue
            # "src/app.py::main" → "src/app.py"
            if "::" in segment:
                fpath = segment.split("::")[0].strip()
            else:
                fpath = segment
            # Strip trailing () from function-call syntax
            fpath = re.sub(r"\(\)$", "", fpath).strip()
            if not fpath:
                continue
            # Accept anything with a dot (extension or dotted module path)
            if "." in fpath:
                files.add(fpath)

    return files


def _build_file_index(repo_path: str) -> Dict[str, List[str]]:
    """Build a basename → [relative-path, …] index for fuzzy file resolution."""
    index: Dict[str, List[str]] = {}
    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fname in filenames:
            if not _is_source_file(fname):
                continue
            file_path = os.path.join(root, fname)
            if not _is_safe_repo_file(file_path, repo_path):
                continue
            rel = os.path.relpath(file_path, repo_path)
            index.setdefault(fname, []).append(rel)
    return index


def _resolve_file(
    candidate: str,
    repo_path: str,
    file_index: Dict[str, List[str]],
) -> str | None:
    """Try to resolve a candidate path from the LLM to an actual repo file.

    Strategies (in order):
    1. Direct: ``os.path.join(repo_path, candidate)`` exists.
    2. Basename match: look up ``os.path.basename(candidate)`` in *file_index*.
       If there's exactly one match, use it.  If multiple, prefer the one whose
       relative path contains directory components from the candidate.
    3. Dotted-module heuristic: convert ``pkg.module`` to ``pkg/module.py``
       (or ``pkg/module/__init__.py``) and retry direct + basename.
    """
    # 1. Direct
    if _is_safe_repo_file(os.path.join(repo_path, candidate), repo_path):
        return candidate

    # Helper: pick best from a list of matches
    def _best(matches: List[str], hint: str) -> str:
        if len(matches) == 1:
            return matches[0]
        # Prefer paths sharing directory components with the hint
        hint_parts = set(hint.replace("\\", "/").split("/")[:-1])
        if hint_parts:
            scored = []
            for m in matches:
                m_parts = set(m.replace("\\", "/").split("/")[:-1])
                scored.append((len(hint_parts & m_parts), m))
            scored.sort(key=lambda t: -t[0])
            if scored[0][0] > 0:
                return scored[0][1]
        return matches[0]

    # 2. Basename
    basename = os.path.basename(candidate)
    if basename in file_index:
        return _best(file_index[basename], candidate)

    # 3. Dotted-module → path conversion (e.g. "mylib.client" → "mylib/client.py")
    if "/" not in candidate and "\\" not in candidate and "." in candidate:
        parts = candidate.split(".")
        # Try each possible split: the last N parts might be the module chain
        for i in range(len(parts)):
            stem = "/".join(parts[: i + 1])
            for ext in (".py", ".js", ".ts", ".java", ".go", ".rs"):
                mod_file = stem + ext
                mod_basename = os.path.basename(mod_file)
                if _is_safe_repo_file(os.path.join(repo_path, mod_file), repo_path):
                    return mod_file
                if mod_basename in file_index:
                    return _best(file_index[mod_basename], mod_file)
            # __init__.py for package dirs
            init_file = stem + "/__init__.py"
            if _is_safe_repo_file(os.path.join(repo_path, init_file), repo_path):
                return init_file

    return None


def extract_path_context(
    repo_path: str,
    invocation_paths: List[str],
    risk_areas: List[str],
    snippet_files: List[str] | None = None,
) -> List[Dict[str, Any]]:
    """Extract full source from files referenced in the first-pass results.

    Returns a list of ``{"file": ..., "content": ...}`` dicts containing the
    complete source of each file along the identified invocation paths, up to
    ``_MAX_DEEP_CONTEXT_CHARS``.  Files are sorted so that risk-area files
    come first.

    *snippet_files* is an optional list of repo-relative paths that the code
    scanner already found hits in.  These are used as fallback when LLM-produced
    paths cannot be resolved against the filesystem.
    """
    candidates = _parse_path_references(invocation_paths, risk_areas)

    if not candidates and not snippet_files:
        return []

    # Build a filename index for fuzzy resolution
    file_index = _build_file_index(repo_path)

    # Resolve LLM candidates to real paths
    resolved: dict[str, str] = {}  # resolved_rel_path → original_candidate
    unresolved: list[str] = []
    for cand in candidates:
        real = _resolve_file(cand, repo_path, file_index)
        if real and real not in resolved:
            resolved[real] = cand
        else:
            unresolved.append(cand)

    if unresolved:
        logger.info(
            "Could not resolve %d path references: %s",
            len(unresolved),
            unresolved,
        )

    # If nothing resolved from LLM paths, fall back to snippet files
    if not resolved and snippet_files:
        logger.info(
            "Falling back to %d snippet files for deep analysis context",
            len(snippet_files),
        )
        for sf in snippet_files:
            if _is_safe_repo_file(os.path.join(repo_path, sf), repo_path):
                resolved[sf] = sf

    if not resolved:
        return []

    # Prioritise risk-area files (they contain the vulnerable call).
    risk_file_set = {_parse_file_line_ref(a)[0] for a in risk_areas}
    # Also check resolved paths that came from risk-area candidates
    risk_resolved = set()
    for real_path, orig in resolved.items():
        if orig in risk_file_set:
            risk_resolved.add(real_path)

    ordered = sorted(
        resolved.keys(),
        key=lambda f: (f not in risk_resolved, f),
    )

    result: List[Dict[str, Any]] = []
    total_chars = 0

    for rel_path in ordered:
        abs_path = os.path.join(repo_path, rel_path)
        if not _is_safe_repo_file(abs_path, repo_path):
            continue
        try:
            with open(abs_path, "r", errors="ignore") as f:
                content = f.read()
        except Exception:
            continue

        if total_chars + len(content) > _MAX_DEEP_CONTEXT_CHARS:
            remaining = _MAX_DEEP_CONTEXT_CHARS - total_chars
            if remaining > 500:
                content = content[:remaining] + "\n… [truncated]"
            else:
                break

        result.append({"file": rel_path, "content": content})
        total_chars += len(content)

    logger.info(
        "Extracted deep context: %d files (%d chars), resolved %d/%d LLM refs, "
        "%d snippet fallbacks",
        len(result),
        total_chars,
        len({r for r in resolved if r not in (snippet_files or [])}),
        len(candidates),
        len({r for r in resolved if snippet_files and r in snippet_files}),
    )
    return result


_DEEP_SYSTEM_PROMPT = get_prompt_value("deep_analysis", "system")

_DEEP_ANALYSIS_PROTOCOL = get_prompt_value("deep_analysis", "analysis_protocol")


async def deep_analyze_with_llm(
    ollama: Any,
    vuln_id: str,
    advisory_summary: str,
    first_pass: Dict[str, Any],
    path_context: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Second-pass LLM analysis with full source of files along invocation paths.

    Receives the first-pass results (risk areas, invocation paths, reasoning)
    and the full source of the files mentioned.  Returns a deeper assessment
    of exploitability and mitigations.
    """
    if not path_context:
        return {
            "confirmed": False,
            "mitigations": "N/A",
            "exploitable": "UNCERTAIN",
            "risk_level": "LOW",
            "reasoning": "No source files could be extracted along the identified paths.",
            "skipped": True,
        }

    # Format first-pass finding summary
    paths = first_pass.get("invocation_paths", [])
    finding_summary = (
        f"{'REACHABLE' if first_pass.get('reachable') else 'NOT REACHABLE'}"
    )
    if paths:
        finding_summary += " via " + "; ".join(paths[:5])
    if first_pass.get("risk_areas"):
        finding_summary += f" | Risk areas: {', '.join(first_pass['risk_areas'])}"

    # Format full file contents
    files_text = "\n\n".join(
        f"=== {f['file']} ===\n{f['content']}" for f in path_context
    )

    prompt = f"""{_DEEP_ANALYSIS_PROTOCOL}
Now perform deep analysis on the following:
VULNERABILITY: {vuln_id}
ADVISORY: {advisory_summary}
FIRST-PASS FINDING: {finding_summary}
FILES:
{files_text}

{_DEEP_RESPONSE_CONTRACT}"""

    logger.info(
        "[code_scanner] Deep analysis: %d files (%d chars) for %s",
        len(path_context),
        sum(len(f["content"]) for f in path_context),
        vuln_id,
    )
    try:
        raw, research_log = await generate_with_research(
            ollama,
            prompt,
            system=_DEEP_SYSTEM_PROMPT + _RESEARCH_ADDENDUM,
        )
        result = _parse_deep_response(raw)
        if research_log:
            result["research_log"] = research_log
        return result
    except Exception as e:
        logger.error("Deep LLM analysis failed: %s", e)
        return {
            "confirmed": first_pass.get("reachable", False),
            "mitigations": "unknown",
            "exploitable": "UNCERTAIN",
            "risk_level": "MEDIUM" if first_pass.get("reachable") else "LOW",
            "reasoning": f"Deep analysis unavailable: {e}",
            "error": str(e),
        }


def _parse_deep_response(raw: str) -> Dict[str, Any]:
    """Parse the structured deep-analysis LLM response."""
    confirmed = False
    mitigations = ""
    exploitable = "UNCERTAIN"
    risk_level = "MEDIUM"
    reasoning = ""
    current_field: str | None = None

    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        upper = stripped.upper()

        if upper.startswith("CONFIRMED:"):
            confirmed = "YES" in upper.split(":", 1)[1].upper()
            current_field = None
        elif upper.startswith("MITIGATIONS:"):
            mitigations = stripped.split(":", 1)[1].strip()
            current_field = "mitigations"
        elif upper.startswith("EXPLOITABLE:"):
            val = stripped.split(":", 1)[1].strip().upper()
            if val in ("YES", "NO", "UNCERTAIN"):
                exploitable = val
            current_field = None
        elif upper.startswith("RISK_LEVEL:"):
            val = stripped.split(":", 1)[1].strip().upper()
            for canon in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"):
                if canon in val:
                    risk_level = canon
                    break
            current_field = None
        elif upper.startswith("REASONING:"):
            reasoning = stripped.split(":", 1)[1].strip()
            current_field = "reasoning"
        elif current_field == "mitigations":
            mitigations += " " + stripped
        elif current_field == "reasoning":
            reasoning += " " + stripped

    if not reasoning:
        reasoning = raw.strip()

    return {
        "confirmed": confirmed,
        "mitigations": mitigations or "NONE",
        "exploitable": exploitable,
        "risk_level": risk_level,
        "reasoning": reasoning,
    }


# ---------------------------------------------------------------------------
# Transitive call-path analysis
# ---------------------------------------------------------------------------

_TRANSITIVE_SYSTEM_PROMPT = get_prompt_value("transitive_analysis", "system")

_TRANSITIVE_ANALYSIS_PROTOCOL = get_prompt_value(
    "transitive_analysis", "analysis_protocol"
)


async def analyze_transitive_paths(
    ollama: Any,
    vuln_id: str,
    advisory_summary: str,
    intermediaries: List[Dict[str, Any]],
    repo_path: str,
    vulnerable_symbols: List[str] | None = None,
    dependency_chains: List[Dict[str, Any]] | None = None,
    vulnerable_component: str = "",
) -> Dict[str, Any]:
    """Analyse whether transitive dependencies are reachable through intermediaries.

    1. Scans project source for usage of each intermediary package.
    2. Collects snippets and structural context for those usages.
    3. Asks the LLM whether the project's usage of the intermediary could
       trigger the vulnerable code path, using full dependency chains for
       context.

    *dependency_chains* is a list of chain dicts as returned by
    ``build_dependency_chains()`` — each has ``chain`` (list of
    ``{"name", "version"}``) and ``lock_file``.

    Returns ``{"reachable": str, "confidence": str, "intermediary": str,
               "reasoning": str, "usage_hits": int, "intermediaries_checked": [str]}``.
    """
    if not intermediaries:
        return {
            "reachable": "NO",
            "confidence": "High",
            "intermediary": "",
            "reasoning": "No intermediary packages identified in lock files.",
            "usage_hits": 0,
            "intermediaries_checked": [],
        }

    # Scan project code for references to each intermediary
    all_snippets: List[Dict[str, Any]] = []
    all_structure_parts: List[str] = []
    total_hits = 0
    checked: List[str] = []

    for inter in intermediaries:
        name = inter["name"]
        checked.append(name)
        symbols = vulnerable_symbols or []
        hits = search_usage(repo_path, name, [])
        if hits != ["No direct usage found"]:
            total_hits += len(hits)
            snippets = collect_snippets(repo_path, name, [])
            all_snippets.extend(snippets)
            struct = collect_structure(repo_path, name, [])
            if struct:
                all_structure_parts.append(struct)

    if not all_snippets and not all_structure_parts:
        return {
            "reachable": "NO",
            "confidence": "Medium",
            "intermediary": ", ".join(checked),
            "reasoning": (
                "The intermediary packages are present as transitive dependencies "
                "but are not referenced in the project's source code. The vulnerable "
                "code is not reachable through the project's own code."
            ),
            "usage_hits": 0,
            "intermediaries_checked": checked,
            "snippets": [],
            "structure_excerpt": "",
        }

    if not ollama:
        return {
            "reachable": "UNCERTAIN",
            "confidence": "Low",
            "intermediary": ", ".join(checked),
            "reasoning": (
                f"Found {total_hits} references to intermediary packages in "
                f"source code but LLM is unavailable for path analysis."
            ),
            "usage_hits": total_hits,
            "intermediaries_checked": checked,
            "snippets": all_snippets[:6],
            "structure_excerpt": "".join(all_structure_parts)[:4000],
        }

    # Build LLM prompt
    inter_list = ", ".join(
        f"{i['name']} ({i.get('version', '?')} via {i.get('lock_file', '?')})"
        for i in intermediaries
    )

    # Format dependency chains
    chains_block = ""
    if dependency_chains:
        chain_lines = []
        for c in dependency_chains[:20]:  # Cap at 20 to avoid prompt bloat
            parts = [
                f"{n['name']}@{n['version']}" if n.get("version") else n["name"]
                for n in c["chain"]
            ]
            chain_lines.append(
                f"  {' → '.join(parts)} → [VULNERABLE] (via {c['lock_file']})"
            )
        if len(dependency_chains) > 20:
            chain_lines.append(f"  … and {len(dependency_chains) - 20} more chains")
        chains_block = "\nDEPENDENCY CHAINS:\n" + "\n".join(chain_lines) + "\n"

    snippet_text = "\n\n".join(
        f"--- {s['file']}:{s['line']} ---\n{s['snippet']}" for s in all_snippets
    )

    structure_block = ""
    if all_structure_parts:
        structure_block = f"\nSTRUCTURE:\n{''.join(all_structure_parts)}\n"

    prompt = f"""{_TRANSITIVE_ANALYSIS_PROTOCOL}
Now analyze the following:
VULNERABILITY: {vuln_id}
ADVISORY: {advisory_summary}
INTERMEDIARY PACKAGES: {inter_list}
VULNERABLE SYMBOLS: {", ".join(vulnerable_symbols or ["unknown"])}{chains_block}
SNIPPETS:
{snippet_text}
{structure_block}
{_TRANSITIVE_RESPONSE_CONTRACT}"""

    logger.info(
        "[code_scanner] Transitive path analysis: %d intermediaries, %d snippets for %s",
        len(intermediaries),
        len(all_snippets),
        vuln_id,
    )
    try:
        raw, research_log = await generate_with_research(
            ollama,
            prompt,
            system=_TRANSITIVE_SYSTEM_PROMPT + _RESEARCH_ADDENDUM,
            vulnerable_component=vulnerable_component,
        )
        result = _parse_transitive_response(raw)
        result["usage_hits"] = total_hits
        result["intermediaries_checked"] = checked
        result["snippets"] = all_snippets[:6]
        result["structure_excerpt"] = "".join(all_structure_parts)[:4000]
        if research_log:
            result["research_log"] = research_log
        return result
    except Exception as e:
        logger.error("Transitive path analysis failed: %s", e)
        return {
            "reachable": "UNCERTAIN",
            "confidence": "Low",
            "intermediary": ", ".join(checked),
            "reasoning": f"Transitive analysis unavailable: {e}",
            "error": str(e),
            "usage_hits": total_hits,
            "intermediaries_checked": checked,
            "snippets": all_snippets[:6],
            "structure_excerpt": "".join(all_structure_parts)[:4000],
        }


def _parse_transitive_response(raw: str) -> Dict[str, Any]:
    """Parse the structured transitive-analysis LLM response."""
    reachable = "UNCERTAIN"
    confidence = "Low"
    intermediary = ""
    reasoning = ""
    current_field: str | None = None

    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        upper = stripped.upper()

        if upper.startswith("REACHABLE:"):
            val = stripped.split(":", 1)[1].strip().upper()
            if val in ("YES", "NO", "UNCERTAIN"):
                reachable = val
            current_field = None
        elif upper.startswith("CONFIDENCE:"):
            val = stripped.split(":", 1)[1].strip()
            for canon in ("High", "Medium", "Low"):
                if canon.upper() in val.upper():
                    confidence = canon
                    break
            current_field = None
        elif upper.startswith("INTERMEDIARY:"):
            intermediary = stripped.split(":", 1)[1].strip()
            current_field = None
        elif upper.startswith("REASONING:"):
            reasoning = stripped.split(":", 1)[1].strip()
            current_field = "reasoning"
        elif current_field == "reasoning":
            reasoning += " " + stripped

    if not reasoning:
        reasoning = raw.strip()

    return {
        "reachable": reachable,
        "confidence": confidence,
        "intermediary": intermediary,
        "reasoning": reasoning,
    }
