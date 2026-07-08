"""Tests for the AST-based code analyzer."""

import os
import tempfile
import textwrap

from src.agents.ast_analyzer import (
    SymbolGraph,
    _component_variants,
    analyze_repository,
    format_for_llm,
    infer_symbols_from_cwe,
)


def _make_repo(files: dict[str, str]) -> str:
    """Create a temporary repo with the given file contents."""
    tmp = tempfile.mkdtemp()
    for name, content in files.items():
        fpath = os.path.join(tmp, name)
        os.makedirs(os.path.dirname(fpath), exist_ok=True)
        with open(fpath, "w") as f:
            f.write(textwrap.dedent(content))
    return tmp


# ------------------------------------------------------------------ #
# Component variant generation
# ------------------------------------------------------------------ #


def test_component_variants_basic():
    v = _component_variants("path-to-regexp")
    assert "path-to-regexp" in v
    assert "path_to_regexp" in v
    assert "pathToRegexp" in v
    assert "PathToRegexp" in v
    assert "pathtoregexp" in v


def test_component_variants_scoped():
    v = _component_variants("@types/path-to-regexp")
    assert "path-to-regexp" in v
    assert "path_to_regexp" in v
    assert "@types/path-to-regexp" in v


def test_component_variants_simple():
    v = _component_variants("express")
    assert "express" in v


# ------------------------------------------------------------------ #
# CWE-based heuristics
# ------------------------------------------------------------------ #


def test_cwe_redos():
    patterns = infer_symbols_from_cwe(["CWE-1333"])
    assert "regex" in patterns
    assert "compile" in patterns
    assert "match" in patterns


def test_cwe_sqli():
    patterns = infer_symbols_from_cwe(["CWE-89"])
    assert "query" in patterns
    assert "execute" in patterns


def test_cwe_unknown():
    patterns = infer_symbols_from_cwe(["CWE-99999"])
    assert patterns == []


def test_cwe_multiple():
    patterns = infer_symbols_from_cwe(["CWE-1333", "CWE-20"])
    assert "regex" in patterns
    assert "parse" in patterns
    # No duplicates
    assert len(patterns) == len(set(patterns))


# ------------------------------------------------------------------ #
# Python AST analysis
# ------------------------------------------------------------------ #


def test_python_import_from():
    repo = _make_repo(
        {
            "app.py": """\
            from path_to_regexp import compile, match

            def handler():
                pattern = compile("/user/:id")
                return match(pattern, "/user/42")
        """,
        }
    )
    graph = analyze_repository(repo, "path-to-regexp")
    assert len(graph.imports) == 1
    imp = graph.imports[0]
    assert imp.module == "path_to_regexp"
    assert "compile" in imp.symbols
    assert "match" in imp.symbols
    assert "compile" in graph.resolved_symbols
    assert "match" in graph.resolved_symbols
    # Call sites
    assert len(graph.calls) >= 2
    call_syms = [c.symbol for c in graph.calls]
    assert "compile" in call_syms
    assert "match" in call_syms
    # Enclosing scope
    handler_calls = [c for c in graph.calls if c.enclosing == "def handler"]
    assert len(handler_calls) >= 2


def test_python_import_namespace():
    repo = _make_repo(
        {
            "app.py": """\
            import path_to_regexp as ptr

            result = ptr.compile("/api/:version")
        """,
        }
    )
    graph = analyze_repository(repo, "path-to-regexp")
    assert len(graph.imports) == 1
    assert graph.imports[0].alias == "ptr"
    assert graph.imports[0].kind == "namespace"
    # Should find ptr.compile call
    assert any("ptr" in c.symbol or "compile" in c.symbol for c in graph.calls)


def test_python_no_match():
    repo = _make_repo(
        {
            "app.py": """\
            import json
            data = json.loads('{}')
        """,
        }
    )
    graph = analyze_repository(repo, "path-to-regexp")
    assert len(graph.imports) == 0
    assert len(graph.calls) == 0
    assert len(graph.resolved_symbols) == 0


# ------------------------------------------------------------------ #
# JavaScript / TypeScript analysis
# ------------------------------------------------------------------ #


def test_js_es6_named_import():
    repo = _make_repo(
        {
            "app.js": """\
            import { pathToRegexp, compile } from 'path-to-regexp';

            const re = pathToRegexp('/user/:id');
            const toPath = compile('/user/:id');
        """,
        }
    )
    graph = analyze_repository(repo, "path-to-regexp")
    assert len(graph.imports) == 1
    assert "pathToRegexp" in graph.imports[0].symbols
    assert "compile" in graph.imports[0].symbols
    assert "pathToRegexp" in graph.resolved_symbols
    assert len(graph.calls) >= 2


def test_js_default_import():
    repo = _make_repo(
        {
            "app.js": """\
            import pathToRegexp from 'path-to-regexp';

            const re = pathToRegexp('/user/:id');
        """,
        }
    )
    graph = analyze_repository(repo, "path-to-regexp")
    assert len(graph.imports) == 1
    assert graph.imports[0].alias == "pathToRegexp"
    assert len(graph.calls) >= 1


def test_js_require():
    repo = _make_repo(
        {
            "app.js": """\
            const { pathToRegexp, compile } = require('path-to-regexp');

            const re = pathToRegexp('/api/:version');
        """,
        }
    )
    graph = analyze_repository(repo, "path-to-regexp")
    assert len(graph.imports) == 1
    assert "pathToRegexp" in graph.imports[0].symbols
    assert len(graph.calls) >= 1


def test_js_require_namespace():
    repo = _make_repo(
        {
            "app.js": """\
            const ptr = require('path-to-regexp');

            const re = ptr.pathToRegexp('/foo');
        """,
        }
    )
    graph = analyze_repository(repo, "path-to-regexp")
    assert len(graph.imports) == 1
    assert graph.imports[0].alias == "ptr"
    assert len(graph.calls) >= 1


def test_ts_type_import():
    repo = _make_repo(
        {
            "app.ts": """\
            import type { Key } from 'path-to-regexp';
            import { pathToRegexp } from 'path-to-regexp';

            const keys: Key[] = [];
            const re = pathToRegexp('/user/:id', keys);
        """,
        }
    )
    graph = analyze_repository(repo, "path-to-regexp")
    # Should have 2 imports, one type-only
    assert len(graph.imports) == 2
    type_imports = [i for i in graph.imports if i.is_type_only]
    assert len(type_imports) == 1
    assert "Key" in type_imports[0].symbols


# ------------------------------------------------------------------ #
# Java analysis
# ------------------------------------------------------------------ #


def test_java_import():
    repo = _make_repo(
        {
            "App.java": """\
            import com.example.pathtoregexp.PathCompiler;

            public class App {
                public void handle() {
                    PathCompiler compiler = new PathCompiler("/api/:id");
                    compiler.compile();
                }
            }
        """,
        }
    )
    graph = analyze_repository(repo, "path-to-regexp")
    assert len(graph.imports) == 1
    assert "PathCompiler" in graph.imports[0].symbols
    assert any("PathCompiler" in c.symbol for c in graph.calls)


def test_java_wildcard_import():
    repo = _make_repo(
        {
            "App.java": """\
            import com.example.pathtoregexp.*;

            public class App {
                public void run() {
                    Pattern p = Pattern.compile(".*");
                }
            }
        """,
        }
    )
    graph = analyze_repository(repo, "path-to-regexp")
    assert len(graph.imports) == 1
    assert "*" in graph.imports[0].symbols


# ------------------------------------------------------------------ #
# C/C++ analysis
# ------------------------------------------------------------------ #


def test_c_include():
    repo = _make_repo(
        {
            "main.c": """\
            #include <pathtoregexp/regex.h>
            #include <stdio.h>

            int main() {
                ptr_compile("/user/:id");
                return 0;
            }
        """,
        }
    )
    graph = analyze_repository(repo, "path-to-regexp")
    assert len(graph.imports) == 1
    assert "pathtoregexp/regex.h" in graph.imports[0].module


# ------------------------------------------------------------------ #
# Multi-file and cross-language
# ------------------------------------------------------------------ #


def test_multi_file():
    repo = _make_repo(
        {
            "src/routes.py": """\
            from path_to_regexp import compile

            def build_route(pattern):
                return compile(pattern)
        """,
            "src/app.py": """\
            from path_to_regexp import match

            def check(path):
                return match("/api/:v", path)
        """,
            "src/unrelated.py": """\
            import json
            data = json.loads('{}')
        """,
        }
    )
    graph = analyze_repository(repo, "path-to-regexp")
    assert len(graph.imports) == 2
    import_files = {i.file for i in graph.imports}
    assert any("routes.py" in f for f in import_files)
    assert any("app.py" in f for f in import_files)
    assert "compile" in graph.resolved_symbols
    assert "match" in graph.resolved_symbols


# ------------------------------------------------------------------ #
# format_for_llm
# ------------------------------------------------------------------ #


def test_format_for_llm_empty():
    assert format_for_llm(SymbolGraph()) == ""


def test_format_for_llm_with_data():
    repo = _make_repo(
        {
            "app.py": """\
            from path_to_regexp import compile

            compile("/user/:id")
        """,
        }
    )
    graph = analyze_repository(repo, "path-to-regexp")
    text = format_for_llm(graph)
    assert "IMPORT ANALYSIS" in text
    assert "CALL SITES" in text
    assert "DISCOVERED SYMBOLS" in text
    assert "compile" in text


# ------------------------------------------------------------------ #
# Skipping node_modules and similar directories
# ------------------------------------------------------------------ #


def test_skip_node_modules():
    repo = _make_repo(
        {
            "node_modules/path-to-regexp/index.js": """\
            export function pathToRegexp() {}
        """,
            "src/app.js": """\
            import { pathToRegexp } from 'path-to-regexp';
            pathToRegexp('/test');
        """,
        }
    )
    graph = analyze_repository(repo, "path-to-regexp")
    # Only the src/app.js file should be analyzed, not node_modules.
    import_files = {i.file for i in graph.imports}
    assert all("node_modules" not in f for f in import_files)
    assert len(graph.imports) == 1
