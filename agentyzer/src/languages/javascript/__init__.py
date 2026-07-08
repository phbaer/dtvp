"""JavaScript / TypeScript language plugin — regex-based analysis."""

from __future__ import annotations

import re
from typing import Any

from src.agents.ast_analyzer import (
    _JS_FROM_RE,
    _JS_REQUIRE_RE,
    _JS_SIDE_EFFECT_RE,
    CallSite,
    ImportInfo,
    _parse_js_bindings,
    _parse_require_bindings,
    _scan_calls_by_name,
)
from src.languages.base import LanguagePlugin


class JavaScriptPlugin(LanguagePlugin):
    @property
    def name(self) -> str:
        return "javascript"

    @property
    def ecosystem(self) -> str:
        return "npm"

    @property
    def file_extensions(self) -> frozenset[str]:
        return frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"})

    # ------------------------------------------------------------------
    # AST analysis (regex-based)
    # ------------------------------------------------------------------

    def parse_imports(
        self,
        source: str,
        rel_path: str,
        variants: list[str],
        known_symbols: set[str],
    ) -> tuple[list[Any], list[Any]]:
        imports: list[ImportInfo] = []
        local_names: dict[str, str] = {}
        is_typescript = rel_path.endswith((".ts", ".tsx"))

        lines = source.splitlines()

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()

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

        calls = _scan_calls_by_name(lines, rel_path, local_names, known_symbols)
        return imports, calls

    # ------------------------------------------------------------------
    # Manifests
    # ------------------------------------------------------------------

    def manifest_filenames(self) -> list[str]:
        return ["package.json"]

    def lockfile_filenames(self) -> list[str]:
        return [
            "package-lock.json",
            "npm-shrinkwrap.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "bun.lock",
        ]

    # ------------------------------------------------------------------
    # Lock file version extraction
    # ------------------------------------------------------------------

    def extract_locked_version(
        self,
        text: str,
        component_name: str,
        filename: str,
    ) -> str | None:
        base = filename.rsplit("/", 1)[-1] if "/" in filename else filename

        if base in ("package-lock.json", "npm-shrinkwrap.json"):
            pattern = rf'"(?:node_modules/)?{re.escape(component_name)}":\s*\{{\s*"version":\s*"([^"]+)"'
            m = re.search(pattern, text)
            return m.group(1) if m else None

        if base == "pnpm-lock.yaml":
            pattern = rf'"{re.escape(component_name)}":\s*\{{\s*"version":\s*"([^"]+)"'
            m = re.search(pattern, text)
            return m.group(1) if m else None

        if base == "bun.lock":
            patterns = (
                rf'"{re.escape(component_name)}"\s*:\s*\[\s*"{re.escape(component_name)}@([^"\s]+)"',
                rf"\b{re.escape(component_name)}@([0-9][0-9a-zA-Z.*\-+]*)\b",
            )
            for pattern in patterns:
                m = re.search(pattern, text, re.IGNORECASE)
                if m:
                    return m.group(1)
            return None

        if base == "yarn.lock":
            pattern = rf'{re.escape(component_name)}@[^\n]*\n\s+version\s+"([^"]+)"'
            m = re.search(pattern, text)
            return m.group(1) if m else None

        return None

    # ------------------------------------------------------------------
    # Manifest version extraction
    # ------------------------------------------------------------------

    def parse_manifest_versions(
        self,
        text: str,
        filename: str,
        component_name: str,
    ) -> list[str]:
        import json

        versions: list[str] = []
        try:
            data = json.loads(text)
            deps: dict[str, str] = {}
            for key in (
                "dependencies",
                "devDependencies",
                "peerDependencies",
                "optionalDependencies",
            ):
                deps.update(data.get(key, {}))
            for dep_name, ver in deps.items():
                if dep_name.lower() == component_name.lower():
                    versions.append(ver.strip())
        except Exception:
            pass
        return versions


plugin = JavaScriptPlugin()
