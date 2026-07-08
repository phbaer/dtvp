"""C/C++ language plugin — regex-based analysis."""

from __future__ import annotations

import re
from typing import Any

from src.agents.ast_analyzer import (
    _C_INCLUDE_RE,
    CallSite,
    ImportInfo,
    _scan_calls_by_name,
)
from src.languages.base import LanguagePlugin


class CppPlugin(LanguagePlugin):
    @property
    def name(self) -> str:
        return "cpp"

    @property
    def ecosystem(self) -> str:
        return "C/C++"

    @property
    def file_extensions(self) -> frozenset[str]:
        return frozenset({".c", ".h", ".cpp", ".cxx", ".cc", ".hpp", ".hxx", ".hh"})

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

        lines = source.splitlines()
        for lineno, line in enumerate(lines, 1):
            m = _C_INCLUDE_RE.search(line)
            if not m:
                continue
            header = m.group(1)
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

        calls = _scan_calls_by_name(lines, rel_path, local_names, known_symbols)
        return imports, calls

    # ------------------------------------------------------------------
    # Manifests
    # ------------------------------------------------------------------

    def manifest_filenames(self) -> list[str]:
        return [
            "conanfile.txt",
            "conanfile.py",
            "vcpkg.json",
            "CMakeLists.txt",
        ]

    def lockfile_filenames(self) -> list[str]:
        return ["conan.lock"]

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
        if base == "conan.lock":
            m = re.search(
                rf"{re.escape(component_name)}/([0-9][0-9a-zA-Z.*\-+_]+)",
                text,
                re.IGNORECASE,
            )
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

        lf = filename.lower()
        versions: list[str] = []

        if lf.endswith("vcpkg.json"):
            try:
                data = json.loads(text)
                for dep in data.get("dependencies", []):
                    dep_name = dep if isinstance(dep, str) else dep.get("name", "")
                    ver = (
                        None
                        if isinstance(dep, str)
                        else dep.get("version>=", dep.get("version", ""))
                    )
                    if dep_name.lower() == component_name.lower() and ver:
                        versions.append(ver)
                for ov in data.get("overrides", []):
                    if (
                        isinstance(ov, dict)
                        and ov.get("name", "").lower() == component_name.lower()
                    ):
                        ver = ov.get("version")
                        if ver:
                            versions.append(ver)
            except Exception:
                pass

        elif lf.endswith("conanfile.txt"):
            in_requires = False
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("["):
                    in_requires = stripped.lower() == "[requires]"
                    continue
                if in_requires and component_name.lower() in stripped.lower():
                    m = re.search(r"/([0-9][0-9a-zA-Z.\-_]*)", stripped)
                    if m:
                        versions.append(m.group(1))

        elif lf.endswith("conanfile.py"):
            for line in text.splitlines():
                if component_name.lower() in line.lower():
                    m = re.search(
                        rf"{component_name}/([0-9][0-9a-zA-Z.\-_]*)",
                        line,
                        re.I,
                    )
                    if m:
                        versions.append(m.group(1))

        elif lf.endswith("cmakelists.txt"):
            for line in text.splitlines():
                if component_name.lower() in line.lower():
                    m = re.search(
                        rf"find_package\s*\(\s*{component_name}\s+([0-9][0-9a-zA-Z.\-_]*)",
                        line,
                        re.I,
                    )
                    if m:
                        versions.append(m.group(1))
                        continue
                    m = re.search(
                        r"GIT_TAG\s+[v]?([0-9][0-9a-zA-Z.\-_]*)",
                        line,
                        re.I,
                    )
                    if m:
                        versions.append(m.group(1))
                        continue
                    m = re.search(
                        r"VERSION\s+([0-9][0-9a-zA-Z.\-_]*)",
                        line,
                        re.I,
                    )
                    if m:
                        versions.append(m.group(1))

        return versions


plugin = CppPlugin()
