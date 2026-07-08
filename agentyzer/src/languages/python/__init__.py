"""Python language plugin — full AST-based analysis."""

from __future__ import annotations

import ast
import re
from typing import Any

from src.agents.ast_analyzer import CallSite, ImportInfo, _PythonVisitor
from src.languages.base import LanguagePlugin


class PythonPlugin(LanguagePlugin):
    @property
    def name(self) -> str:
        return "python"

    @property
    def ecosystem(self) -> str:
        return "PyPI"

    @property
    def file_extensions(self) -> frozenset[str]:
        return frozenset({".py"})

    # ------------------------------------------------------------------
    # AST analysis
    # ------------------------------------------------------------------

    def parse_imports(
        self,
        source: str,
        rel_path: str,
        variants: list[str],
        known_symbols: set[str],
    ) -> tuple[list[Any], list[Any]]:
        try:
            tree = ast.parse(source, filename=rel_path)
        except SyntaxError:
            return [], []

        visitor = _PythonVisitor(variants, source.splitlines(), set(known_symbols))
        visitor.visit(tree)

        for imp in visitor.imports:
            imp.file = rel_path
        for cs in visitor.calls:
            cs.file = rel_path
        return visitor.imports, visitor.calls

    # ------------------------------------------------------------------
    # Manifests
    # ------------------------------------------------------------------

    def manifest_filenames(self) -> list[str]:
        return [
            "requirements.txt",
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "Pipfile",
        ]

    def lockfile_filenames(self) -> list[str]:
        return [
            "requirements.lock",
            "Pipfile.lock",
            "poetry.lock",
            "uv.lock",
            "pylock.toml",
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

        if base == "uv.lock":
            pattern = (
                rf'name\s*=\s*"{re.escape(component_name)}"'
                r'\s+version\s*=\s*"([^"]+)"'
            )
            m = re.search(pattern, text, re.IGNORECASE)
            return m.group(1) if m else None

        if base == "requirements.lock":
            m = re.search(
                rf"{re.escape(component_name)}[=<>~!]=*\s*([0-9][0-9a-zA-Z.*\-]*)",
                text,
            )
            return m.group(1) if m else None

        if base == "Pipfile.lock":
            pattern = rf'"{re.escape(component_name)}"\s*:\s*\{{[\s\S]*?"version"\s*:\s*"=?=?([^"\s]+)"'
            m = re.search(pattern, text, re.IGNORECASE)
            return m.group(1).lstrip("=") if m else None

        if base == "poetry.lock":
            pattern = (
                rf'name\s*=\s*"{re.escape(component_name)}"'
                r'[\s\S]*?version\s*=\s*"([^"]+)"'
            )
            m = re.search(pattern, text)
            return m.group(1) if m else None

        if base == "pylock.toml":
            pattern = (
                rf'name\s*=\s*"{re.escape(component_name)}"'
                r'[\s\S]*?version\s*=\s*"([^"]+)"'
            )
            m = re.search(pattern, text, re.IGNORECASE)
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
        base = filename.rsplit("/", 1)[-1] if "/" in filename else filename
        lf = base.lower()
        versions: list[str] = []

        if lf == "pyproject.toml":
            try:
                import toml

                data = toml.loads(text)
            except Exception:
                data = {}

            for line in text.splitlines():
                if component_name.lower() in line.lower():
                    m = re.search(
                        rf"{component_name}\s*==\s*([0-9a-zA-Z.\-_]+)", line, re.I
                    )
                    if m:
                        versions.append(m.group(1))

            proj = data.get("project", {})
            if isinstance(proj, dict):
                deps = proj.get("dependencies", {})
                if isinstance(deps, list):
                    for entry in deps:
                        if (
                            isinstance(entry, str)
                            and component_name.lower() in entry.lower()
                        ):
                            parts = entry.split()
                            if len(parts) > 1:
                                versions.append(parts[-1])
                            else:
                                m = re.search(
                                    r"[><=~!]+\s*([0-9][0-9a-zA-Z.\-_]*)",
                                    entry,
                                )
                                if m:
                                    versions.append(m.group(1))
                elif isinstance(deps, dict):
                    for dep_name, ver in deps.items():
                        if dep_name.lower() == component_name.lower():
                            versions.append(ver if isinstance(ver, str) else "")

            poetry = data.get("tool", {}).get("poetry", {})
            if poetry:
                deps = poetry.get("dependencies", {})
                for dep_name, ver in deps.items():
                    if dep_name.lower() == component_name.lower():
                        versions.append(ver if isinstance(ver, str) else "")

        elif lf in ("requirements.txt", "setup.py", "setup.cfg", "pipfile"):
            for line in text.splitlines():
                if component_name.lower() in line.lower():
                    m = re.search(
                        rf"{component_name}\s*==\s*([0-9a-zA-Z.\-_]+)", line, re.I
                    )
                    if m:
                        versions.append(m.group(1))
                        continue
                    m = re.search(
                        rf"{component_name}[^\n]*?([0-9]+\.[0-9a-zA-Z.\-_]+)",
                        line,
                        re.I,
                    )
                    if m:
                        versions.append(m.group(1))

        return versions


plugin = PythonPlugin()
