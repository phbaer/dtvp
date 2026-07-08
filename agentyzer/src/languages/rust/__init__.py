"""Rust language plugin."""

from __future__ import annotations

import re

from src.languages.base import LanguagePlugin


class RustPlugin(LanguagePlugin):
    @property
    def name(self) -> str:
        return "rust"

    @property
    def ecosystem(self) -> str:
        return "crates.io"

    @property
    def file_extensions(self) -> frozenset[str]:
        return frozenset({".rs"})

    def manifest_filenames(self) -> list[str]:
        return ["Cargo.toml"]

    def lockfile_filenames(self) -> list[str]:
        return ["Cargo.lock"]

    def extract_locked_version(
        self,
        text: str,
        component_name: str,
        filename: str,
    ) -> str | None:
        base = filename.rsplit("/", 1)[-1] if "/" in filename else filename
        if base == "Cargo.lock":
            pattern = (
                rf'name\s*=\s*"{re.escape(component_name)}"'
                r'\s+version\s*=\s*"([^"]+)"'
            )
            m = re.search(pattern, text)
            return m.group(1) if m else None
        return None

    def parse_manifest_versions(
        self,
        text: str,
        filename: str,
        component_name: str,
    ) -> list[str]:
        versions: list[str] = []
        try:
            import toml

            data = toml.loads(text)
            deps = data.get("dependencies", {})
            for dep_name, ver in deps.items():
                if dep_name.lower() == component_name.lower():
                    if isinstance(ver, str):
                        versions.append(ver)
                    elif isinstance(ver, dict) and "version" in ver:
                        versions.append(ver["version"])
        except Exception:
            pass
        return versions


plugin = RustPlugin()
