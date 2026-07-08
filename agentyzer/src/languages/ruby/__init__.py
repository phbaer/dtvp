"""Ruby language plugin."""

from __future__ import annotations

import re

from src.languages.base import LanguagePlugin


class RubyPlugin(LanguagePlugin):
    @property
    def name(self) -> str:
        return "ruby"

    @property
    def ecosystem(self) -> str:
        return "RubyGems"

    @property
    def file_extensions(self) -> frozenset[str]:
        return frozenset({".rb"})

    def manifest_filenames(self) -> list[str]:
        return ["Gemfile"]

    def lockfile_filenames(self) -> list[str]:
        return ["Gemfile.lock"]

    def extract_locked_version(
        self,
        text: str,
        component_name: str,
        filename: str,
    ) -> str | None:
        base = filename.rsplit("/", 1)[-1] if "/" in filename else filename
        if base == "Gemfile.lock":
            m = re.search(
                rf"{re.escape(component_name)}\s+\(([0-9][0-9a-zA-Z.*\-]*)\)",
                text,
            )
            return m.group(1) if m else None
        return None

    def parse_manifest_versions(
        self,
        text: str,
        filename: str,
        component_name: str,
    ) -> list[str]:
        versions: list[str] = []
        for line in text.splitlines():
            if component_name.lower() in line.lower():
                m = re.search(
                    rf"gem\s+['\"]?{component_name}['\"]?\s*,\s*['\"]([^'\"]+)['\"]",
                    line,
                    re.I,
                )
                if m:
                    versions.append(m.group(1))
        return versions


plugin = RubyPlugin()
