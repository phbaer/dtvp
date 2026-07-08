"""Go language plugin."""

from __future__ import annotations

import re

from src.languages.base import LanguagePlugin


class GoPlugin(LanguagePlugin):
    @property
    def name(self) -> str:
        return "go"

    @property
    def ecosystem(self) -> str:
        return "Go"

    @property
    def file_extensions(self) -> frozenset[str]:
        return frozenset({".go"})

    def manifest_filenames(self) -> list[str]:
        return ["go.mod"]

    def lockfile_filenames(self) -> list[str]:
        return ["go.sum"]

    def extract_locked_version(
        self,
        text: str,
        component_name: str,
        filename: str,
    ) -> str | None:
        base = filename.rsplit("/", 1)[-1] if "/" in filename else filename
        if base == "go.sum":
            m = re.search(
                rf"{re.escape(component_name)}\s+v([0-9][0-9a-zA-Z.*\-]*)",
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
            parts = line.strip().split()
            if len(parts) >= 2 and component_name.lower() in parts[0].lower():
                versions.append(parts[-1])
        return versions


plugin = GoPlugin()
