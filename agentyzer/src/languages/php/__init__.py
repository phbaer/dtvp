"""PHP (Composer) language plugin."""

from __future__ import annotations

import re

from src.languages.base import LanguagePlugin


class PhpPlugin(LanguagePlugin):
    @property
    def name(self) -> str:
        return "php"

    @property
    def ecosystem(self) -> str:
        return "Packagist"

    @property
    def file_extensions(self) -> frozenset[str]:
        return frozenset({".php"})

    def manifest_filenames(self) -> list[str]:
        return ["composer.json"]

    def lockfile_filenames(self) -> list[str]:
        return ["composer.lock"]

    def extract_locked_version(
        self,
        text: str,
        component_name: str,
        filename: str,
    ) -> str | None:
        base = filename.rsplit("/", 1)[-1] if "/" in filename else filename
        if base == "composer.lock":
            pattern = (
                rf'"name":\s*"{re.escape(component_name)}"'
                r'[\s\S]*?"version":\s*"v?([^"]+)"'
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
        import json

        versions: list[str] = []
        try:
            data = json.loads(text)
            for key in ("require", "require-dev"):
                deps = data.get(key, {})
                for dep_name, ver in deps.items():
                    if dep_name.lower() == component_name.lower():
                        versions.append(ver)
        except Exception:
            pass
        return versions


plugin = PhpPlugin()
