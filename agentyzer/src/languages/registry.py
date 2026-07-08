"""Plugin registry with auto-discovery.

At import time the registry scans ``src/languages/*/`` for modules that
export a ``plugin`` attribute conforming to :class:`LanguagePlugin`.
"""

from __future__ import annotations

import importlib
import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.languages.base import LanguagePlugin

logger = logging.getLogger(__name__)


class LanguageRegistry:
    """Central registry mapping extensions/ecosystems to language plugins."""

    def __init__(self) -> None:
        self._by_extension: dict[str, LanguagePlugin] = {}
        self._by_ecosystem: dict[str, LanguagePlugin] = {}
        self._plugins: list[LanguagePlugin] = []

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, plugin: LanguagePlugin) -> None:
        """Register a language plugin."""
        self._plugins.append(plugin)
        for ext in plugin.file_extensions:
            self._by_extension[ext] = plugin
        self._by_ecosystem[plugin.ecosystem.lower()] = plugin
        logger.debug(
            "Registered language plugin %s (ecosystem=%s, exts=%s)",
            plugin.name,
            plugin.ecosystem,
            plugin.file_extensions,
        )

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def for_file(self, path: str) -> LanguagePlugin | None:
        """Resolve a plugin by file extension."""
        ext = os.path.splitext(path)[1].lower()
        return self._by_extension.get(ext)

    def for_ecosystem(self, ecosystem: str) -> LanguagePlugin | None:
        """Resolve a plugin by ecosystem name (case-insensitive)."""
        return self._by_ecosystem.get(ecosystem.lower())

    def for_lockfile(self, filename: str) -> LanguagePlugin | None:
        """Resolve a plugin by lock file name."""
        base = os.path.basename(filename)
        for plugin in self._plugins:
            if base in plugin.lockfile_filenames():
                return plugin
        return None

    def for_manifest(self, filename: str) -> LanguagePlugin | None:
        """Resolve a plugin by manifest file name."""
        base = os.path.basename(filename)
        for plugin in self._plugins:
            if base in plugin.manifest_filenames():
                return plugin
        return None

    # ------------------------------------------------------------------
    # Aggregation
    # ------------------------------------------------------------------

    def all_manifest_filenames(self) -> set[str]:
        """Aggregate manifest filenames across all registered plugins."""
        result: set[str] = set()
        for plugin in self._plugins:
            result.update(plugin.manifest_filenames())
        return result

    def all_lockfile_filenames(self) -> set[str]:
        """Aggregate lock file names across all registered plugins."""
        result: set[str] = set()
        for plugin in self._plugins:
            result.update(plugin.lockfile_filenames())
        return result

    def all_plugins(self) -> list[LanguagePlugin]:
        """Return all registered plugins."""
        return list(self._plugins)

    def all_file_extensions(self) -> set[str]:
        """Aggregate source file extensions across all plugins."""
        result: set[str] = set()
        for plugin in self._plugins:
            result.update(plugin.file_extensions)
        return result

    # ------------------------------------------------------------------
    # Auto-discovery
    # ------------------------------------------------------------------

    def discover(self) -> None:
        """Scan ``src/languages/*/`` for plugin modules and register them."""
        pkg_dir = os.path.dirname(__file__)
        for entry in sorted(os.listdir(pkg_dir)):
            entry_path = os.path.join(pkg_dir, entry)
            if not os.path.isdir(entry_path):
                continue
            init_path = os.path.join(entry_path, "__init__.py")
            if not os.path.isfile(init_path):
                continue
            module_name = f"src.languages.{entry}"
            try:
                mod = importlib.import_module(module_name)
            except Exception:
                logger.debug("Skipping language module %s", module_name, exc_info=True)
                continue
            plugin = getattr(mod, "plugin", None)
            if plugin is not None:
                self.register(plugin)


# Module-level singleton — populated at import time.
registry = LanguageRegistry()
registry.discover()
