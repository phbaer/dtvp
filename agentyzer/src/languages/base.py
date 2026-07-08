"""Abstract base class for language plugins.

Each supported language/ecosystem implements this interface once.
The core pipeline delegates all language-specific work (AST parsing,
manifest/lockfile parsing, version extraction) to plugins via the
:class:`LanguageRegistry`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class Dependency:
    """A dependency declared in a manifest file."""

    name: str
    version_spec: str  # version specifier as written, e.g. ">=2.0,<3"


@dataclass
class LockedDependency:
    """A dependency with a pinned version from a lock file."""

    name: str
    version: str


class LanguagePlugin(ABC):
    """Interface that every language plugin must implement.

    Implement only the methods relevant to your language.  The default
    implementations return empty results so a minimal plugin only needs
    to declare its metadata and override what it supports.
    """

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable language name, e.g. ``"python"``."""

    @property
    @abstractmethod
    def ecosystem(self) -> str:
        """Package ecosystem identifier, e.g. ``"PyPI"``, ``"npm"``."""

    @property
    @abstractmethod
    def file_extensions(self) -> frozenset[str]:
        """Source file extensions handled by this plugin, e.g. ``{".py"}``."""

    # ------------------------------------------------------------------
    # AST / code analysis
    # ------------------------------------------------------------------

    def parse_imports(
        self,
        source: str,
        rel_path: str,
        variants: list[str],
        known_symbols: set[str],
    ) -> tuple[list[Any], list[Any]]:
        """Parse source for imports of the vulnerable component.

        Parameters
        ----------
        source
            Full file content.
        rel_path
            Relative path inside the repository.
        variants
            Component name variants to search for.
        known_symbols
            Symbols already identified from the advisory.

        Returns
        -------
        tuple[list[ImportInfo], list[CallSite]]
            Imports and call sites found.
        """
        return [], []

    # ------------------------------------------------------------------
    # Dependency manifests and lock files
    # ------------------------------------------------------------------

    @abstractmethod
    def manifest_filenames(self) -> list[str]:
        """Return filenames this plugin recognises as dependency manifests."""

    @abstractmethod
    def lockfile_filenames(self) -> list[str]:
        """Return filenames this plugin recognises as lock files."""

    def extract_locked_version(
        self,
        text: str,
        component_name: str,
        filename: str,
    ) -> str | None:
        """Extract the pinned version of *component_name* from a lock file.

        Returns ``None`` if the component is not found or the format is
        not supported.
        """
        return None

    def parse_manifest_versions(
        self,
        text: str,
        filename: str,
        component_name: str,
    ) -> list[str]:
        """Extract version specifiers for *component_name* from a manifest.

        Returns a (possibly empty) list of version strings or specifiers.
        """
        return []

    def manifest_mentions_component(
        self,
        text: str,
        filename: str,
        component_name: str,
    ) -> bool:
        """Return whether a manifest mentions *component_name*.

        Plugins can override this when a manifest stores package identity
        across multiple fields, such as Maven ``groupId`` + ``artifactId``.
        """
        return component_name.lower() in text.lower()

    def lockfile_mentions_component(
        self,
        text: str,
        filename: str,
        component_name: str,
    ) -> bool:
        """Return whether a lock file mentions *component_name*."""
        return (
            component_name.lower() in text.lower()
            or self.extract_locked_version(text, component_name, filename) is not None
        )
