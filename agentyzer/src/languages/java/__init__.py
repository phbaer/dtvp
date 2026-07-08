"""Java language plugin — regex-based analysis."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

from src.agents.ast_analyzer import (
    _JAVA_IMPORT_RE,
    CallSite,
    ImportInfo,
    _scan_calls_by_name,
)
from src.languages.base import LanguagePlugin


class JavaPlugin(LanguagePlugin):
    @property
    def name(self) -> str:
        return "java"

    @property
    def ecosystem(self) -> str:
        return "Maven"

    @property
    def file_extensions(self) -> frozenset[str]:
        return frozenset({".java"})

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
            m = _JAVA_IMPORT_RE.search(line)
            if not m:
                continue
            full_import = m.group(1)
            if not any(v.lower() in full_import.lower() for v in variants):
                continue
            parts = full_import.rsplit(".", 1)
            if parts[-1] == "*":
                sym = "*"
                alias = parts[0].rsplit(".", 1)[-1] if "." in parts[0] else parts[0]
            else:
                sym = parts[-1]
                alias = None
            imports.append(
                ImportInfo(
                    file=rel_path,
                    line=lineno,
                    module=full_import,
                    symbols=[sym],
                    alias=alias,
                    kind="namespace" if sym == "*" else "named",
                )
            )
            if sym != "*":
                local_names[sym] = full_import

        calls = _scan_calls_by_name(lines, rel_path, local_names, known_symbols)
        return imports, calls

    # ------------------------------------------------------------------
    # Manifests
    # ------------------------------------------------------------------

    def manifest_filenames(self) -> list[str]:
        return ["pom.xml", "build.gradle", "build.gradle.kts", "libs.versions.toml"]

    def lockfile_filenames(self) -> list[str]:
        return [
            "gradle.lockfile",
            "compileClasspath.lockfile",
            "runtimeClasspath.lockfile",
            "testCompileClasspath.lockfile",
            "testRuntimeClasspath.lockfile",
            "annotationProcessor.lockfile",
            "testAnnotationProcessor.lockfile",
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
        if base in self.lockfile_filenames():
            for line in text.splitlines():
                locked = _parse_gradle_lock_line(line)
                if locked and _matches_java_component(
                    locked["group"],
                    locked["artifact"],
                    component_name,
                ):
                    return locked["version"]
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
        lf = filename.lower()
        versions: list[str] = []

        if lf.endswith("pom.xml"):
            versions.extend(_pom_versions(text, component_name))

        elif lf.endswith(("build.gradle", "build.gradle.kts")):
            versions.extend(_gradle_versions(text, component_name))

        elif lf.endswith("libs.versions.toml"):
            versions.extend(_version_catalog_versions(text, component_name))

        return _unique_nonempty(versions)

    def manifest_mentions_component(
        self,
        text: str,
        filename: str,
        component_name: str,
    ) -> bool:
        lf = filename.lower()
        if lf.endswith("pom.xml"):
            return _pom_mentions_component(text, component_name)
        if lf.endswith(("build.gradle", "build.gradle.kts")):
            return _gradle_mentions_component(text, component_name)
        if lf.endswith("libs.versions.toml"):
            return _version_catalog_mentions_component(text, component_name)
        return super().manifest_mentions_component(text, filename, component_name)

    def lockfile_mentions_component(
        self,
        text: str,
        filename: str,
        component_name: str,
    ) -> bool:
        base = filename.rsplit("/", 1)[-1] if "/" in filename else filename
        if base in self.lockfile_filenames():
            return self.extract_locked_version(text, component_name, filename) is not None
        return super().lockfile_mentions_component(text, filename, component_name)


def _unique_nonempty(values: list[str | None]) -> list[str]:
    result: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in result:
            result.append(text)
    return result


def _strip_xml_namespaces(root: ET.Element) -> ET.Element:
    for elem in root.iter():
        if "}" in elem.tag:
            elem.tag = elem.tag.rsplit("}", 1)[1]
    return root


def _child_text(elem: ET.Element, name: str) -> str:
    child = elem.find(name)
    return (child.text or "").strip() if child is not None else ""


def _matches_java_component(group: str, artifact: str, component_name: str) -> bool:
    component = (component_name or "").strip().lower()
    if not component:
        return False
    group_l = (group or "").strip().lower()
    artifact_l = (artifact or "").strip().lower()
    ga = f"{group_l}:{artifact_l}" if group_l and artifact_l else artifact_l
    return component in {group_l, artifact_l, ga} or component in ga


def _collect_maven_properties(root: ET.Element) -> dict[str, str]:
    properties: dict[str, str] = {}
    for props in root.findall(".//properties"):
        for child in list(props):
            value = (child.text or "").strip()
            if child.tag and value:
                properties[child.tag] = value

    project_version = _child_text(root, "version")
    if not project_version:
        parent = root.find("parent")
        project_version = _child_text(parent, "version") if parent is not None else ""
    if project_version:
        properties.setdefault("project.version", project_version)
        properties.setdefault("pom.version", project_version)
    return properties


def _resolve_property(value: str, properties: dict[str, str]) -> str:
    text = (value or "").strip()
    if not text:
        return ""

    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        return properties.get(key, match.group(0))

    return re.sub(r"\$\{([^}]+)\}", replace, text).strip()


def _pom_dependencies(text: str) -> list[dict[str, str]]:
    try:
        root = _strip_xml_namespaces(ET.fromstring(text))
    except Exception:
        return []

    properties = _collect_maven_properties(root)
    dependencies: list[dict[str, str]] = []
    for dep in root.findall(".//dependency"):
        group = _resolve_property(_child_text(dep, "groupId"), properties)
        artifact = _resolve_property(_child_text(dep, "artifactId"), properties)
        version = _resolve_property(_child_text(dep, "version"), properties)
        if group or artifact:
            dependencies.append(
                {"group": group, "artifact": artifact, "version": version}
            )
    return dependencies


def _pom_mentions_component(text: str, component_name: str) -> bool:
    return any(
        _matches_java_component(dep["group"], dep["artifact"], component_name)
        for dep in _pom_dependencies(text)
    )


def _pom_versions(text: str, component_name: str) -> list[str]:
    return [
        dep["version"]
        for dep in _pom_dependencies(text)
        if dep["version"]
        and _matches_java_component(dep["group"], dep["artifact"], component_name)
    ]


def _gradle_properties(text: str) -> dict[str, str]:
    properties: dict[str, str] = {}
    patterns = (
        r"\b(?:def\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*['\"]([^'\"]+)['\"]",
        r"\bext\.([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*['\"]([^'\"]+)['\"]",
        r"\bset\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            properties[match.group(1)] = match.group(2)
    return properties


def _resolve_gradle_version(version: str, properties: dict[str, str]) -> str:
    value = (version or "").strip()
    if not value:
        return ""
    if value.startswith("$"):
        key = value[1:].strip("{}")
        return properties.get(key, value)

    def replace(match: re.Match[str]) -> str:
        key = match.group(1) or match.group(2)
        return properties.get(key, match.group(0))

    return re.sub(r"\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_.-]*)", replace, value)


def _parse_gradle_coordinate(coordinate: str) -> tuple[str, str, str] | None:
    parts = [part.strip() for part in coordinate.split(":")]
    if len(parts) < 3:
        return None
    return parts[0], parts[1], ":".join(parts[2:])


def _gradle_versions(text: str, component_name: str) -> list[str]:
    properties = _gradle_properties(text)
    versions: list[str] = []

    for match in re.finditer(
        r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation|"
        r"testRuntimeOnly|annotationProcessor|compile|runtime)"
        r"\s*(?:\(\s*)?['\"]([^'\"]+:[^'\"]+:[^'\"]+)['\"]",
        text,
    ):
        parsed = _parse_gradle_coordinate(match.group(1))
        if not parsed:
            continue
        group, artifact, version = parsed
        if _matches_java_component(group, artifact, component_name):
            versions.append(_resolve_gradle_version(version, properties))

    map_patterns = (
        r"group\s*:\s*['\"]([^'\"]+)['\"]\s*,\s*name\s*:\s*['\"]([^'\"]+)['\"]"
        r"\s*,\s*version\s*:\s*['\"]([^'\"]+)['\"]",
        r"group\s*=\s*['\"]([^'\"]+)['\"]\s*,\s*name\s*=\s*['\"]([^'\"]+)['\"]"
        r"\s*,\s*version\s*=\s*['\"]([^'\"]+)['\"]",
    )
    for pattern in map_patterns:
        for match in re.finditer(pattern, text):
            group, artifact, version = match.groups()
            if _matches_java_component(group, artifact, component_name):
                versions.append(_resolve_gradle_version(version, properties))

    return versions


def _gradle_mentions_component(text: str, component_name: str) -> bool:
    return bool(_gradle_versions(text, component_name)) or (
        component_name.lower() in text.lower()
    )


def _parse_gradle_lock_line(line: str) -> dict[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or stripped.startswith("empty="):
        return None
    coordinate = stripped.split("=", 1)[0].strip()
    parts = coordinate.split(":")
    if len(parts) < 3:
        return None
    return {"group": parts[0], "artifact": parts[1], "version": ":".join(parts[2:])}


def _parse_version_catalog(text: str) -> tuple[dict[str, str], list[dict[str, str]]]:
    try:
        import toml

        data = toml.loads(text)
    except Exception:
        data = {}
    versions = {
        key: str(value)
        for key, value in (data.get("versions") or {}).items()
        if isinstance(value, str)
    }
    libraries: list[dict[str, str]] = []
    for entry in (data.get("libraries") or {}).values():
        if isinstance(entry, str):
            parsed = _parse_gradle_coordinate(entry)
            if parsed:
                group, artifact, version = parsed
                libraries.append(
                    {"group": group, "artifact": artifact, "version": version}
                )
            continue
        if not isinstance(entry, dict):
            continue
        module = str(entry.get("module") or "")
        group = str(entry.get("group") or "")
        artifact = str(entry.get("name") or "")
        if module:
            parsed = module.split(":", 1)
            if len(parsed) == 2:
                group, artifact = parsed
        version = ""
        version_value = entry.get("version")
        if isinstance(version_value, str):
            version = version_value
        elif isinstance(version_value, dict):
            version = str(
                version_value.get("ref") and versions.get(version_value["ref"])
                or version_value.get("require")
                or version_value.get("strictly")
                or version_value.get("prefer")
                or ""
            )
        version_ref = entry.get("version.ref")
        if not version and isinstance(version_ref, str):
            version = versions.get(version_ref, "")
        if group or artifact:
            libraries.append(
                {"group": group, "artifact": artifact, "version": version}
            )
    return versions, libraries


def _version_catalog_versions(text: str, component_name: str) -> list[str]:
    versions, libraries = _parse_version_catalog(text)
    result = [
        lib["version"]
        for lib in libraries
        if lib["version"]
        and _matches_java_component(lib["group"], lib["artifact"], component_name)
    ]
    component_key = component_name.lower().replace(".", "-").replace(":", "-")
    for key, version in versions.items():
        if component_key in key.lower() or key.lower() in component_key:
            result.append(version)
    return result


def _version_catalog_mentions_component(text: str, component_name: str) -> bool:
    _, libraries = _parse_version_catalog(text)
    return any(
        _matches_java_component(lib["group"], lib["artifact"], component_name)
        for lib in libraries
    )


plugin = JavaPlugin()
