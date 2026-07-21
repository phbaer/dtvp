import json
import logging
import math
import os
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from .authorization import resolve_user_role, validate_user_roles_config
from .assessment_restore_services import (
    build_missing_rescoring_vector_restore_candidate,
    refresh_group_restore_metadata,
)
from .team_mapping import compile_team_mapping, get_team_mapping_tags

logger = logging.getLogger(__name__)

# Pre-compile regex patterns
RE_SCORE = re.compile(r"\[Rescored:\s*([\d\.]+)\]")
RE_VECTOR = re.compile(r"\[Rescored Vector:\s*([^\]]+)\]")
RE_ANY_VECTOR = re.compile(r"\b(CVSS:\d\.\d/\S+|AV:[NLA]/\S+)")

DEFAULT_DEPENDENCY_CHAIN_LIMIT = 100

# Base metric keys by CVSS major version. Everything else (temporal,
# environmental, supplemental, and modified-base metrics) is considered a
# rescoring addition.
_CVSS_BASE_METRIC_KEYS = {
    "2": frozenset({"AV", "AC", "Au", "C", "I", "A"}),
    "3": frozenset({"AV", "AC", "PR", "UI", "S", "C", "I", "A"}),
    "4": frozenset(
        {"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}
    ),
}


def _metric_key(token: str) -> str:
    """Extract the metric key from a CVSS token like ``AV:N`` → ``AV``."""
    return token.split(":")[0]


def _cvss_vector_major_version(vector: str) -> Optional[str]:
    normalized = vector.strip().lstrip("(")
    if normalized.startswith("CVSS:4."):
        return "4"
    if normalized.startswith("CVSS:3."):
        return "3"
    if normalized.startswith("CVSS:2.") or normalized.startswith("AV:"):
        return "2"
    return None


def _cvss_vector_parts(vector: str) -> tuple[list[str], int]:
    parts = vector.strip().replace("(", "").replace(")", "").split("/")
    metric_start = 1 if parts and parts[0].startswith("CVSS:") else 0
    return parts, metric_start


def sanitize_rescored_vector(
    original_vector: Optional[str], rescored_vector: Optional[str]
) -> Optional[str]:
    """Ensure a rescored CVSS vector preserves all base metric components from
    the original vector, only adding non-base tokens (temporal, environmental,
    modified-base).

    If the rescored vector already has the correct base, it is returned as-is.
    Otherwise the base components are taken from ``original_vector`` and only
    the non-base tokens from ``rescored_vector`` are appended.

    The original vector's CVSS version and version-specific base metrics are
    retained. Cross-version vectors are returned unchanged so the caller can
    expose them for manual review. Returns ``None`` when correction removes all
    meaningful rescoring additions.
    """
    if not original_vector or not rescored_vector:
        return rescored_vector or None

    original_version = _cvss_vector_major_version(original_vector)
    rescored_version = _cvss_vector_major_version(rescored_vector)
    if (
        original_version is None
        or rescored_version is None
        or original_version != rescored_version
    ):
        # Cross-version vectors cannot safely share base components. Keep the
        # submitted vector intact so the existing mismatch indicator can route
        # it to manual review.
        return rescored_vector

    base_metric_keys = _CVSS_BASE_METRIC_KEYS[original_version]
    orig_parts, orig_start = _cvss_vector_parts(original_vector)
    rescored_parts, rescored_start = _cvss_vector_parts(rescored_vector)

    orig_base = {
        p for p in orig_parts[orig_start:] if _metric_key(p) in base_metric_keys
    }
    rescored_base = {
        p
        for p in rescored_parts[rescored_start:]
        if _metric_key(p) in base_metric_keys
    }

    original_prefix = orig_parts[:orig_start]
    rescored_prefix = rescored_parts[:rescored_start]
    if orig_base == rescored_base and original_prefix == rescored_prefix:
        # Base metrics and the precise CVSS version already match.
        return rescored_vector

    # Reconstruct using the original vector version and base metrics plus only
    # the non-base tokens from the rescored vector.
    original_base = [
        p for p in orig_parts[orig_start:] if _metric_key(p) in base_metric_keys
    ]
    non_base = [
        p
        for p in rescored_parts[rescored_start:]
        if _metric_key(p) not in base_metric_keys
    ]
    corrected = "/".join(original_prefix + original_base + non_base)
    normalized_original = "/".join(original_prefix + original_base)

    if corrected == normalized_original:
        return None  # No meaningful change after correction

    logger.debug(
        "Corrected rescored vector (base metrics were altered): %s -> %s",
        rescored_vector,
        corrected,
    )
    return corrected


def get_team_mapping_path() -> str:
    return os.getenv("TEAM_MAPPING_PATH", "data/team_mapping.json")


def get_auto_analysis_guidance_path() -> str:
    return os.getenv(
        "DTVP_AUTO_ANALYSIS_GUIDANCE_PATH",
        "data/auto_analysis_guidance.json",
    )


STATE_PRIORITY = {
    "EXPLOITABLE": 0,
    "IN_TRIAGE": 1,
    "FALSE_POSITIVE": 2,
    "NOT_AFFECTED": 3,
    "RESOLVED": 4,
    "NOT_SET": 5,
}


def load_team_mapping(path: str = None) -> Dict[str, str]:
    if path is None:
        path = get_team_mapping_path()

    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"Failed to load team mapping from {path}: {e}")
        return {}


def load_auto_analysis_guidance(path: str = None) -> Dict[str, Any]:
    if path is None:
        path = get_auto_analysis_guidance_path()

    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            payload = json.load(f)
            return payload if isinstance(payload, dict) else {}
    except Exception as e:
        logger.warning(f"Failed to load auto-analysis guidance from {path}: {e}")
        return {}


def get_user_roles_path() -> str:
    return os.getenv("USER_ROLES_PATH", "data/user_roles.json")


def score_to_severity(score: float) -> str:
    """Maps CVSS score to DT severity bands."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


def load_user_roles(path: str = None) -> Dict[str, str]:
    if path is None:
        path = get_user_roles_path()

    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            return validate_user_roles_config(json.load(f))
    except Exception as e:
        logger.warning(f"Failed to load user roles from {path}: {e}")
        return {}


def get_rescore_rules_path() -> str:
    return os.getenv("RESCORE_RULES_PATH", "data/rescore_rules.json")


def load_rescore_rules(path: str = None) -> Optional[Dict[str, Any]]:
    if path is None:
        path = get_rescore_rules_path()

    if not os.path.exists(path):
        return None
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"Failed to load rescore rules from {path}: {e}")
        return None


def get_user_role(username: str, roles_map: Dict[str, str] = None) -> str:
    """
    Returns 'REVIEWER' or 'ANALYST'.
    Missing, unreadable, invalid, and incomplete role mappings fail closed to
    ANALYST. Only an explicit REVIEWER assignment grants reviewer privileges.
    """
    if roles_map is None:
        roles_map = load_user_roles()
    return resolve_user_role(username, roles_map).value


def build_parent_map(bom: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Builds a map of child_ref -> list of parent_refs from BOM.
    """
    parent_map = {}
    if not bom or "dependencies" not in bom:
        return {}

    for dep in bom["dependencies"]:
        parent_ref = dep.get("ref")
        for child_ref in dep.get("dependsOn", []):
            if child_ref not in parent_map:
                parent_map[child_ref] = []
            parent_map[child_ref].append(parent_ref)

    return parent_map


class DisjointSet:
    def __init__(self):
        self.parent = {}

    def find(self, item):
        if item not in self.parent:
            self.parent[item] = item
            return item
        if self.parent[item] != item:
            self.parent[item] = self.find(self.parent[item])
        return self.parent[item]

    def union(self, item1, item2):
        root1 = self.find(item1)
        root2 = self.find(item2)
        if root1 != root2:
            self.parent[root1] = root2


class BOMAnalysisCache:
    """
    Caches analysis data for a specific BOM to avoid re-parsing for every vulnerability.
    """

    def __init__(self, bom: Dict[str, Any], mapping: Dict[str, str]):
        self.bom = bom
        self.mapping = compile_team_mapping(mapping)
        self.parent_map = build_parent_map(bom)
        self.comp_map = {}  # ref -> comp

        # Caches
        self.uuid_to_ref = {}
        self.name_to_ref_candidates = {}  # name -> list of refs (in case of dupes, though rare)
        self.purl_to_ref_candidates = {}
        self.direct_tags_cache = {}  # component identity -> tuple(tags)
        self.tags_cache = {}  # ref -> tuple(tags)
        self.path_cache = {}  # (ref, max_paths) -> (tuple(paths), truncated)
        self.analysis_cache = {}  # (component_uuid, component_name, purl) -> (tags, paths)
        self.team_mapped_ref_cache = {}  # ref -> bool
        self.ref_to_name = {}  # ref -> human-readable name (includes metadata component)
        self.ref_to_group = {}  # ref -> group (CycloneDX component group)
        self.ref_to_purl = {}  # ref -> package URL

        self._preprocess_components()

    def _preprocess_components(self):
        if not self.bom:
            return

        # Index metadata component (project root) if present
        meta_comp = self.bom.get("metadata", {}).get("component", {})
        meta_ref = meta_comp.get("bom-ref")
        if meta_ref:
            if meta_ref not in self.comp_map:
                self.comp_map[meta_ref] = meta_comp
            meta_name = meta_comp.get("name")
            if meta_name:
                self.ref_to_name[meta_ref] = meta_name
            meta_group = meta_comp.get("group")
            if meta_group:
                self.ref_to_group[meta_ref] = meta_group
            meta_purl = meta_comp.get("purl")
            if meta_purl:
                self.ref_to_purl[meta_ref] = meta_purl

        for comp in self.bom.get("components", []):
            ref = comp.get("bom-ref")
            if not ref:
                continue

            self.comp_map[ref] = comp

            c_uuid = comp.get("uuid")
            c_name = comp.get("name")
            c_group = comp.get("group")
            c_purl = comp.get("purl")

            if c_uuid:
                self.uuid_to_ref[c_uuid] = ref

            if c_name:
                self.ref_to_name[ref] = c_name
                if c_name not in self.name_to_ref_candidates:
                    self.name_to_ref_candidates[c_name] = []
                self.name_to_ref_candidates[c_name].append(ref)

            if c_group:
                self.ref_to_group[ref] = c_group

            if c_purl:
                self.ref_to_purl[ref] = c_purl
                if c_purl not in self.purl_to_ref_candidates:
                    self.purl_to_ref_candidates[c_purl] = []
                self.purl_to_ref_candidates[c_purl].append(ref)

    def _get_component_group(self, ref: str) -> Optional[str]:
        """Return the CycloneDX group for a BOM ref, if known."""
        return self.ref_to_group.get(ref)

    def _get_component_purl(self, ref: str) -> Optional[str]:
        """Return the package URL for a BOM ref, if known."""
        return self.ref_to_purl.get(ref)

    def _get_direct_tags(
        self,
        component_name: Optional[str],
        component_group: Optional[str] = None,
        component_purl: Optional[str] = None,
        *,
        group_known: bool = False,
        include_wildcard: bool = False,
    ) -> Set[str]:
        if not component_name and not component_purl:
            return set()
        cache_key = (
            str(component_name or ""),
            str(component_group or ""),
            str(component_purl or ""),
            group_known,
            include_wildcard,
        )
        cached = self.direct_tags_cache.get(cache_key)
        if cached is not None:
            return set(cached)

        tags = tuple(
            get_team_mapping_tags(
                self.mapping,
                component_name,
                component_group,
                component_purl,
                group_known=group_known,
                include_wildcard=include_wildcard,
            )
        )
        self.direct_tags_cache[cache_key] = tags
        return set(tags)

    def _get_component_name(self, ref: str) -> str:
        # Fast path: pre-built ref→name mapping (covers components + metadata)
        if ref in self.ref_to_name:
            return self.ref_to_name[ref]
        # Fallback to comp_map lookup
        comp = self.comp_map.get(ref, {})
        name = comp.get("name")
        if name:
            self.ref_to_name[ref] = name
            return name
        # Try extracting a human-readable name from purl or ref
        readable = self._humanize_ref(ref)
        self.ref_to_name[ref] = readable
        return readable

    @staticmethod
    def _humanize_ref(ref: str) -> str:
        """Extract a human-readable name from a purl or bom-ref string."""
        # purl format: pkg:type/namespace/name@version or pkg:type/name@version
        if ref.startswith("pkg:"):
            path = ref.split(":", 1)[1]  # drop "pkg:"
            path = path.split("?", 1)[0]  # drop qualifiers
            path = path.split("#", 1)[0]  # drop subpath
            # type/namespace/name@version or type/name@version
            parts = path.split("/", 1)
            if len(parts) > 1:
                name_part = parts[1]  # namespace/name@version or name@version
                name_part = name_part.split("@", 1)[0]  # drop version
                return name_part
        return ref

    def _get_parent_refs(self, ref: str) -> List[str]:
        return list(dict.fromkeys(self.parent_map.get(ref, [])))

    def _is_team_mapped_ref(self, ref: str) -> bool:
        """Check whether a BOM ref corresponds to a component with an explicit team mapping."""
        if ref in self.team_mapped_ref_cache:
            return self.team_mapped_ref_cache[ref]

        name = self._get_component_name(ref)
        if not name:
            self.team_mapped_ref_cache[ref] = False
            return False
        group = self._get_component_group(ref)
        purl = self._get_component_purl(ref)
        is_mapped = bool(self._get_direct_tags(name, group, purl, group_known=True))
        self.team_mapped_ref_cache[ref] = is_mapped
        return is_mapped

    def is_direct_dependency(
        self,
        component_uuid: str,
        component_name: str,
    ) -> Optional[bool]:
        """
        Determine whether a component is a direct dependency.  A component is
        *direct* when at least one of its immediate parents is either:
          - the project root (a ref with no parents of its own), or
          - a team-mapped component.
        It is *transitive* (False) when none of its parents satisfy the above.
        Returns None when the component cannot be located or has no parents.
        """
        target_ref = self.get_target_ref(component_uuid, component_name)
        if not target_ref:
            return None

        parent_refs = self._get_parent_refs(target_ref)
        if not parent_refs:
            return None

        for parent_ref in parent_refs:
            # Direct child of the project root
            if not self._get_parent_refs(parent_ref):
                return True
            # Direct child of a team-mapped component
            if self._is_team_mapped_ref(parent_ref):
                return True

        return False

    def _get_tags_for_ref(self, ref: str) -> List[str]:
        if ref in self.tags_cache:
            return list(self.tags_cache[ref])

        direct_tags = list(
            self._get_direct_tags(
                self._get_component_name(ref),
                self._get_component_group(ref),
                self._get_component_purl(ref),
                group_known=True,
            )
        )
        if direct_tags:
            unique_tags = list(dict.fromkeys(tag for tag in direct_tags if tag))
            self.tags_cache[ref] = tuple(unique_tags)
            return unique_tags

        tags: List[str] = []
        tag_seen: Set[str] = set()
        seen_refs: Set[str] = {ref}

        def walk(current_ref: str):
            for parent_ref in self._get_parent_refs(current_ref):
                if parent_ref in seen_refs:
                    continue
                seen_refs.add(parent_ref)

                parent_name = self._get_component_name(parent_ref)
                parent_group = self._get_component_group(parent_ref)
                parent_purl = self._get_component_purl(parent_ref)
                parent_tags = list(
                    self._get_direct_tags(
                        parent_name,
                        parent_group,
                        parent_purl,
                        group_known=True,
                    )
                )
                if parent_tags:
                    for tag in parent_tags:
                        if tag and tag not in tag_seen:
                            tags.append(tag)
                            tag_seen.add(tag)
                else:
                    walk(parent_ref)

        walk(ref)
        self.tags_cache[ref] = tuple(tags)
        return tags

    def _get_dependency_paths_for_ref(
        self,
        ref: str,
        visiting: Optional[Set[str]] = None,
        max_paths: Optional[int] = None,
    ) -> Tuple[Tuple[str, ...], bool]:
        if visiting is None:
            visiting = set()
        if ref in visiting:
            return (), False

        cache_key = (ref, max_paths)
        cached = self.path_cache.get(cache_key)
        if cached is not None:
            return cached

        parent_refs = self._get_parent_refs(ref)
        current_name = self._get_component_name(ref)
        if not parent_refs:
            paths = (current_name,)
            self.path_cache[cache_key] = (paths, False)
            return paths, False

        visiting.add(ref)
        found_paths = []
        truncated = False
        for parent_ref in parent_refs:
            parent_paths, parent_truncated = self._get_dependency_paths_for_ref(
                parent_ref, visiting, max_paths
            )
            for parent_path in parent_paths:
                if max_paths is not None and len(found_paths) >= max_paths:
                    truncated = True
                    break
                found_paths.append(f"{current_name} -> {parent_path}")
            if parent_truncated:
                truncated = True
            if max_paths is not None and len(found_paths) >= max_paths:
                truncated = True
                break
        visiting.remove(ref)

        unique_paths = sorted(set(found_paths))
        if max_paths is None:
            cached_paths = tuple(unique_paths)
            self.path_cache[cache_key] = (cached_paths, False)
            return cached_paths, False

        limited_paths = tuple(unique_paths[:max_paths])
        result = (limited_paths, truncated or len(unique_paths) > max_paths)
        self.path_cache[cache_key] = result
        return result

    def get_target_ref(
        self,
        component_uuid: str,
        component_name: str,
        component_purl: Optional[str] = None,
    ) -> str:
        # 1. Match by UUID
        if component_uuid and component_uuid in self.uuid_to_ref:
            return self.uuid_to_ref[component_uuid]

        # 2. Match by Ref (if UUID provided is actually a Ref)
        if component_uuid and component_uuid in self.comp_map:
            return component_uuid

        # 3. Match by package URL
        if component_purl and component_purl in self.purl_to_ref_candidates:
            return self.purl_to_ref_candidates[component_purl][0]

        # 4. Match by Name
        if component_name and component_name in self.name_to_ref_candidates:
            # Return first match. Logic could be improved if name collisions matter.
            return self.name_to_ref_candidates[component_name][0]

        return None

    def get_component_group(
        self,
        component_uuid: str,
        component_name: str,
        component_purl: Optional[str] = None,
    ) -> Optional[str]:
        target_ref = self.get_target_ref(component_uuid, component_name, component_purl)
        if not target_ref:
            return None
        return self._get_component_group(target_ref)

    def get_component_purl(
        self,
        component_uuid: str,
        component_name: str,
        component_purl: Optional[str] = None,
    ) -> Optional[str]:
        target_ref = self.get_target_ref(component_uuid, component_name, component_purl)
        if not target_ref:
            return component_purl
        return self._get_component_purl(target_ref) or component_purl

    def get_tags_only(
        self,
        component_uuid: str,
        component_name: str,
        component_purl: Optional[str] = None,
    ) -> List[str]:
        cache_key = (component_uuid or "", component_name or "", component_purl or "")
        cached = self.analysis_cache.get(cache_key)
        if cached and cached[0] is not None:
            return list(cached[0])

        target_ref = self.get_target_ref(component_uuid, component_name, component_purl)
        found_tags: List[str] = []

        if target_ref:
            found_tags = self._get_tags_for_ref(target_ref)
        else:
            found_tags = list(
                self._get_direct_tags(
                    component_name,
                    component_purl=component_purl,
                    group_known=False,
                )
            )

        if not found_tags:
            if target_ref:
                found_tags = list(
                    self._get_direct_tags(
                        self._get_component_name(target_ref),
                        self._get_component_group(target_ref),
                        self._get_component_purl(target_ref),
                        group_known=True,
                        include_wildcard=True,
                    )
                )
            else:
                found_tags = list(
                    self._get_direct_tags(
                        component_name,
                        component_purl=component_purl,
                        group_known=False,
                        include_wildcard=True,
                    )
                )

        tag_list = found_tags
        self.analysis_cache[cache_key] = (
            tuple(tag_list),
            cached[1] if cached else None,
        )
        return tag_list

    def get_dependency_paths(
        self,
        component_uuid: str,
        component_name: str,
        max_paths: Optional[int] = None,
        return_truncated: bool = False,
        component_purl: Optional[str] = None,
    ):
        """
        Returns dependency paths, optionally limited to max_paths.
        """
        cache_key = (component_uuid or "", component_name or "", component_purl or "")
        cached = self.analysis_cache.get(cache_key)
        if cached and cached[1] is not None and max_paths is None:
            return list(cached[1]) if not return_truncated else (list(cached[1]), False)

        found_paths = set()
        truncated = False
        target_ref = self.get_target_ref(component_uuid, component_name, component_purl)

        start_name = component_name
        if target_ref:
            target_comp = self.comp_map.get(target_ref)
            if target_comp:
                start_name = target_comp.get("name") or component_name

        if target_ref:
            paths, truncated = self._get_dependency_paths_for_ref(
                target_ref, max_paths=max_paths
            )
            found_paths.update(paths)
            if not found_paths:
                found_paths.add(start_name)
        else:
            found_paths.add(component_name)

        path_list = sorted(found_paths)
        if max_paths is None:
            self.analysis_cache[cache_key] = (
                cached[0] if cached else None,
                tuple(path_list),
            )
        if return_truncated:
            return path_list, truncated
        return path_list


def group_vulnerabilities(
    versions_data: List[Dict[str, Any]],
    project_boms: Dict[str, Any] = None,
    processed_boms: Dict[str, "BOMAnalysisCache"] = None,
    include_dependency_paths: bool = True,
) -> List[Dict[str, Any]]:
    """
    Groups vulnerabilities across multiple project versions.
    Optionally tags them based on BOM hierarchy and team mapping.
    processed_boms: Optional dict of project_uuid -> BOMAnalysisCache.
                    If provided, raw 'project_boms' are ignored for that uuid.
    """
    if project_boms is None:
        project_boms = {}
    if processed_boms is None:
        processed_boms = {}

    mapping = load_team_mapping()

    # Pre-process BOMs
    bom_processors = processed_boms.copy()
    for proj_uuid, bom in project_boms.items():
        if proj_uuid not in bom_processors:
            bom_processors[proj_uuid] = BOMAnalysisCache(bom, mapping)

    groups = {}  # Key: canonical_id -> Group Data

    # Pass 1: Build Alias Network
    ds = DisjointSet()

    # We need to collect all IDs mentioned to ensure they are in the DS
    # and to potentially map aliases found in one finding to another finding that uses that alias as its primary ID.

    for entry in versions_data:
        for finding in entry["vulnerabilities"]:
            vuln = finding.get("vulnerability", {})
            vid = vuln.get("vulnId") or vuln.get("name")
            if not vid:
                continue

            # Normalize ID for grouping
            vid_norm = vid.upper()
            ds.find(vid_norm)  # Register

            aliases = vuln.get("aliases", [])
            allowed_alias_keys = {
                "cveId",
                "ghsaId",
                "sonatypeId",
                "osvId",
                "snykId",
                "gsdId",
                "vulnDbId",
                "bdsaId",
            }
            for alias_obj in aliases:
                for key, alias_id in alias_obj.items():
                    if key not in allowed_alias_keys:
                        continue
                    if alias_id and isinstance(alias_id, str):
                        ds.union(vid_norm, alias_id.upper())

    # Pass 2: Determine Canonical ID for each set
    # We want a deterministic canonical ID. Preference: CVE > GHSA > Others > lexicographical
    # roots = set(ds.find(x) for x in ds.parent.keys()) # Unused, removing.
    root_to_canonical = {}

    # We need to group all known IDs by their root
    groups_by_root = {}
    for item in ds.parent.keys():
        r = ds.find(item)
        if r not in groups_by_root:
            groups_by_root[r] = []
        groups_by_root[r].append(item)

    for r, members in groups_by_root.items():
        # Sort members by priority
        def sort_key(x):
            if x.startswith("CVE-"):
                return (0, x)
            if x.startswith("GHSA-"):
                return (1, x)
            return (2, x)

        sorted_members = sorted(members, key=sort_key)
        root_to_canonical[r] = sorted_members[0]

    for entry in versions_data:
        version_info = entry["version"]
        vulns = entry["vulnerabilities"]
        proj_uuid = version_info.get("uuid")

        # Get processor for this project version, or create an empty one/default if missing
        processor = bom_processors.get(proj_uuid)
        if not processor:
            # Just in case it wasn't in processed_boms AND wasn't in project_boms
            processor = BOMAnalysisCache({}, mapping)
            bom_processors[proj_uuid] = processor

        for finding in vulns:
            # Finding structure depends on DT API.
            vuln = finding.get("vulnerability", {})
            raw_id = vuln.get("vulnId") or vuln.get("name")  # Fallback

            if not raw_id:
                continue

            # map to canonical (normalized)
            root = ds.find(raw_id.upper())
            canonical_id = root_to_canonical.get(root, raw_id.upper())

            new_cvss_score = (
                vuln.get("cvssV4")
                or vuln.get("cvssV4BaseScore")
                or vuln.get("cvssV3")
                or vuln.get("cvssV3BaseScore")
                or vuln.get("cvssV2")
                or vuln.get("cvssV2BaseScore")
            )
            new_cvss_vector = (
                vuln.get("cvssV4Vector")
                or vuln.get("cvssV3Vector")
                or vuln.get("cvssV2Vector")
            )

            if canonical_id not in groups:
                groups[canonical_id] = {
                    "id": canonical_id,
                    "title": vuln.get("title"),
                    "description": vuln.get("description"),
                    "severity": vuln.get("severity"),
                    "cvss_score": new_cvss_score,
                    "cvss_vector": new_cvss_vector,
                    "rescored_cvss": None,
                    "rescored_vector": None,
                    "rescored_vector_adjusted": False,
                    "affected_versions": {},
                    "tags": [],
                    "assignees": [],
                    "aliases": set(groups_by_root.get(root, [])) - {canonical_id},
                    "assessment_restore_count": 0,
                    "assessment_restore_recoverable_count": 0,
                    "assessment_restore_reasons": [],
                    "assessment_restore_status": None,
                }
            else:
                # Update base CVSS to maximum
                curr_score = groups[canonical_id].get("cvss_score")
                if new_cvss_score is not None:
                    if curr_score is None or new_cvss_score > curr_score:
                        groups[canonical_id]["cvss_score"] = new_cvss_score
                        groups[canonical_id]["cvss_vector"] = new_cvss_vector

            # Prepare component info
            component = finding.get("component", {})
            comp_uuid = component.get("uuid")
            comp_name = component.get("name")
            comp_ver = component.get("version")
            comp_group = component.get("group")
            comp_purl = component.get("purl")

            # Calculate Tags only
            tags = []
            if processor:
                tags = processor.get_tags_only(comp_uuid, comp_name, comp_purl)
                comp_group = (
                    processor.get_component_group(comp_uuid, comp_name, comp_purl)
                    or comp_group
                )
                comp_purl = (
                    processor.get_component_purl(comp_uuid, comp_name, comp_purl)
                    or comp_purl
                )

            for tag in tags:
                if tag not in groups[canonical_id]["tags"]:
                    groups[canonical_id]["tags"].append(tag)

            analysis = finding.get("analysis", {})
            details = analysis.get("analysisDetails") or ""
            attribution = finding.get("attribution") or {}
            attributed_on = (
                attribution.get("attributedOn")
                or finding.get("attributedOn")
                or finding.get("attributed_on")
            )

            # Parse rescored value if present
            rescored_score = None
            rescored_vector = None
            if details:
                # Parse Score
                match_score = RE_SCORE.search(details)
                if match_score:
                    try:
                        rescored_score = float(match_score.group(1))
                    except ValueError:
                        pass

                # Parse Vector
                match_vector = RE_VECTOR.search(details)
                if match_vector:
                    rescored_vector = match_vector.group(1).strip()
                else:
                    # Fallback: Search for any CVSS vector string in the details
                    match_any_vector = RE_ANY_VECTOR.search(details)
                    if match_any_vector:
                        rescored_vector = match_any_vector.group(1).strip()

            # Sanitize: ensure rescored vector preserves original base metrics
            base_vector = groups[canonical_id].get("cvss_vector")
            rescored_vector_adjusted = groups[canonical_id].get(
                "rescored_vector_adjusted", False
            )
            if rescored_vector and base_vector:
                sanitized = sanitize_rescored_vector(base_vector, rescored_vector)
                if sanitized != rescored_vector:
                    rescored_vector_adjusted = True
                rescored_vector = sanitized
            groups[canonical_id]["rescored_vector_adjusted"] = (
                groups[canonical_id].get("rescored_vector_adjusted", False)
                or rescored_vector_adjusted
            )

            # Set rescored score/vector if they were explicitly provided
            if rescored_score is not None:
                curr_rescored = groups[canonical_id]["rescored_cvss"]
                if curr_rescored is None or rescored_score > curr_rescored:
                    groups[canonical_id]["rescored_cvss"] = rescored_score
                    # Also update group severity based on rescored score
                    groups[canonical_id]["severity"] = score_to_severity(rescored_score)
                    # Also update vector if provided alongside the highest score
                    if rescored_vector:
                        groups[canonical_id]["rescored_vector"] = rescored_vector
            elif rescored_vector and groups[canonical_id]["rescored_vector"] is None:
                groups[canonical_id]["rescored_vector"] = rescored_vector

            # Extract assignees from assessment blocks
            if details:
                _, detail_blocks = _parse_assessment_blocks(details)
                for blk in detail_blocks:
                    for assignee in blk.get("assigned", []):
                        if (
                            assignee
                            and assignee not in groups[canonical_id]["assignees"]
                        ):
                            groups[canonical_id]["assignees"].append(assignee)

            component_info = {
                "project_uuid": proj_uuid,
                "project_name": version_info.get("name"),
                "project_version": version_info.get("version"),
                "component_name": comp_name,
                "component_group": comp_group,
                "component_purl": comp_purl,
                "component_version": comp_ver,
                "component_uuid": comp_uuid,
                "vulnerability_uuid": vuln.get("uuid"),
                "finding_uuid": finding.get("uuid"),
                "attributed_on": attributed_on,
                "analysis_state": analysis.get("state")
                or analysis.get("analysisState"),
                "justification": analysis.get("justification")
                or analysis.get("analysisJustification")
                or "NOT_SET",
                "analysis_details": details,
                "analysis_comments": analysis.get("analysisComments", []),
                "is_suppressed": analysis.get("isSuppressed", False)
                or analysis.get("suppressed", False),
                "is_direct_dependency": None,
                "tags": tags,
            }
            restore_candidate = build_missing_rescoring_vector_restore_candidate(
                {
                    "analysisState": component_info.get("analysis_state"),
                    "analysisDetails": details,
                    "analysisComments": component_info.get("analysis_comments", []),
                }
            )
            if restore_candidate:
                component_info["assessment_restore"] = restore_candidate

            if include_dependency_paths and proj_uuid in bom_processors and comp_uuid:
                try:
                    paths, truncated = bom_processors[proj_uuid].get_dependency_paths(
                        comp_uuid,
                        comp_name,
                        max_paths=DEFAULT_DEPENDENCY_CHAIN_LIMIT,
                        return_truncated=True,
                        component_purl=comp_purl,
                    )
                    component_info["dependency_chains"] = paths
                    component_info["dependency_chains_truncated"] = truncated
                except Exception:
                    component_info["dependency_chains"] = []
                    component_info["dependency_chains_truncated"] = False

            aff_vers_map = groups[canonical_id]["affected_versions"]
            if proj_uuid not in aff_vers_map:
                aff_vers_map[proj_uuid] = {
                    "project_name": version_info.get("name"),
                    "project_version": version_info.get("version"),
                    "project_uuid": proj_uuid,
                    "components": [],
                }

            # Resolve the cheap direct/transitive classification without expanding full paths.
            if proj_uuid in bom_processors:
                try:
                    component_info["is_direct_dependency"] = bom_processors[
                        proj_uuid
                    ].is_direct_dependency(
                        comp_uuid,
                        comp_name,
                    )
                except Exception:
                    # best effort, keep unknown on failure
                    component_info["is_direct_dependency"] = component_info.get(
                        "is_direct_dependency"
                    )

            aff_vers_map[proj_uuid]["components"].append(component_info)

    # Define Severity Rank
    severity_rank = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
        "UNASSIGNED": 5,
        None: 6,
    }

    # Convert groups to list and flatten affected_versions
    result = []
    for g in groups.values():
        # Sort affected versions by project version (descending - assuming later versions first)
        # Using string sort for stability.
        g["affected_versions"] = sorted(
            list(g["affected_versions"].values()),
            key=lambda x: x.get("project_version") or "",
            reverse=True,
        )
        g["aliases"] = sorted(list(g.get("aliases", [])))
        refresh_group_restore_metadata(g)
        result.append(g)

    # Sort final result: Severity (asc rank), then Score (desc), then ID (asc)
    result.sort(
        key=lambda x: (
            severity_rank.get(x.get("severity"), 6),
            -1
            * (
                x.get("rescored_cvss")
                if x.get("rescored_cvss") is not None
                else (x.get("cvss_score") or 0.0)
            ),
            x.get("id"),
        )
    )

    return result


def populate_group_dependency_chains(
    group: Dict[str, Any],
    processed_boms: Dict[str, "BOMAnalysisCache"] | None,
    max_paths: int = DEFAULT_DEPENDENCY_CHAIN_LIMIT,
) -> Dict[str, Any]:
    if not processed_boms:
        return group

    for affected_version in group.get("affected_versions") or []:
        project_uuid = affected_version.get("project_uuid")
        processor = processed_boms.get(project_uuid)
        if not processor:
            continue
        for component in affected_version.get("components") or []:
            if "dependency_chains" in component:
                continue
            component_uuid = component.get("component_uuid")
            component_name = component.get("component_name")
            if not component_uuid:
                component["dependency_chains"] = []
                component["dependency_chains_truncated"] = False
                continue
            try:
                paths, truncated = processor.get_dependency_paths(
                    component_uuid,
                    component_name,
                    max_paths=max_paths,
                    return_truncated=True,
                    component_purl=component.get("component_purl"),
                )
                component["dependency_chains"] = paths
                component["dependency_chains_truncated"] = truncated
            except Exception:
                component["dependency_chains"] = []
                component["dependency_chains_truncated"] = False
    return group


def calculate_statistics(grouped_vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculates statistics from grouped vulnerabilities.
    """
    stats = {
        # Total findings across versions/components (not deduplicated)
        "severity_counts": {},
        # Unique vulnerability group counts (deduplicated by canonical vuln)
        "unique_severity_counts": {},
        # Total instance (finding-level) state counts
        "finding_state_counts": {},
        # Group-level deduped state counts based on aggregated analysis for each vuln group
        "state_counts": {},
        "total_unique": len(grouped_vulns),
        "total_findings": 0,
        "affected_projects_count": 0,
    }

    project_uuids = set()

    for group in grouped_vulns:
        # Group severity (unique vulnerability canonical grouping)
        sev = group.get("severity", "UNKNOWN")
        stats["unique_severity_counts"][sev] = (
            stats["unique_severity_counts"].get(sev, 0) + 1
        )

        # Collect all instances to aggregate state and count findings
        all_instances = []
        for av in group.get("affected_versions", []):
            project_uuids.add(av.get("project_uuid"))
            for comp in av.get("components", []):
                stats["total_findings"] += 1
                # Reporting findings-based severity distribution by the group severity
                stats["severity_counts"][sev] = stats["severity_counts"].get(sev, 0) + 1

                # Findings-level state distribution (each component finding)
                fv_state = (comp.get("analysis_state") or "NOT_SET").upper()
                stats["finding_state_counts"][fv_state] = (
                    stats["finding_state_counts"].get(fv_state, 0) + 1
                )

                all_instances.append(comp)

        states = set(i.get("analysis_state") or "NOT_SET" for i in all_instances)
        non_missing_states = set(s for s in states if s != "NOT_SET")

        if not non_missing_states:
            display_state = "NOT_SET"
        elif len(non_missing_states) == 1:
            if "NOT_SET" in states:
                display_state = "INCOMPLETE"
            else:
                display_state = list(non_missing_states)[0]
        else:
            display_state = "INCONSISTENT"

        stats["state_counts"][display_state] = (
            stats["state_counts"].get(display_state, 0) + 1
        )

    stats["affected_projects_count"] = len(project_uuids)

    return stats


def _parse_assessment_blocks(details: str) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Parses assessment details string into shared text and a list of team blocks.
    Returns: (shared_text, blocks_list)
    Preserves entry order.
    """
    if not details:
        return "", []

    blocks = []

    # Split into potential blocks using the header prefix
    raw_blocks = re.split(r"---(?=\s*\[Team:)", details)
    shared_text = raw_blocks[0].strip() if raw_blocks else ""

    for rb in raw_blocks[1:]:
        # Find the header ends with '---'
        header_end = rb.find("---")
        if header_end == -1:
            continue

        header = rb[:header_end]
        content = rb[header_end + 3 :].strip()

        # Clean metadata from content to prevent leakage
        content = re.sub(
            r"\[(Rescored|Rescored Vector|Assessed By|Reviewed By|Team|State|"
            r"Justification|Date|Assigned|Evidence Reviewed|Version Coverage|"
            r"Ticket):\s*[^\]]*\]",
            "",
            content,
        )
        content = re.sub(
            r"\[Status: Pending Review\]", "", content, flags=re.IGNORECASE
        )
        content = re.sub(r"\bAssessed\s*--\s*\S+", "", content)
        content = re.sub(r"--\s*\S+\s*$", "", content, flags=re.MULTILINE)
        content = content.strip()

        # Robust Parsing: Find all tags
        parsed_tags = {}
        for match in re.finditer(r"\[([\w\s]+):\s*([^\]]+)\]", header):
            key = match.group(1).strip()
            value = match.group(2).strip()
            parsed_tags[key] = value

        t_name = parsed_tags.get("Team")
        if t_name:
            rescored_val = None
            if "Rescored" in parsed_tags:
                try:
                    rescored_val = float(parsed_tags["Rescored"])
                except ValueError:
                    pass

            assigned_raw = parsed_tags.get("Assigned", "")
            assigned_list = (
                [u.strip() for u in assigned_raw.split(",") if u.strip()]
                if assigned_raw
                else []
            )
            timestamp = None
            try:
                if parsed_tags.get("Date"):
                    timestamp = float(parsed_tags["Date"])
            except ValueError:
                pass

            blocks.append(
                {
                    "team": "General" if t_name.casefold() == "general" else t_name,
                    "state": parsed_tags.get("State", "NOT_SET"),
                    "user": parsed_tags.get("Assessed By", "unknown"),
                    "reviewer": parsed_tags.get("Reviewed By"),
                    "justification": parsed_tags.get("Justification", "NOT_SET"),
                    "rescored": rescored_val,
                    "vector": parsed_tags.get("Rescored Vector"),
                    "assigned": assigned_list,
                    "evidence_reviewed": parsed_tags.get(
                        "Evidence Reviewed", ""
                    ).casefold()
                    in {"yes", "true", "checked"},
                    "version_coverage_checked": parsed_tags.get(
                        "Version Coverage", ""
                    ).casefold()
                    in {"yes", "true", "checked"},
                    "ticket": parsed_tags.get("Ticket", ""),
                    "timestamp": timestamp,
                    "details": content,
                }
            )

    return shared_text, blocks


ASSESSMENT_STATES = frozenset(
    {
        "EXPLOITABLE",
        "FALSE_POSITIVE",
        "IN_TRIAGE",
        "NOT_AFFECTED",
        "NOT_SET",
        "RESOLVED",
    }
)


def _assessment_header_value(value: Any) -> str:
    return re.sub(
        r"\s+",
        " ",
        str(value or "")
        .replace("[", "")
        .replace("]", "")
        .replace("---", ""),
    ).strip()


def _render_assessment_document(
    shared_text: str,
    blocks: List[Dict[str, Any]],
    *,
    pending_review: bool,
) -> str:
    parts = [shared_text.strip()] if shared_text.strip() else []
    for block in blocks:
        header_parts = [
            f"[Team: {_assessment_header_value(block.get('team'))}]",
            f"[State: {_assessment_header_value(block.get('state') or 'NOT_SET')}]",
            f"[Assessed By: {_assessment_header_value(block.get('user') or 'unknown')}]",
        ]
        if block.get("reviewer"):
            header_parts.append(
                f"[Reviewed By: {_assessment_header_value(block['reviewer'])}]"
            )
        if block.get("timestamp") is not None:
            header_parts.append(
                f"[Date: {_assessment_header_value(block['timestamp'])}]"
            )
        if block.get("justification"):
            header_parts.append(
                f"[Justification: {_assessment_header_value(block['justification'])}]"
            )
        if block.get("rescored") is not None:
            rescored = float(block["rescored"])
            if math.isfinite(rescored):
                header_parts.append(f"[Rescored: {rescored}]")
        if block.get("vector"):
            header_parts.append(
                f"[Rescored Vector: {_assessment_header_value(block['vector'])}]"
            )
        if block.get("assigned"):
            assigned = ", ".join(
                _assessment_header_value(value) for value in block["assigned"]
            )
            header_parts.append(f"[Assigned: {assigned}]")
        if block.get("evidence_reviewed"):
            header_parts.append("[Evidence Reviewed: yes]")
        if block.get("version_coverage_checked"):
            header_parts.append("[Version Coverage: yes]")
        if block.get("ticket"):
            header_parts.append(
                f"[Ticket: {_assessment_header_value(block['ticket'])}]"
            )
        content = str(block.get("details") or "").strip()
        rendered = f"--- {' '.join(header_parts)} ---"
        if content:
            rendered += f"\n{content}"
        parts.append(rendered)
    if pending_review:
        parts.append("[Status: Pending Review]")
    return "\n\n".join(parts).strip()


def build_authorized_analyst_assessment_details(
    *,
    requested_details: str,
    current_details: str,
    team: str | None,
    username: str,
) -> tuple[str, str]:
    """Apply only the analyst's target-team block to server-owned details."""
    target_key = _assessment_team_key(team)
    if not target_key or target_key == "general":
        raise ValueError("Analysts must update a non-General team assessment")

    _requested_shared, requested_blocks = _parse_assessment_blocks(requested_details)
    current_shared, current_blocks = _parse_assessment_blocks(current_details)

    requested_keys = [
        _assessment_team_key(block.get("team")) for block in requested_blocks
    ]
    if any(not key for key in requested_keys) or len(set(requested_keys)) != len(
        requested_keys
    ):
        raise ValueError("Assessment contains duplicate or invalid team blocks")

    requested_by_team = {
        _assessment_team_key(block.get("team")): block for block in requested_blocks
    }
    target = requested_by_team.get(target_key)
    if target is not None:
        if str(target.get("user") or "") != username:
            raise ValueError("Assessment author must match the authenticated user")
        if target.get("reviewer"):
            raise ValueError("Analysts cannot mark assessments as reviewed")
        state = str(target.get("state") or "").upper()
        if state not in ASSESSMENT_STATES:
            raise ValueError("Assessment state is invalid")

    current = _deduplicate_assessment_blocks(current_blocks)
    current_target = next(
        (
            block
            for block in current
            if _assessment_team_key(block.get("team")) == target_key
        ),
        None,
    )
    current = [
        block
        for block in current
        if _assessment_team_key(block.get("team")) != target_key
    ]
    if target is not None:
        target = {
            **target,
            "team": str(team).strip(),
            "state": str(target.get("state") or "NOT_SET").upper(),
            "user": username,
            "reviewer": None,
            "timestamp": int(time.time() * 1000),
            "rescored": current_target.get("rescored") if current_target else None,
            "vector": current_target.get("vector") if current_target else None,
        }
        current.append(target)

    final_details = _render_assessment_document(
        current_shared,
        current,
        pending_review=True,
    )
    return final_details, calculate_aggregated_state(final_details)


def _assessment_team_key(value: Any) -> str:
    return str(value or "").strip().casefold()


def _deduplicate_assessment_blocks(
    blocks: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    unique: dict[str, tuple[int, Dict[str, Any]]] = {}
    for index, block in enumerate(blocks):
        key = _assessment_team_key(block.get("team"))
        if not key:
            continue
        candidate = dict(block)
        if key == "general":
            candidate["team"] = "General"
        existing = unique.get(key)
        if existing is None:
            unique[key] = (index, candidate)
            continue
        existing_index, existing_block = existing
        existing_timestamp = float(existing_block.get("timestamp") or 0)
        candidate_timestamp = float(candidate.get("timestamp") or 0)
        if candidate_timestamp > existing_timestamp or (
            candidate_timestamp == existing_timestamp
            and len(str(candidate.get("details") or ""))
            >= len(str(existing_block.get("details") or ""))
        ):
            unique[key] = (existing_index, candidate)
    return [block for _index, block in sorted(unique.values(), key=lambda item: item[0])]


def process_assessment_details(
    new_details: str,
    user: str,
    role: str,
    team: Optional[str] = None,
    state: str = "NOT_SET",
    existing_details: str = "",
    assigned: Optional[List[str]] = None,
) -> Tuple[str, str]:
    """
    Parses and merges assessment details, preserving multi-team blocks.
    """
    role = role.upper() if role else "ANALYST"
    target_team = team if team else "General"

    # 1. Parse Existing Blocks
    shared_text, parsed_blocks = _parse_assessment_blocks(existing_details)
    blocks_list = _deduplicate_assessment_blocks(parsed_blocks)

    # 2. Extract Metadata from New Content (if Reviewer)
    new_rescored_val = None
    new_rescored_vector = None
    if role == "REVIEWER":
        match_score = RE_SCORE.search(new_details)
        if match_score:
            try:
                new_rescored_val = float(match_score.group(1))
            except ValueError:
                pass

        match_vector = RE_VECTOR.search(new_details) or RE_ANY_VECTOR.search(
            new_details
        )
        if match_vector:
            new_rescored_vector = match_vector.group(1).strip()

    # 3. Clean New Content (Strip all headers and tags)
    content = re.sub(r"---.*?---", "", new_details, flags=re.DOTALL)
    content = re.sub(
        r"\[(Rescored|Rescored Vector|Assessed By|Reviewed By|Team|State|"
        r"Justification|Date|Assigned|Evidence Reviewed|Version Coverage|"
        r"Ticket):\s*[^\]]*\]",
        "",
        content,
    )
    content = re.sub(r"\[Status: Pending Review\]", "", content, flags=re.IGNORECASE)
    # Remove trailing metadata like "Assessed -- user" or "-- user"
    content = re.sub(r"\bAssessed\s*--\s*\S+", "", content)
    content = re.sub(r"--\s*\S+\s*$", "", content, flags=re.MULTILINE)
    content = content.strip()

    # 4. Handle Legacy text: If shared_text exists but no General block, move it
    if shared_text and not any(
        _assessment_team_key(b["team"]) == "general" for b in blocks_list
    ):
        blocks_list.insert(
            0,
            {
                "team": "General",
                "state": "NOT_SET",
                "user": "unknown",
                "details": shared_text,
                "rescored": None,
                "vector": None,
            },
        )
        shared_text = ""

    # 5. Update Target Team Block
    target_key = _assessment_team_key(target_team)
    target_block = next(
        (
            block
            for block in blocks_list
            if _assessment_team_key(block["team"]) == target_key
        ),
        None,
    )

    # Logic for Reviewer vs Analyst
    final_user = user
    final_reviewer = None
    if role == "REVIEWER":
        final_reviewer = user
        # Preserve original assessor if we are reviewing their work
        final_user = (target_block.get("user") if target_block else None) or user
    else:
        # Analyst update clears previous review
        final_user = user
        final_reviewer = None

    # Rescore Logic: Use new tags if provided, otherwise preserve existing per-team tags
    res_val = (
        new_rescored_val
        if new_rescored_val is not None
        else (target_block.get("rescored") if target_block else None)
    )
    res_vec = (
        new_rescored_vector
        if new_rescored_vector
        else (target_block.get("vector") if target_block else None)
    )

    # Assigned: Use new list if provided, otherwise preserve existing
    final_assigned = (
        assigned
        if assigned is not None
        else (target_block.get("assigned", []) if target_block else [])
    )

    if target_block:
        target_block.update(
            {
                "state": state,
                "user": final_user,
                "reviewer": final_reviewer,
                "rescored": res_val,
                "vector": res_vec,
                "assigned": final_assigned,
                "details": content,
            }
        )
    else:
        blocks_list.append(
            {
                "team": target_team,
                "state": state,
                "user": final_user,
                "reviewer": final_reviewer,
                "rescored": res_val,
                "vector": res_vec,
                "assigned": final_assigned,
                "details": content,
            }
        )
    blocks_list = _deduplicate_assessment_blocks(blocks_list)

    # 6. Reconstruct the canonical document while preserving safe metadata.
    rendered_blocks = [
        block
        for block in blocks_list
        if not (
            _assessment_team_key(block["team"]) != target_key
            and block["state"] == "NOT_SET"
            and not block.get("details")
        )
    ]
    final_str = _render_assessment_document(
        shared_text,
        rendered_blocks,
        pending_review=role == "ANALYST",
    )

    # 7. Aggregate State
    agg_state = calculate_aggregated_state(final_str)

    return final_str, agg_state


def calculate_aggregated_state(details: str) -> str:
    """
    Parses and calculates aggregated state. General block has precedence if set.
    """
    _, parsed_blocks = _parse_assessment_blocks(details)
    blocks_list = _deduplicate_assessment_blocks(parsed_blocks)

    if not blocks_list:
        return "NOT_SET"

    # Order of precedence:
    # 1. Any block named 'General' (if set)
    # 2. Worst state of all teams

    general_block = next(
        (
            block
            for block in blocks_list
            if _assessment_team_key(block["team"]) == "general"
        ),
        None,
    )
    if general_block and general_block.get("state") != "NOT_SET":
        return general_block["state"]

    states = [b["state"] for b in blocks_list if b["state"] != "NOT_SET"]
    if not states:
        return "NOT_SET"

    return sorted(states, key=lambda s: STATE_PRIORITY.get(s, 10))[0]
