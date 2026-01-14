from typing import List, Dict, Any, Tuple
import re
import json
import os

# Pre-compile regex patterns
RE_SCORE = re.compile(r"\[Rescored:\s*([\d\.]+)\]")
RE_VECTOR = re.compile(r"\[Rescored Vector:\s*([^\]]+)\]")
RE_ANY_VECTOR = re.compile(r"\b(CVSS:\d\.\d/\S+|AV:[NLA]/\S+)")


def get_team_mapping_path() -> str:
    return os.getenv("TEAM_MAPPING_PATH", "data/team_mapping.json")


def load_team_mapping(path: str = None) -> Dict[str, str]:
    if path is None:
        path = get_team_mapping_path()

    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return {}


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
        self.mapping = mapping
        self.parent_map = build_parent_map(bom)
        self.comp_map = {}  # ref -> comp

        # Caches
        self.uuid_to_ref = {}
        self.name_to_ref_candidates = {}  # name -> list of refs (in case of dupes, though rare)
        self.analysis_cache = {}  # (component_uuid, component_name) -> (tags, paths)

        self._preprocess_components()

    def _preprocess_components(self):
        if not self.bom:
            return

        for comp in self.bom.get("components", []):
            ref = comp.get("bom-ref")
            if not ref:
                continue

            self.comp_map[ref] = comp

            c_uuid = comp.get("uuid")
            c_name = comp.get("name")

            if c_uuid:
                self.uuid_to_ref[c_uuid] = ref

            if c_name:
                if c_name not in self.name_to_ref_candidates:
                    self.name_to_ref_candidates[c_name] = []
                self.name_to_ref_candidates[c_name].append(ref)

    def get_target_ref(self, component_uuid: str, component_name: str) -> str:
        # 1. Match by UUID
        if component_uuid and component_uuid in self.uuid_to_ref:
            return self.uuid_to_ref[component_uuid]

        # 2. Match by Ref (if UUID provided is actually a Ref)
        if component_uuid and component_uuid in self.comp_map:
            return component_uuid

        # 3. Match by Name
        if component_name and component_name in self.name_to_ref_candidates:
            # Return first match. Logic could be improved if name collisions matter.
            return self.name_to_ref_candidates[component_name][0]

        return None

    def get_tags_only(self, component_uuid: str, component_name: str) -> List[str]:
        found_tags = set()

        # Check direct match first
        if component_name in self.mapping:
            found_tags.add(self.mapping[component_name])

        target_ref = self.get_target_ref(component_uuid, component_name)

        if target_ref:
            # We still need to traverse parents to find tags inherited from parents
            # But we don't need to build full paths, just find tags.
            # BFS is still needed but we can simplify state.

            queue = [target_ref]
            visited = {target_ref}

            while queue:
                current_ref = queue.pop(0)

                # Check current node for Tags
                current_comp = self.comp_map.get(current_ref)
                if current_comp:
                    curr_name = current_comp.get("name")
                    if curr_name and curr_name in self.mapping:
                        found_tags.add(self.mapping[curr_name])

                # Get parents
                parents = self.parent_map.get(current_ref, [])
                for p_ref in parents:
                    if p_ref not in visited:
                        visited.add(p_ref)
                        queue.append(p_ref)

        if not found_tags and "*" in self.mapping:
            found_tags.add(self.mapping["*"])

        return list(found_tags)

    def get_dependency_paths(
        self,
        component_uuid: str,
        component_name: str,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """
        Returns paginated dependency paths.
        Returns {
            "paths": List[str],
            "total": int,
            "limit": int,
            "offset": int
        }
        """
        # Note: This recalculates paths. Caching might be useful if called often for same comp.

        found_paths = set()
        target_ref = self.get_target_ref(component_uuid, component_name)

        start_name = component_name
        if target_ref:
            target_comp = self.comp_map.get(target_ref)
            if target_comp:
                start_name = target_comp.get("name") or component_name

        if target_ref:
            # BFS/Queue for traversal
            queue = [(target_ref, [start_name])]
            visited_states = set()
            visited_states.add((target_ref, tuple([start_name])))

            # Safety break to avoid infinite loops or massive memory
            # The user asked for pagination. If we have 1000s paths, generating all might be slow.
            # But since we need "total" for pagination, we likely need to generate most of them
            # or use a smart counting algorithm.
            # For now, let's generate all (assuming it's reasonable for a single component)
            # and then slice.

            while queue:
                current_ref, current_path = queue.pop(0)

                # Get parents
                parents = self.parent_map.get(current_ref, [])

                if not parents:
                    # Root node
                    path_str = " -> ".join(current_path)
                    found_paths.add(path_str)
                    continue

                for p_ref in parents:
                    p_comp = self.comp_map.get(p_ref)
                    p_name = p_comp.get("name") if p_comp else p_ref

                    if p_name in current_path:
                        continue

                    new_path = current_path + [str(p_name)]
                    state = (p_ref, tuple(new_path))

                    if state in visited_states:
                        continue
                    visited_states.add(state)
                    queue.append((p_ref, new_path))

            if not found_paths:
                found_paths.add(start_name)
        else:
            found_paths.add(component_name)

        # Convert to sorted list
        all_paths = sorted(list(found_paths))
        total = len(all_paths)

        # Paginate
        paginated_paths = all_paths[offset : offset + limit]

        return {
            "paths": paginated_paths,
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    def get_analysis(
        self, component_uuid: str, component_name: str
    ) -> Tuple[List[str], List[str]]:
        # Legacy compatibility if needed, or removing if I updated all callers.
        # I updated group_vulnerabilities, but let's keep it for safety or other callers?
        # logic.py:get_component_analysis calls it.
        tags = self.get_tags_only(component_uuid, component_name)
        paths_data = self.get_dependency_paths(
            component_uuid, component_name, limit=1000
        )
        return (tags, paths_data["paths"])


def get_component_analysis(
    component_uuid: str,
    component_name: str,
    bom: Dict[str, Any],
    mapping: Dict[str, str],
) -> tuple[List[str], List[str]]:
    """
    Analyzes component to find tags and usage paths.
    Returns (list_of_tags, list_of_paths).
    Legacy wrapper around BOMAnalysisCache.
    """
    cache = BOMAnalysisCache(bom, mapping)
    return cache.get_analysis(component_uuid, component_name)


def group_vulnerabilities(
    versions_data: List[Dict[str, Any]],
    project_boms: Dict[str, Any] = None,
    processed_boms: Dict[str, "BOMAnalysisCache"] = None,
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

            ds.find(vid)  # Register

            aliases = vuln.get("aliases", [])
            for alias_obj in aliases:
                for key, alias_id in alias_obj.items():
                    if alias_id and isinstance(alias_id, str):
                        ds.union(vid, alias_id)

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

            # map to canonical
            root = ds.find(raw_id)
            canonical_id = root_to_canonical.get(root, raw_id)

            if canonical_id not in groups:
                groups[canonical_id] = {
                    "id": canonical_id,
                    "title": vuln.get("title"),
                    "description": vuln.get("description"),
                    "severity": vuln.get("severity"),
                    "cvss_score": vuln.get("cvssV3")
                    or vuln.get("cvssV3BaseScore")
                    or vuln.get("cvssV2")
                    or vuln.get("cvssV2BaseScore"),
                    "cvss_vector": vuln.get("cvssV3Vector") or vuln.get("cvssV2Vector"),
                    "rescored_cvss": None,
                    "rescored_vector": None,
                    "affected_versions": {},
                    "tags": set(),
                    "aliases": set(groups_by_root.get(root, [])) - {canonical_id},
                }
            else:
                pass

            # Prepare component info
            component = finding.get("component", {})
            comp_uuid = component.get("uuid")
            comp_name = component.get("name")
            comp_ver = component.get("version")

            # Calculate Tags only
            tags = []
            if processor:
                tags = processor.get_tags_only(comp_uuid, comp_name)

            groups[canonical_id]["tags"].update(tags)

            analysis = finding.get("analysis", {})
            details = analysis.get("analysisDetails") or ""

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

            # If we found a rescored value, update the group level if not set
            if rescored_score is not None and not groups[canonical_id]["rescored_cvss"]:
                groups[canonical_id]["rescored_cvss"] = rescored_score

            if (
                rescored_vector is not None
                and not groups[canonical_id]["rescored_vector"]
            ):
                groups[canonical_id]["rescored_vector"] = rescored_vector

            component_info = {
                "project_uuid": proj_uuid,
                "project_name": version_info.get("name"),
                "project_version": version_info.get("version"),
                "component_name": comp_name,
                "component_version": comp_ver,
                "component_uuid": comp_uuid,
                "vulnerability_uuid": vuln.get("uuid"),
                "finding_uuid": finding.get("uuid"),
                "analysis_state": analysis.get("state")
                or analysis.get("analysisState"),
                "justification": analysis.get("justification")
                or analysis.get("analysisJustification")
                or "NOT_SET",
                "analysis_details": details,
                "analysis_comments": analysis.get("analysisComments", []),
                "is_suppressed": analysis.get("isSuppressed", False)
                or analysis.get("suppressed", False),
                "usage_paths": [],
            }

            aff_vers_map = groups[canonical_id]["affected_versions"]
            if proj_uuid not in aff_vers_map:
                aff_vers_map[proj_uuid] = {
                    "project_name": version_info.get("name"),
                    "project_version": version_info.get("version"),
                    "project_uuid": proj_uuid,
                    "components": [],
                }

            aff_vers_map[proj_uuid]["components"].append(component_info)

    # Convert groups to list and flatten affected_versions
    result = []
    for g in groups.values():
        g["affected_versions"] = list(g["affected_versions"].values())
        g["tags"] = sorted(list(g["tags"]))
        g["aliases"] = sorted(list(g.get("aliases", [])))
        result.append(g)

    return result
