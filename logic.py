from typing import List, Dict, Any, Tuple, Set
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

    def get_analysis(
        self, component_uuid: str, component_name: str
    ) -> Tuple[List[str], List[str]]:
        cache_key = (component_uuid, component_name)
        if cache_key in self.analysis_cache:
            return self.analysis_cache[cache_key]

        found_tags = set()
        found_paths = set()

        # Check direct match first
        if component_name in self.mapping:
            found_tags.add(self.mapping[component_name])

        target_ref = self.get_target_ref(component_uuid, component_name)

        if target_ref:
            # BFS/Queue for traversal
            start_name = component_name
            target_comp = self.comp_map.get(target_ref)
            if target_comp:
                start_name = target_comp.get("name") or component_name

            queue = [(target_ref, [start_name])]
            visited_states = set()
            visited_states.add((target_ref, tuple([start_name])))

            while queue:
                current_ref, current_path = queue.pop(0)

                # Check current node for Tags
                current_comp = self.comp_map.get(current_ref)
                if current_comp:
                    curr_name = current_comp.get("name")
                    if curr_name and curr_name in self.mapping:
                        found_tags.add(self.mapping[curr_name])

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

        if not found_paths:
            found_paths.add(component_name)

        if not found_tags and "*" in self.mapping:
            found_tags.add(self.mapping["*"])

        result = (list(found_tags), sorted(list(found_paths)))
        self.analysis_cache[cache_key] = result
        return result


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
    versions_data: List[Dict[str, Any]], project_boms: Dict[str, Any] = None
) -> List[Dict[str, Any]]:
    """
    Groups vulnerabilities across multiple project versions.
    Optionally tags them based on BOM hierarchy and team mapping.
    """
    if project_boms is None:
        project_boms = {}

    mapping = load_team_mapping()

    # Pre-process BOMs
    bom_processors = {}
    for proj_uuid, bom in project_boms.items():
        bom_processors[proj_uuid] = BOMAnalysisCache(bom, mapping)

    groups = {}  # Key: vuln_id -> Group Data

    for entry in versions_data:
        version_info = entry["version"]
        vulns = entry["vulnerabilities"]
        proj_uuid = version_info.get("uuid")

        # Get processor for this project version, or create an empty one/default if missing
        processor = bom_processors.get(proj_uuid)
        if not processor:
            processor = BOMAnalysisCache(project_boms.get(proj_uuid, {}), mapping)
            bom_processors[proj_uuid] = processor

        for finding in vulns:
            # Finding structure depends on DT API.
            vuln = finding.get("vulnerability", {})
            vuln_id = vuln.get("vulnId") or vuln.get("name")  # Fallback

            if not vuln_id:
                continue

            if vuln_id not in groups:
                groups[vuln_id] = {
                    "id": vuln_id,
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
                }

            # Prepare component info
            component = finding.get("component", {})
            comp_uuid = component.get("uuid")
            comp_name = component.get("name")

            # Calculate Tags and Usage Paths using processor
            tags, paths = processor.get_analysis(comp_uuid, comp_name)

            if tags:
                # Logging could be verbose, consider removing or making conditional
                pass

            groups[vuln_id]["tags"].update(tags)

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
            if rescored_score is not None:
                groups[vuln_id]["rescored_cvss"] = rescored_score

            if rescored_vector is not None:
                groups[vuln_id]["rescored_vector"] = rescored_vector

            component_info = {
                "project_uuid": proj_uuid,
                "project_name": version_info.get("name"),
                "project_version": version_info.get("version"),
                "component_name": comp_name,
                "component_version": component.get("version"),
                "component_uuid": comp_uuid,
                "vulnerability_uuid": vuln.get("uuid"),
                "finding_uuid": finding.get("uuid"),
                "analysis_state": analysis.get("state")
                or analysis.get("analysisState"),
                "analysis_details": details,
                "analysis_comments": analysis.get("analysisComments", []),
                "is_suppressed": analysis.get("isSuppressed", False)
                or analysis.get("suppressed", False),
                "usage_paths": paths,
            }

            if proj_uuid not in groups[vuln_id]["affected_versions"]:
                groups[vuln_id]["affected_versions"][proj_uuid] = {
                    "project_name": version_info.get("name"),
                    "project_version": version_info.get("version"),
                    "project_uuid": proj_uuid,
                    "components": [],
                }

            groups[vuln_id]["affected_versions"][proj_uuid]["components"].append(
                component_info
            )

    # Convert groups to list and flatten affected_versions
    result = []
    for g in groups.values():
        g["affected_versions"] = list(g["affected_versions"].values())
        g["tags"] = list(g["tags"])  # Convert set to list
        g["tags"].sort()
        result.append(g)

    return result
