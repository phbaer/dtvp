from typing import List, Dict, Any, Optional, Tuple
import re
import json
import os

# Pre-compile regex patterns
RE_SCORE = re.compile(r"\[Rescored:\s*([\d\.]+)\]")
RE_VECTOR = re.compile(r"\[Rescored Vector:\s*([^\]]+)\]")
RE_ANY_VECTOR = re.compile(r"\b(CVSS:\d\.\d/\S+|AV:[NLA]/\S+)")


def get_team_mapping_path() -> str:
    return os.getenv("TEAM_MAPPING_PATH", "data/team_mapping.json")


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
    except Exception:
        return {}


def get_user_roles_path() -> str:
    return os.getenv("USER_ROLES_PATH", "data/user_roles.json")


def load_user_roles(path: str = None) -> Optional[Dict[str, str]]:
    if path is None:
        path = get_user_roles_path()

    if not os.path.exists(path):
        return None
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def get_user_role(username: str, roles_map: Dict[str, str] = None) -> str:
    """
    Returns 'REVIEWER' or 'ANALYST'.
    If roles_map is None (no config file), everyone is REVIEWER.
    If roles_map matches username, return that.
    Otherwise (config exists but user not in it), return 'ANALYST'.
    """
    if roles_map is None:
        roles_map = load_user_roles()

    if roles_map is None:
        return "REVIEWER"

    return roles_map.get(username, "ANALYST")


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
    ) -> List[str]:
        """
        Returns all dependency paths.
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
        return sorted(list(found_paths))


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
                # ONLY record if it differs from the base score
                if rescored_score != groups[canonical_id]["cvss_score"]:
                    groups[canonical_id]["rescored_cvss"] = rescored_score

            if (
                rescored_vector is not None
                and not groups[canonical_id]["rescored_vector"]
            ):
                # ONLY record if it differs from the base vector
                if rescored_vector != groups[canonical_id]["cvss_vector"]:
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
                "tags": tags,
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
        g["tags"] = sorted(list(g["tags"]))
        g["aliases"] = sorted(list(g.get("aliases", [])))
        result.append(g)

    # Sort final result: Severity (asc rank), then Score (desc), then ID (asc)
    result.sort(
        key=lambda x: (
            severity_rank.get(x.get("severity"), 6),
            -1 * (x.get("rescored_cvss") or x.get("cvss_score") or 0.0),
            x.get("id"),
        )
    )

    return result


def process_assessment_details(
    new_details: str,
    user: str,
    role: str,
    team: Optional[str] = None,
    state: str = "NOT_SET",
    existing_details: str = "",
) -> Tuple[str, str]:
    """
    Parses the assessment details to:
    1. Consolidate Per-Team assessment blocks.
    2. Update/Add the current team's assessment.
    3. Aggregate the "worst" state across all teams.
    4. Maintain shared tags like [Rescored] based on aggregates.
    """
    if not existing_details:
        existing_details = ""

    # 1. Parse existing team blocks
    # Format: --- [Team: Name] [State: State] [Assessed By: User] ---
    #         Details...
    blocks = {}  # team -> {state, user, details, rescored, vector}

    # Split into potential blocks using the header prefix
    raw_blocks = re.split(r"---(?=\s*\[Team:)", existing_details)
    shared_text = raw_blocks[0].strip() if raw_blocks else ""

    for rb in raw_blocks[1:]:
        # Find the header ends with '---'
        header_end = rb.find("---")
        if header_end == -1:
            continue

        header = rb[:header_end]
        content = rb[header_end + 3 :].strip()

        match = re.search(
            r"\[Team:\s*([^\]]+)\]\s*\[State:\s*([^\]]+)\](?:\s*\[Assessed By:\s*([^\]]+)\])?(?:\s*\[Reviewed By:\s*([^\]]+)\])?(?:\s*\[Rescored:\s*([^\]]+)\])?(?:\s*\[Rescored Vector:\s*([^\]]+)\])?",
            header,
        )
        if match:
            t_name = match.group(1)
            blocks[t_name] = {
                "state": match.group(2),
                "user": match.group(3) or "unknown",
                "reviewer": match.group(4),
                "rescored": float(match.group(5)) if match.group(5) else None,
                "vector": match.group(6),
                "details": content,
            }

    # 2. Update current team
    t_key = team or "General"

    # Extract rescored info from the NEW details if tags were manually added or passed
    # (Though usually the UI sends them via other means, but let's parse from new_details as well)
    new_score_match = re.search(r"\[Rescored:\s*([\d\.]+)\]", new_details)
    new_score = float(new_score_match.group(1)) if new_score_match else None

    new_vector_match = re.search(r"\[Rescored Vector:\s*([^\]]+)\]", new_details)
    new_vector = new_vector_match.group(1).strip() if new_vector_match else None

    # Clean the new technical details from any tags we are about to re-add in the header
    clean_new_details = new_details
    clean_new_details = re.sub(r"\[Rescored:\s*[\d\.]+\]", "", clean_new_details)
    clean_new_details = re.sub(r"\[Rescored Vector:\s*[^\]]+\]", "", clean_new_details)
    clean_new_details = re.sub(r"\[Assessed By:\s*[^\]]+\]", "", clean_new_details)
    clean_new_details = re.sub(r"\[Team:\s*[^\]]+\]", "", clean_new_details)
    clean_new_details = re.sub(r"\[State:\s*[^\]]+\]", "", clean_new_details)
    clean_new_details = clean_new_details.strip()

    blocks[t_key] = {
        "state": state,
        "user": user,
        "reviewer": user
        if role == "REVIEWER"
        else blocks.get(t_key, {}).get("reviewer"),
        "rescored": new_score,
        "vector": new_vector,
        "details": clean_new_details,
    }

    # 3. Aggregate State (Global Precedence)
    # If "General" exists and is not NOT_SET, it wins.
    # Otherwise, fallback to worst-case priority among all blocks.
    general_block = blocks.get("General")
    if general_block and general_block["state"] != "NOT_SET":
        aggregated_state = general_block["state"]
    else:
        all_states = [b["state"] for b in blocks.values()]
        if all_states:
            aggregated_state = sorted(
                all_states, key=lambda s: STATE_PRIORITY.get(s, 5)
            )[0]
        else:
            aggregated_state = "NOT_SET"

    # 4. Aggregate Rescored (Max wins)
    all_scores = [b["rescored"] for b in blocks.values() if b["rescored"] is not None]
    max_score = max(all_scores) if all_scores else None

    # Vector corresponds to the max score (or latest if tied)
    max_vector = None
    if max_score is not None:
        for b in blocks.values():
            if b["rescored"] == max_score:
                max_vector = b["vector"]
                break

    # 5. Reconstruct final string
    final_output = []

    # Aggregated tags at the very top
    top_tags = []
    if max_score is not None:
        top_tags.append(f"[Rescored: {max_score}]")
    if max_vector:
        top_tags.append(f"[Rescored Vector: {max_vector}]")

    if top_tags:
        final_output.append(" ".join(top_tags))

    if shared_text:
        # Keep legacy text, but avoid duplicating aggregated tags if they were there
        clean_shared = re.sub(r"\[Rescored:\s*[\d\.]+\]", "", shared_text)
        clean_shared = re.sub(
            r"\[Rescored Vector:\s*[^\]]+\]", "", clean_shared
        ).strip()
        if clean_shared:
            final_output.append(clean_shared)

    # Team blocks
    for t_name, data in sorted(blocks.items()):
        header = f"--- [Team: {t_name}] [State: {data['state']}] [Assessed By: {data['user']}]"
        if data.get("reviewer"):
            header += f" [Reviewed By: {data['reviewer']}]"
        if data["rescored"] is not None:
            header += f" [Rescored: {data['rescored']}]"
        if data["vector"]:
            header += f" [Rescored Vector: {data['vector']}]"
        header += " ---"

        final_output.append(header)
        if data["details"]:
            final_output.append(data["details"])

    final_str = "\n".join(final_output)

    # Analysts always add the flag if missing
    if role == "ANALYST":
        if "[Status: Pending Review]" not in final_str:
            final_str += "\n\n[Status: Pending Review]"

    # Reviewer automatic stripping removed.
    # The client (UI) now decides whether to strip it (Approve) or keep it (Save).

    return final_str, aggregated_state


def calculate_aggregated_state(details: str) -> str:
    """
    Parses the assessment details string to calculate the aggregated state
    based on the worst-case logic.
    """
    if not details:
        return "NOT_SET"

    # Split into potential blocks using the header prefix
    raw_blocks = re.split(r"---(?=\s*\[Team:)", details)

    states = []

    for rb in raw_blocks[1:]:
        # Find the header ends with '---'
        header_end = rb.find("---")
        if header_end == -1:
            continue

        header = rb[:header_end]

        match = re.search(r"\[State:\s*([^\]]+)\]", header)
        if match:
            states.append(match.group(1))

    # Aggregate State (Global Precedence)
    # Check if a General block exists in the states we found
    # NOTE: The simple calculate_aggregated_state might need to be more aware of which state belongs to General.
    # If the parsing is too complex here, we can just rely on process_assessment_details during updates.
    # But for a quick fix, let's look for the General block explicitly if possible.

    # Re-parse to find General explicitly
    general_match = re.search(r"--- \[Team: General\] \[State: ([^\]]+)\]", details)
    if general_match:
        gen_state = general_match.group(1)
        if gen_state != "NOT_SET":
            return gen_state

    if not states:
        return "NOT_SET"

    # Fallback: Worst wins
    aggregated_state = sorted(states, key=lambda s: STATE_PRIORITY.get(s, 5))[0]
    return aggregated_state
