from typing import List, Dict, Any
import re

# Pre-compile regex patterns
RE_SCORE = re.compile(r"\[Rescored:\s*([\d\.]+)\]")
RE_VECTOR = re.compile(r"\[Rescored Vector:\s*([^\]]+)\]")
RE_ANY_VECTOR = re.compile(r"\b(CVSS:\d\.\d/\S+|AV:[NLA]/\S+)")


def group_vulnerabilities(versions_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Groups vulnerabilities across multiple project versions.

    versions_data structure:
    [
        {
            "version": { ... project version data ... },
            "vulnerabilities": [ ... list of findings ... ]
        },
        ...
    ]

    Returns a list of grouped vulnerabilities.
    Each group contains:
    - id: Common Vulnerability ID (e.g. CVE-2023-1234)
    - severity: Max severity in group? Or just the string if same.
    - description: Description from one of them.
    - affected_versions: List of objects {
          project_name, project_version, project_uuid,
          components: [ { component_name, component_version, component_uuid, finding_uuid, analysis_state, ... } ]
      }
    """

    groups = {}  # Key: vuln_id -> Group Data

    for entry in versions_data:
        version_info = entry["version"]
        vulns = entry["vulnerabilities"]

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
                    "affected_versions": {},  # Intermediate dict: project_uuid -> version_data
                }

            # Prepare component info
            analysis = finding.get("analysis", {})
            details = analysis.get("analysisDetails")

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

            # Add to version group
            proj_uuid = version_info.get("uuid")

            component_info = {
                "project_uuid": proj_uuid,
                "project_name": version_info.get("name"),
                "project_version": version_info.get("version"),
                "component_name": finding.get("component", {}).get("name"),
                "component_version": finding.get("component", {}).get("version"),
                "component_uuid": finding.get("component", {}).get("uuid"),
                "vulnerability_uuid": vuln.get("uuid"),
                "finding_uuid": finding.get("uuid"),
                "analysis_state": analysis.get("state")
                or analysis.get("analysisState"),
                "analysis_details": details,
                "analysis_comments": analysis.get("analysisComments", []),
                "is_suppressed": analysis.get("isSuppressed", False)
                or analysis.get("suppressed", False),
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
        result.append(g)

    return result
