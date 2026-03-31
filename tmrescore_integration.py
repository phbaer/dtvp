import re
import json
from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple

import httpx
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


SUPPORTED_TMRESCORE_SCOPES = {"latest_only", "merged_versions"}


def natural_version_key(value: Optional[str]) -> Tuple[Any, ...]:
    tokens = re.split(r"(\d+)", value or "")
    key: List[Any] = []
    for token in tokens:
        if not token:
            continue
        if token.isdigit():
            key.append(int(token))
        else:
            key.append(token.lower())
    return tuple(key)


def sort_projects_by_version(projects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(projects, key=lambda item: natural_version_key(item.get("version")))


def normalize_tmrescore_proposal(proposal: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(proposal)

    details = normalized.get("details")
    if details is None and normalized.get("description"):
        normalized["details"] = normalized["description"]

    analysis = normalized.get("analysis")
    if isinstance(analysis, dict):
        normalized["analysis"] = dict(analysis)

    normalized["original_vector"] = normalized.get("original_vector") or None
    normalized["rescored_vector"] = normalized.get("rescored_vector") or None

    for score_key in ("rescored_score", "original_score"):
        score_value = normalized.get(score_key)
        if score_value in {None, ""}:
            normalized[score_key] = None
            continue
        try:
            normalized[score_key] = float(score_value)
        except (TypeError, ValueError):
            pass

    return normalized


def normalize_tmrescore_snapshot(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(snapshot)
    proposals = normalized.get("proposals") or {}
    if isinstance(proposals, dict):
        normalized["proposals"] = {
            key: normalize_tmrescore_proposal(value)
            for key, value in proposals.items()
            if isinstance(value, dict)
        }
    return normalized


def is_meaningful_tmrescore_proposal(proposal: Dict[str, Any]) -> bool:
    rescored_vector = proposal.get("rescored_vector") or None
    original_vector = proposal.get("original_vector") or None
    rescored_score = proposal.get("rescored_score")
    original_score = proposal.get("original_score")

    if not rescored_vector:
        return False
    if original_vector and rescored_vector == original_vector:
        return False
    if original_vector is None and rescored_score is not None and original_score is not None and rescored_score == original_score:
        return False
    return True


class TMRescoreSettings(BaseSettings):
    DTVP_TMRESCORE_URL: str = Field(alias="DTVP_TMRESCORE_URL", default="")
    DTVP_TMRESCORE_TIMEOUT_SECONDS: float = Field(
        alias="DTVP_TMRESCORE_TIMEOUT_SECONDS",
        default=180.0,
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def base_url(self) -> str:
        return self.DTVP_TMRESCORE_URL.rstrip("/")

    @property
    def enabled(self) -> bool:
        return bool(self.base_url)


class TMRescoreClient:
    def __init__(self, settings: Optional[TMRescoreSettings] = None):
        self.settings = settings or TMRescoreSettings()
        if not self.settings.enabled:
            raise RuntimeError("TMRescore integration is not configured")

        self.client = httpx.AsyncClient(timeout=self.settings.DTVP_TMRESCORE_TIMEOUT_SECONDS)

    async def close(self):
        await self.client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()

    async def create_session(
        self,
        application_name: str,
        application_version: str,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "application_name": application_name,
            "application_version": application_version,
        }
        if session_id:
            payload["session_id"] = session_id

        response = await self.client.post(
            f"{self.settings.base_url}/api/v1/sessions",
            json=payload,
        )
        response.raise_for_status()
        return response.json()

    async def get_health(self) -> Dict[str, Any]:
        response = await self.client.get(f"{self.settings.base_url}/health")
        response.raise_for_status()
        return response.json()

    async def analyze_inventory(
        self,
        session_id: str,
        threatmodel_bytes: bytes,
        sbom_bytes: bytes,
        items_csv_bytes: Optional[bytes] = None,
        config_bytes: Optional[bytes] = None,
        chain_analysis: bool = True,
        prioritize: bool = True,
        what_if: bool = False,
        enrich: bool = False,
        ollama_model: Optional[str] = None,
    ) -> Dict[str, Any]:
        files = {
            "threatmodel": ("threatmodel.tm7", threatmodel_bytes, "application/octet-stream"),
            "sbom": ("sbom.json", sbom_bytes, "application/json"),
        }
        if items_csv_bytes is not None:
            files["items_csv"] = ("items.csv", items_csv_bytes, "text/csv")
        if config_bytes is not None:
            files["config"] = ("config.yaml", config_bytes, "application/x-yaml")

        response = await self.client.post(
            f"{self.settings.base_url}/api/v1/sessions/{session_id}/inventory",
            files=files,
            data={
                "chain_analysis": str(chain_analysis).lower(),
                "prioritize": str(prioritize).lower(),
                "what_if": str(what_if).lower(),
                "enrich": str(enrich).lower(),
                **({"ollama_model": ollama_model} if ollama_model else {}),
            },
        )
        response.raise_for_status()
        return response.json()

    async def get_results(self, session_id: str) -> Dict[str, Any]:
        response = await self.client.get(
            f"{self.settings.base_url}/api/v1/sessions/{session_id}/results"
        )
        response.raise_for_status()
        return response.json()

    async def get_progress(self, session_id: str) -> Dict[str, Any]:
        response = await self.client.get(
            f"{self.settings.base_url}/api/v1/sessions/{session_id}/progress"
        )
        response.raise_for_status()
        return response.json()

    async def get_results_json(self, session_id: str) -> Dict[str, Any]:
        response = await self.client.get(
            f"{self.settings.base_url}/api/v1/sessions/{session_id}/results/json"
        )
        response.raise_for_status()
        return response.json()

    async def get_results_vex(self, session_id: str) -> Dict[str, Any]:
        response = await self.client.get(
            f"{self.settings.base_url}/api/v1/sessions/{session_id}/results/vex"
        )
        response.raise_for_status()
        return response.json()

    async def get_output_file(self, session_id: str, filename: str) -> httpx.Response:
        response = await self.client.get(
            f"{self.settings.base_url}/api/v1/sessions/{session_id}/outputs/{filename}"
        )
        response.raise_for_status()
        return response


def get_tmrescore_generated_at(results_document: Dict[str, Any]) -> Optional[str]:
    return (
        results_document.get("generated_at")
        or (results_document.get("metadata") or {}).get("timestamp")
    )


def _extract_vex_rating(vulnerability: Dict[str, Any]) -> Tuple[Optional[float], Optional[str]]:
    preferred_source_name = "CVSS Re-Scorer (Environmental)"

    for rating in vulnerability.get("ratings") or []:
        if not isinstance(rating, dict):
            continue
        source = rating.get("source") or {}
        if str(source.get("name") or "").strip() != preferred_source_name:
            continue
        score = rating.get("score")
        vector = rating.get("vector") or None
        if score is None and not vector:
            continue
        return (float(score) if score is not None else None), vector
    return None, None


def _extract_vex_properties(vulnerability: Dict[str, Any]) -> Dict[str, Any]:
    extracted: Dict[str, Any] = {}
    for item in vulnerability.get("properties") or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        extracted[name] = item.get("value")
    return extracted


def _parse_vex_json_property(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def build_tmrescore_proposals(results_document: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    proposals: Dict[str, Dict[str, Any]] = {}

    for vulnerability in results_document.get("vulnerabilities") or []:
        vuln_id = str(
            vulnerability.get("id")
            or vulnerability.get("vulnId")
            or vulnerability.get("name")
            or ""
        ).strip()
        if not vuln_id:
            continue

        vex_properties = _extract_vex_properties(vulnerability)

        rescored_score = vulnerability.get("rescored_score")
        rescored_vector = vulnerability.get("rescored_vector") or None
        original_score = vulnerability.get("original_score")
        original_vector = vulnerability.get("original_vector") or None

        if rescored_score is None and not rescored_vector:
            rescored_score, rescored_vector = _extract_vex_rating(vulnerability)

        affected_refs = vulnerability.get("affected_refs") or []
        if not affected_refs:
            affected_refs = [
                item.get("ref") if isinstance(item, dict) else item
                for item in (vulnerability.get("affects") or [])
            ]

        analysis_payload = vulnerability.get("analysis") if isinstance(vulnerability.get("analysis"), dict) else None
        detail_message = (analysis_payload or {}).get("detail") or None
        description = (
            vulnerability.get("description")
            or vulnerability.get("title")
            or detail_message
            or vuln_id
        )

        if not rescored_vector:
            continue

        key = vuln_id.upper()
        candidate = normalize_tmrescore_proposal({
            "vuln_id": vuln_id,
            "rescored_score": float(rescored_score) if rescored_score is not None else None,
            "rescored_vector": rescored_vector,
            "original_score": float(original_score) if original_score is not None else None,
            "original_vector": original_vector,
            "affected_refs": [ref for ref in affected_refs if ref],
            "description": description,
            "details": detail_message,
            "analysis": dict(analysis_payload) if analysis_payload else None,
            "original_severity": vex_properties.get("cvss-rescorer:original_severity") or None,
            "rescored_severity": vex_properties.get("cvss-rescorer:rescored_severity") or None,
            "cwe_descriptions": _parse_vex_json_property(vex_properties.get("cvss-rescorer:cwe_descriptions")),
            "evaluations": _parse_vex_json_property(vex_properties.get("cvss-rescorer:evaluations")),
        })

        existing = proposals.get(key)
        if not existing:
            proposals[key] = candidate
            continue

        if candidate["rescored_score"] is not None:
            existing["rescored_score"] = candidate["rescored_score"]
        if candidate["rescored_vector"]:
            existing["rescored_vector"] = candidate["rescored_vector"]
        if candidate["original_score"] is not None:
            existing["original_score"] = candidate["original_score"]
        if candidate["original_vector"]:
            existing["original_vector"] = candidate["original_vector"]
        if not existing.get("details") and candidate.get("details"):
            existing["details"] = candidate["details"]
        if not existing.get("analysis") and candidate.get("analysis"):
            existing["analysis"] = candidate["analysis"]
        if not existing.get("description") and candidate.get("description"):
            existing["description"] = candidate["description"]

        merged_refs = set(existing.get("affected_refs") or [])
        merged_refs.update(candidate["affected_refs"])
        existing["affected_refs"] = sorted(merged_refs)

    return proposals


def build_dtvp_vulnerability_proposals(
    analysis_inputs: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    proposals: Dict[str, Dict[str, Any]] = {}

    for entry in analysis_inputs:
        for finding in entry.get("vulnerabilities") or []:
            vulnerability = finding.get("vulnerability") or {}
            vuln_id = str(
                vulnerability.get("vulnId")
                or vulnerability.get("id")
                or vulnerability.get("name")
                or ""
            ).strip()
            if not vuln_id:
                continue

            _, original_score, original_vector, _ = _extract_primary_rating(vulnerability)
            if original_score is None and not original_vector:
                continue

            key = vuln_id.upper()
            candidate = normalize_tmrescore_proposal({
                "vuln_id": vuln_id,
                "description": vulnerability.get("description") or vulnerability.get("title") or vuln_id,
                "original_score": original_score,
                "original_vector": original_vector,
                "rescored_score": None,
                "rescored_vector": None,
                "affected_refs": [],
            })

            existing = proposals.get(key)
            if not existing:
                proposals[key] = candidate
                continue

            if existing.get("original_score") is None and candidate["original_score"] is not None:
                existing["original_score"] = candidate["original_score"]
            if not existing.get("original_vector") and candidate["original_vector"]:
                existing["original_vector"] = candidate["original_vector"]

    return proposals


def _append_properties(target: Dict[str, Any], properties: List[Tuple[str, Optional[str]]]) -> None:
    existing = {
        (item.get("name"), item.get("value"))
        for item in target.get("properties", [])
        if isinstance(item, dict)
    }
    enriched = list(target.get("properties", []))
    for name, value in properties:
        if value is None:
            continue
        item = {"name": name, "value": str(value)}
        key = (item["name"], item["value"])
        if key not in existing:
            enriched.append(item)
            existing.add(key)
    if enriched:
        target["properties"] = enriched


def _extract_primary_rating(vulnerability: Dict[str, Any]) -> Tuple[Optional[str], Optional[float], Optional[str], Optional[str]]:
    candidates = [
        ("CVSSv40", vulnerability.get("cvssV4") or vulnerability.get("cvssV4BaseScore"), vulnerability.get("cvssV4Vector")),
        ("CVSSv31", vulnerability.get("cvssV3") or vulnerability.get("cvssV3BaseScore"), vulnerability.get("cvssV3Vector")),
        ("CVSSv20", vulnerability.get("cvssV2") or vulnerability.get("cvssV2BaseScore"), vulnerability.get("cvssV2Vector")),
    ]

    for method, score, vector in candidates:
        if score is None and not vector:
            continue
        normalized_score = float(score) if score is not None else None
        severity = vulnerability.get("severity")
        return method, normalized_score, vector, severity
    return None, None, None, vulnerability.get("severity")


def _build_vulnerability_record(vulnerability: Dict[str, Any]) -> Dict[str, Any]:
    vuln_id = vulnerability.get("vulnId") or vulnerability.get("name") or "UNKNOWN"
    method, score, vector, severity = _extract_primary_rating(vulnerability)
    record: Dict[str, Any] = {
        "id": vuln_id,
        "description": vulnerability.get("description") or vulnerability.get("title") or vuln_id,
        "affects": [],
    }
    if method or score is not None or vector:
        rating: Dict[str, Any] = {}
        if method:
            rating["method"] = method
        if score is not None:
            rating["score"] = score
        if vector:
            rating["vector"] = vector
        if severity:
            rating["severity"] = str(severity).lower()
        record["ratings"] = [rating]
    return record


def _fallback_component_ref(
    project_uuid: str,
    component: Dict[str, Any],
    index: int,
) -> str:
    name = component.get("name") or "component"
    version = component.get("version") or "unknown"
    return f"urn:dtvp:tmrescore:{project_uuid}:component:{index}:{name}@{version}"


def build_analysis_sbom(
    project_name: str,
    analysis_inputs: List[Dict[str, Any]],
    scope: str,
    latest_version: str,
) -> Dict[str, Any]:
    aggregate_ref = f"urn:dtvp:tmrescore:{project_name}:aggregate"
    components: List[Dict[str, Any]] = []
    component_refs = set()
    dependency_map: Dict[str, set[str]] = {}
    vulnerability_records: Dict[str, Dict[str, Any]] = {}
    vulnerability_versions: Dict[str, set[str]] = {}

    def add_component(component: Dict[str, Any]) -> None:
        ref = component.get("bom-ref")
        if not ref or ref in component_refs:
            return
        components.append(component)
        component_refs.add(ref)

    def add_dependency(ref: str, depends_on: List[str]) -> None:
        dep_set = dependency_map.setdefault(ref, set())
        for item in depends_on:
            if item:
                dep_set.add(item)

    add_component(
        {
            "bom-ref": aggregate_ref,
            "type": "application",
            "name": project_name,
            "version": latest_version if scope == "latest_only" else "multi-version-analysis",
            "properties": [
                {"name": "dtvp:analysisScope", "value": scope},
                {"name": "dtvp:latestVersion", "value": latest_version},
            ],
        }
    )

    for entry in analysis_inputs:
        version_info = entry["version"]
        project_uuid = version_info.get("uuid", "unknown-project")
        project_version = version_info.get("version", "unknown")
        bom = entry.get("bom") or {}
        metadata = bom.get("metadata") or {}
        metadata_component = deepcopy(metadata.get("component") or {})
        version_root_ref = f"urn:dtvp:tmrescore:{project_uuid}:root"
        version_root = {
            "bom-ref": version_root_ref,
            "type": metadata_component.get("type") or "application",
            "name": metadata_component.get("name") or project_name,
            "version": metadata_component.get("version") or project_version,
        }
        _append_properties(
            version_root,
            [
                ("dtvp:projectUuid", project_uuid),
                ("dtvp:sourceVersion", project_version),
            ],
        )
        add_component(version_root)
        add_dependency(aggregate_ref, [version_root_ref])

        ref_map: Dict[str, str] = {}
        component_lookup: Dict[str, str] = {}
        raw_root_ref = metadata_component.get("bom-ref")
        if raw_root_ref:
            ref_map[str(raw_root_ref)] = version_root_ref

        version_component_refs: List[str] = []
        child_refs = set()

        for index, component in enumerate(bom.get("components") or []):
            clone = deepcopy(component)
            raw_ref = str(clone.get("bom-ref") or _fallback_component_ref(project_uuid, clone, index))
            mapped_ref = f"urn:dtvp:tmrescore:{project_uuid}:component:{raw_ref}"
            clone["bom-ref"] = mapped_ref
            _append_properties(
                clone,
                [
                    ("dtvp:projectUuid", project_uuid),
                    ("dtvp:sourceVersion", project_version),
                ],
            )
            add_component(clone)
            ref_map[raw_ref] = mapped_ref
            version_component_refs.append(mapped_ref)

            comp_uuid = clone.get("uuid")
            if comp_uuid:
                component_lookup[f"uuid:{comp_uuid}"] = mapped_ref
            purl = clone.get("purl")
            if purl:
                component_lookup[f"purl:{purl}"] = mapped_ref
            name = clone.get("name")
            version = clone.get("version")
            if name:
                component_lookup[f"name:{name}"] = mapped_ref
                if version:
                    component_lookup[f"name_version:{name}@{version}"] = mapped_ref

        for dependency in bom.get("dependencies") or []:
            raw_ref = dependency.get("ref")
            if not raw_ref:
                continue
            mapped_ref = ref_map.get(str(raw_ref))
            if not mapped_ref:
                continue
            mapped_deps = []
            for raw_dep in dependency.get("dependsOn") or []:
                mapped_dep = ref_map.get(str(raw_dep))
                if mapped_dep:
                    mapped_deps.append(mapped_dep)
                    child_refs.add(mapped_dep)
            add_dependency(mapped_ref, mapped_deps)

        if not dependency_map.get(version_root_ref):
            top_level_components = sorted(set(version_component_refs) - child_refs)
            add_dependency(version_root_ref, top_level_components)

        for finding in entry.get("vulnerabilities") or []:
            vulnerability = finding.get("vulnerability") or {}
            vuln_id = vulnerability.get("vulnId") or vulnerability.get("name")
            if not vuln_id:
                continue

            record = vulnerability_records.setdefault(
                str(vuln_id).upper(),
                _build_vulnerability_record(vulnerability),
            )
            vulnerability_versions.setdefault(str(vuln_id).upper(), set()).add(project_version)

            method, score, vector, severity = _extract_primary_rating(vulnerability)
            if record.get("ratings") is None or score is not None or vector:
                replacement = _build_vulnerability_record(vulnerability)
                if replacement.get("ratings"):
                    record["ratings"] = replacement["ratings"]
            if severity and record.get("ratings"):
                record["ratings"][0]["severity"] = str(severity).lower()

            component = finding.get("component") or {}
            affect_ref = None
            comp_uuid = component.get("uuid")
            if comp_uuid:
                affect_ref = component_lookup.get(f"uuid:{comp_uuid}")
            if not affect_ref and component.get("purl"):
                affect_ref = component_lookup.get(f"purl:{component.get('purl')}")
            if not affect_ref and component.get("name") and component.get("version"):
                affect_ref = component_lookup.get(
                    f"name_version:{component.get('name')}@{component.get('version')}"
                )
            if not affect_ref and component.get("name"):
                affect_ref = component_lookup.get(f"name:{component.get('name')}")
            if not affect_ref:
                affect_ref = version_root_ref

            affects = record.setdefault("affects", [])
            if not any(item.get("ref") == affect_ref for item in affects):
                affects.append({"ref": affect_ref})

    vulnerabilities = []
    for key in sorted(vulnerability_records.keys()):
        record = vulnerability_records[key]
        _append_properties(
            record,
            [
                ("dtvp:sourceVersions", ", ".join(sorted(vulnerability_versions.get(key, set()), key=natural_version_key))),
            ],
        )
        vulnerabilities.append(record)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "bom-ref": aggregate_ref,
                "type": "application",
                "name": project_name,
                "version": latest_version if scope == "latest_only" else "multi-version-analysis",
            },
            "properties": [
                {"name": "dtvp:analysisScope", "value": scope},
                {"name": "dtvp:latestVersion", "value": latest_version},
                {
                    "name": "dtvp:sourceVersions",
                    "value": ", ".join(
                        sorted(
                            [entry["version"].get("version", "unknown") for entry in analysis_inputs],
                            key=natural_version_key,
                        )
                    ),
                },
            ],
        },
        "components": components,
        "dependencies": [
            {"ref": ref, "dependsOn": sorted(depends_on)}
            for ref, depends_on in sorted(dependency_map.items())
        ],
        "vulnerabilities": vulnerabilities,
    }