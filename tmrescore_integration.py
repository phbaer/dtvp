import re
import math
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


def _parse_vector_components(vector: str) -> Dict[str, str]:
    parts = [part for part in vector.split("/") if part]
    if parts and parts[0].startswith("CVSS:"):
        parts = parts[1:]

    metrics: Dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        metrics[key] = value
    return metrics


def _append_cvss_metric(vector: str, key: str, value: str) -> str:
    if not vector:
        return vector
    return f"{vector}/{key}:{value}"


def _upgrade_rescored_vector_to_modifiers(
    original_vector: Optional[str],
    rescored_vector: Optional[str],
) -> Optional[str]:
    if not original_vector or not rescored_vector:
        return rescored_vector
    if not (
        original_vector.startswith("CVSS:3.0/") or original_vector.startswith("CVSS:3.1/")
    ):
        return rescored_vector
    if not (
        rescored_vector.startswith("CVSS:3.0/") or rescored_vector.startswith("CVSS:3.1/")
    ):
        return rescored_vector

    original_metrics = _parse_vector_components(original_vector)
    rescored_metrics = _parse_vector_components(rescored_vector)

    if any(key.startswith("M") for key in rescored_metrics):
        return rescored_vector

    base_to_modified = {
        "AV": "MAV",
        "AC": "MAC",
        "PR": "MPR",
        "UI": "MUI",
        "S": "MS",
        "C": "MC",
        "I": "MI",
        "A": "MA",
    }

    extra_metric_order = ["E", "RL", "RC", "CR", "IR", "AR"]
    upgraded_vector = original_vector
    changed = False

    for key in extra_metric_order:
        rescored_value = rescored_metrics.get(key)
        if rescored_value and original_metrics.get(key) != rescored_value:
            upgraded_vector = _append_cvss_metric(upgraded_vector, key, rescored_value)
            changed = True

    for base_key, modified_key in base_to_modified.items():
        original_value = original_metrics.get(base_key)
        rescored_value = rescored_metrics.get(base_key)
        if not original_value or not rescored_value or original_value == rescored_value:
            continue
        upgraded_vector = _append_cvss_metric(upgraded_vector, modified_key, rescored_value)
        changed = True

    return upgraded_vector if changed else rescored_vector


def _round_up_cvss_v3(value: float) -> float:
    return math.ceil((value * 10) - 1e-9) / 10


def _resolve_cvss31_metric(
    metrics: Dict[str, str],
    key: str,
    values: Dict[str, float],
    *,
    fallback_key: Optional[str] = None,
    default_key: Optional[str] = None,
) -> Optional[float]:
    metric_key = key
    metric_value = metrics.get(metric_key)

    if metric_value in {None, "X"} and fallback_key:
        metric_key = fallback_key
        metric_value = metrics.get(fallback_key)

    if metric_value in {None, "X"}:
        metric_value = default_key

    if metric_value is None:
        return None
    return values.get(metric_value)


def _score_cvss31_vector(vector: str) -> Optional[float]:
    metrics = _parse_vector_components(vector)

    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    ac = {"L": 0.77, "H": 0.44}
    ui = {"N": 0.85, "R": 0.62}
    exploit_code = {"X": 1.0, "U": 0.91, "P": 0.94, "F": 0.97, "H": 1.0}
    remediation_level = {"X": 1.0, "O": 0.95, "T": 0.96, "W": 0.97, "U": 1.0}
    report_confidence = {"X": 1.0, "U": 0.92, "R": 0.96, "C": 1.0}
    requirements = {"X": 1.0, "L": 0.5, "M": 1.0, "H": 1.5}
    scope = metrics.get("S")
    if scope not in {"U", "C"}:
        return None

    pr = {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.5},
    }
    cia = {"N": 0.0, "L": 0.22, "H": 0.56}

    try:
        impact_subscore = 1 - (
            (1 - cia[metrics["C"]])
            * (1 - cia[metrics["I"]])
            * (1 - cia[metrics["A"]])
        )
        if scope == "U":
            impact = 6.42 * impact_subscore
        else:
            impact = 7.52 * (impact_subscore - 0.029) - 3.25 * ((impact_subscore - 0.02) ** 15)

        exploitability = 8.22 * av[metrics["AV"]] * ac[metrics["AC"]] * pr[scope][metrics["PR"]] * ui[metrics["UI"]]
    except KeyError:
        return None

    if impact <= 0:
        base_score = 0.0
    elif scope == "U":
        base_score = _round_up_cvss_v3(min(impact + exploitability, 10.0))
    else:
        base_score = _round_up_cvss_v3(min(1.08 * (impact + exploitability), 10.0))

    try:
        temporal_multiplier = (
            exploit_code[metrics.get("E", "X")]
            * remediation_level[metrics.get("RL", "X")]
            * report_confidence[metrics.get("RC", "X")]
        )
    except KeyError:
        return None

    temporal_score = _round_up_cvss_v3(base_score * temporal_multiplier)

    environmental_keys = {
        "CR",
        "IR",
        "AR",
        "MAV",
        "MAC",
        "MPR",
        "MUI",
        "MS",
        "MC",
        "MI",
        "MA",
    }
    if not any(key in metrics for key in environmental_keys):
        return temporal_score if any(key in metrics for key in {"E", "RL", "RC"}) else base_score

    modified_scope = metrics.get("MS", "X")
    if modified_scope == "X":
        modified_scope = scope
    if modified_scope not in {"U", "C"}:
        return None

    modified_av = _resolve_cvss31_metric(metrics, "MAV", av, fallback_key="AV")
    modified_ac = _resolve_cvss31_metric(metrics, "MAC", ac, fallback_key="AC")
    modified_ui = _resolve_cvss31_metric(metrics, "MUI", ui, fallback_key="UI")
    modified_c = _resolve_cvss31_metric(metrics, "MC", cia, fallback_key="C")
    modified_i = _resolve_cvss31_metric(metrics, "MI", cia, fallback_key="I")
    modified_a = _resolve_cvss31_metric(metrics, "MA", cia, fallback_key="A")
    modified_pr_code = metrics.get("MPR", "X")
    if modified_pr_code == "X":
        modified_pr_code = metrics.get("PR")

    try:
        modified_pr = pr[modified_scope][modified_pr_code]
        confidentiality_requirement = requirements[metrics.get("CR", "X")]
        integrity_requirement = requirements[metrics.get("IR", "X")]
        availability_requirement = requirements[metrics.get("AR", "X")]
    except KeyError:
        return None

    if None in {
        modified_av,
        modified_ac,
        modified_ui,
        modified_c,
        modified_i,
        modified_a,
    }:
        return None

    modified_impact_subscore = min(
        1
        - (
            (1 - (modified_c * confidentiality_requirement))
            * (1 - (modified_i * integrity_requirement))
            * (1 - (modified_a * availability_requirement))
        ),
        0.915,
    )

    if modified_scope == "U":
        modified_impact = 6.42 * modified_impact_subscore
    else:
        modified_impact = 7.52 * (modified_impact_subscore - 0.029) - 3.25 * ((modified_impact_subscore * 0.9731 - 0.02) ** 13)

    modified_exploitability = 8.22 * modified_av * modified_ac * modified_pr * modified_ui

    if modified_impact <= 0:
        environmental_score = 0.0
    elif modified_scope == "U":
        environmental_base_score = _round_up_cvss_v3(min(modified_impact + modified_exploitability, 10.0))
        environmental_score = _round_up_cvss_v3(environmental_base_score * temporal_multiplier)
    else:
        environmental_base_score = _round_up_cvss_v3(min(1.08 * (modified_impact + modified_exploitability), 10.0))
        environmental_score = _round_up_cvss_v3(environmental_base_score * temporal_multiplier)

    return environmental_score


def _score_cvss20_vector(vector: str) -> Optional[float]:
    metrics = _parse_vector_components(vector)

    av = {"L": 0.395, "A": 0.646, "N": 1.0}
    ac = {"H": 0.35, "M": 0.61, "L": 0.71}
    au = {"M": 0.45, "S": 0.56, "N": 0.704}
    cia = {"N": 0.0, "P": 0.275, "C": 0.66}

    try:
        impact = 10.41 * (
            1 - (
                (1 - cia[metrics["C"]])
                * (1 - cia[metrics["I"]])
                * (1 - cia[metrics["A"]])
            )
        )
        exploitability = 20 * av[metrics["AV"]] * ac[metrics["AC"]] * au[metrics["Au"]]
    except KeyError:
        return None

    f_impact = 0.0 if impact == 0 else 1.176
    base_score = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact
    return round(max(0.0, min(base_score, 10.0)) + 1e-9, 1)


def calculate_cvss_score_from_vector(vector: Optional[str]) -> Optional[float]:
    if not vector:
        return None
    if vector.startswith("CVSS:3.0/") or vector.startswith("CVSS:3.1/"):
        return _score_cvss31_vector(vector)
    if vector.startswith("CVSS:2.0/") or ("/" in vector and not vector.startswith("CVSS:")):
        return _score_cvss20_vector(vector)
    return None


def normalize_tmrescore_proposal(proposal: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(proposal)

    original_vector = normalized.get("original_vector") or None
    rescored_vector = _upgrade_rescored_vector_to_modifiers(
        original_vector,
        normalized.get("rescored_vector") or None,
    )

    if rescored_vector is not None:
        normalized["rescored_vector"] = rescored_vector

    rescored_score = calculate_cvss_score_from_vector(rescored_vector)
    original_score = calculate_cvss_score_from_vector(original_vector)

    if rescored_score is not None:
        normalized["rescored_score"] = rescored_score
    elif normalized.get("rescored_score") is not None:
        normalized["rescored_score"] = float(normalized["rescored_score"])

    if original_score is not None:
        normalized["original_score"] = original_score
    elif normalized.get("original_score") is not None:
        normalized["original_score"] = float(normalized["original_score"])

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


def _contains_tmrescore_modifiers(vector: Optional[str]) -> bool:
    if not vector:
        return False
    return bool(re.search(r"/(M[A-Z]{1,3}|E|RL|RC|CR|IR|AR):", vector))


def is_meaningful_tmrescore_proposal(proposal: Dict[str, Any]) -> bool:
    rescored_vector = proposal.get("rescored_vector") or None
    original_vector = proposal.get("original_vector") or None

    if not rescored_vector or not original_vector:
        return False
    if rescored_vector == original_vector:
        return False
    return _contains_tmrescore_modifiers(rescored_vector)


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
    for rating in vulnerability.get("ratings") or []:
        if not isinstance(rating, dict):
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

        description = (
            vulnerability.get("description")
            or vulnerability.get("title")
            or (vulnerability.get("analysis") or {}).get("detail")
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