import json
import sys
import uuid
from pathlib import Path
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import uvicorn
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

app = FastAPI(title="Mock TMRescore", version="0.1.0")


class SessionCreate(BaseModel):
    application_name: str
    application_version: str
    session_id: Optional[str] = None


sessions: Dict[str, Dict[str, Any]] = {}

MOCK_VECTOR_PAIRS = [
    {
        "version": "CVSS:3.1",
        "original": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rescored": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MPR:L",
        "original_score": 9.8,
        "rescored_score": 8.8,
    },
    {
        "version": "CVSS:3.1",
        "original": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "rescored": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N/MPR:L",
        "original_score": 9.1,
        "rescored_score": 8.1,
    },
    {
        "version": "CVSS:3.0",
        "original": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "rescored": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N/MPR:L",
        "original_score": 5.9,
        "rescored_score": 5.3,
    },
    {
        "version": "CVSS:2.0",
        "original": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
        "rescored": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
        "original_score": 7.5,
        "rescored_score": 4.6,
    },
    {
        "version": "CVSS:4.0",
        "original": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "rescored": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "original_score": 9.3,
        "rescored_score": 5.4,
    },
    {
        "version": "CVSS:3.1",
        "original": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "rescored": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N/MPR:L",
        "original_score": 5.9,
        "rescored_score": 5.3,
    },
    {
        "version": "CVSS:3.1",
        "original": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N",
        "rescored": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N/MPR:H",
        "original_score": 3.3,
        "rescored_score": 2.9,
    },
]

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_session_info(session: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "session_id": session["session_id"],
        "application_name": session["application_name"],
        "application_version": session["application_version"],
        "project_id": session["project_id"],
        "created_at": session["created_at"],
        "has_threat_model": session["files"]["threatmodel"] is not None,
        "has_sbom": session["files"]["sbom"] is not None,
        "has_cves": session["files"]["cves"] is not None,
        "has_items_csv": session["files"]["items_csv"] is not None,
        "has_analysis_config": session["files"]["config"] is not None,
        "status": session["status"],
    }


def _get_session(session_id: str) -> Dict[str, Any]:
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


def _parse_sbom_bytes(raw: Optional[bytes]) -> Dict[str, Any]:
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


def _extract_rating(vulnerability: Dict[str, Any]) -> tuple[Optional[float], Optional[str]]:
    ratings = vulnerability.get("ratings") or []
    if ratings:
        rating = ratings[0] or {}
        score = rating.get("score")
        vector = rating.get("vector")
        return (float(score) if score is not None else None, vector)
    return None, None


def _cvss_version_family(vector: Optional[str]) -> Optional[str]:
    if not vector:
        return None
    if vector.startswith("CVSS:4.0/"):
        return "CVSS:4.0"
    if vector.startswith("CVSS:3.1/"):
        return "CVSS:3.1"
    if vector.startswith("CVSS:3.0/"):
        return "CVSS:3.0"
    if vector.startswith("CVSS:2.0/") or ("/" in vector and not vector.startswith("CVSS:")):
        return "CVSS:2.0"
    return None


def _synthetic_vector_pair(vulnerability: Dict[str, Any], index: int, preferred_version: Optional[str] = None) -> Dict[str, str]:
    seed = "|".join(
        [
            str(vulnerability.get("id") or "UNKNOWN"),
            str(vulnerability.get("description") or ""),
            str(index),
        ]
    )
    candidates = [pair for pair in MOCK_VECTOR_PAIRS if preferred_version is None or pair["version"] == preferred_version]
    if not candidates:
        candidates = MOCK_VECTOR_PAIRS
    template_index = uuid.uuid5(uuid.NAMESPACE_URL, seed).int % len(candidates)
    return candidates[template_index]


def _merge_rescored_vector(original: str, rescored_template: str) -> str:
    if not original or not rescored_template:
        return rescored_template or original

    original_parts = original.split("/")
    rescored_parts = rescored_template.split("/")

    # If the original vector contains a CVSS version prefix, keep it and append only safe modifier tokens.
    allowed_modifiers = [part for part in rescored_parts[1:] if part.startswith("M")]
    if original_parts[0].startswith("CVSS:"):
        return "/".join(original_parts + allowed_modifiers) if allowed_modifiers else original

    # CVSSv2 has no modifier tokens, so preserve the base vector exactly.
    return original


def _compute_environmental_score(vector: str) -> Optional[float]:
    """Compute the CVSS environmental score for a merged vector string.

    Returns the correct environmental score for CVSS 3.0/3.1 vectors, or
    None for versions not supported by the cvss library.
    """
    if not vector:
        return None
    try:
        from cvss import CVSS3
        if vector.startswith("CVSS:3.0/") or vector.startswith("CVSS:3.1/"):
            c = CVSS3(vector)
            # environmental_score is the third element
            return c.scores()[2]
    except Exception:
        pass
    return None


def _enrich_sbom(sbom: Dict[str, Any]) -> Dict[str, Any]:
    enriched = deepcopy(sbom)
    for index, component in enumerate(enriched.get("components") or []):
        properties = list(component.get("properties") or [])
        properties.append(
            {
                "name": "vp:threatModelElementIds",
                "value": f"TM-ELEMENT-{index + 1}",
            }
        )
        component["properties"] = properties
    return enriched


def _perform_analysis(
    session: Dict[str, Any],
    chain_analysis: bool,
    prioritize: bool,
    what_if: bool,
    enrich: bool,
    ollama_model: Optional[str],
) -> Dict[str, Any]:
    sbom = _parse_sbom_bytes(session["files"]["sbom"])
    enriched_sbom = _enrich_sbom(sbom)
    vulnerabilities = sbom.get("vulnerabilities") or []

    rescored_vulnerabilities = []
    total_reduction = 0.0
    for index, vulnerability in enumerate(vulnerabilities):
        extracted_score, extracted_vector = _extract_rating(vulnerability)
        if extracted_vector:
            vector_pair = _synthetic_vector_pair(
                vulnerability,
                index,
                _cvss_version_family(extracted_vector),
            )
            original_vector = extracted_vector
            original_score = extracted_score
            rescored_vector = _merge_rescored_vector(original_vector, vector_pair["rescored"])
            rescored_score = _compute_environmental_score(rescored_vector)
            if rescored_score is None:
                rescored_score = vector_pair["rescored_score"]
        else:
            vector_pair = _synthetic_vector_pair(vulnerability, index)
            original_vector = vector_pair["original"]
            original_score = vector_pair["original_score"]
            rescored_vector = vector_pair["rescored"]
            rescored_score = vector_pair["rescored_score"]

        if original_score is not None and rescored_score is not None:
            total_reduction += original_score - rescored_score

        rescored_vulnerabilities.append(
            {
                "id": vulnerability.get("id", "UNKNOWN"),
                "description": vulnerability.get("description"),
                "affected_refs": [item.get("ref") for item in vulnerability.get("affects") or []],
                "original_score": original_score,
                "original_vector": original_vector,
                "rescored_score": rescored_score,
                "rescored_vector": rescored_vector,
            }
        )

    avg_score_reduction = round(total_reduction / len(rescored_vulnerabilities), 2) if rescored_vulnerabilities else 0.0
    raw_result = {
        "session_id": session["session_id"],
        "application_name": session["application_name"],
        "application_version": session["application_version"],
        "generated_at": _now_iso(),
        "summary": {
            "component_count": len(sbom.get("components") or []),
            "vulnerability_count": len(vulnerabilities),
            "rescored_count": len(rescored_vulnerabilities),
            "avg_score_reduction": avg_score_reduction,
            "chain_analysis": chain_analysis,
            "prioritize": prioritize,
            "what_if": what_if,
            "enrich": enrich,
            "ollama_model": ollama_model if enrich else None,
        },
        "vulnerabilities": rescored_vulnerabilities,
    }

    vex_result = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": _now_iso(),
            "component": {
                "type": "application",
                "name": session["application_name"],
                "version": session["application_version"],
            },
        },
        "vulnerabilities": [
            {
                "id": vulnerability["id"],
                "analysis": {
                    "state": "in_triage" if not what_if else "under_investigation",
                    "detail": "Mock tmrescore result generated for local testing.",
                    **({"response": [
                        {
                            "title": "LLM enrichment",
                            "detail": f"Threat justification enriched via {ollama_model or 'default-model'}.",
                        }
                    ]} if enrich else {
                        "response": [
                            {
                                "title": "Deterministic mock analysis",
                                "detail": "Structured mock analysis response without a top-level detail message.",
                            }
                        ]
                    }),
                },
                "ratings": [
                    {
                        "source": {"name": "CVSS Re-Scorer (Environmental)"},
                        "method": "CVSSv31",
                        "score": vulnerability["rescored_score"],
                        "vector": vulnerability["rescored_vector"],
                    }
                ]
                if vulnerability["rescored_score"] is not None or vulnerability["rescored_vector"]
                else [],
                "affects": [{"ref": ref} for ref in vulnerability["affected_refs"] if ref],
            }
            for index, vulnerability in enumerate(rescored_vulnerabilities)
        ],
    }

    output_files = {
        "rescored-report.json": json.dumps(raw_result, indent=2).encode("utf-8"),
        "enriched-sbom.json": json.dumps(enriched_sbom, indent=2).encode("utf-8"),
        "summary.txt": (
            f"Mock TMRescore session {session['session_id']}\n"
            f"Application: {session['application_name']} {session['application_version']}\n"
            f"Components: {len(sbom.get('components') or [])}\n"
            f"Vulnerabilities: {len(vulnerabilities)}\n"
            f"Average reduction: {avg_score_reduction}\n"
            f"LLM enrichment: {'enabled' if enrich else 'disabled'}\n"
        ).encode("utf-8"),
    }

    result = {
        "session_id": session["session_id"],
        "status": "completed",
        "total_cves": len(vulnerabilities),
        "rescored_count": len(rescored_vulnerabilities),
        "avg_score_reduction": avg_score_reduction,
        "elapsed_seconds": 0.42,
        "llm_enrichment": {
            "enabled": enrich,
            "ollama_model": ollama_model if enrich else None,
        },
        "outputs": {
            filename: {
                "size": len(content),
                "content_type": "application/json" if filename.endswith(".json") else "text/plain",
            }
            for filename, content in output_files.items()
        },
        "error": None,
    }

    session["status"] = "completed"
    session["progress"] = 100
    session["results"] = result
    session["results_json"] = raw_result
    session["results_vex"] = vex_result
    session["output_files"] = output_files
    return result


def _new_session(payload: SessionCreate) -> Dict[str, Any]:
    session_id = payload.session_id or str(uuid.uuid4())
    project_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, payload.application_name))
    session = {
        "session_id": session_id,
        "application_name": payload.application_name,
        "application_version": payload.application_version,
        "project_id": project_id,
        "created_at": _now_iso(),
        "status": "created",
        "progress": 0,
        "files": {
            "threatmodel": None,
            "sbom": None,
            "cves": None,
            "items_csv": None,
            "config": None,
        },
        "config_json": None,
        "results": None,
        "results_json": None,
        "results_vex": None,
        "output_files": {},
    }
    sessions[session_id] = session
    return session


@app.post("/api/v1/sessions", status_code=201)
async def create_session(payload: SessionCreate):
    session = _new_session(payload)
    return _build_session_info(session)


@app.get("/api/v1/sessions/{session_id}")
async def get_session(session_id: str):
    return _build_session_info(_get_session(session_id))


@app.delete("/api/v1/sessions/{session_id}", status_code=204)
async def delete_session(session_id: str):
    _get_session(session_id)
    sessions.pop(session_id, None)
    return Response(status_code=204)


@app.put("/api/v1/sessions/{session_id}/files/threatmodel")
async def upload_threatmodel(session_id: str, file: UploadFile = File(...)):
    session = _get_session(session_id)
    session["files"]["threatmodel"] = await file.read()
    return {"status": "ok"}


@app.put("/api/v1/sessions/{session_id}/files/sbom")
async def upload_sbom(session_id: str, file: UploadFile = File(...)):
    session = _get_session(session_id)
    session["files"]["sbom"] = await file.read()
    return {"status": "ok"}


@app.put("/api/v1/sessions/{session_id}/files/cves")
async def upload_cves(session_id: str, file: UploadFile = File(...)):
    session = _get_session(session_id)
    session["files"]["cves"] = await file.read()
    return {"status": "ok"}


@app.put("/api/v1/sessions/{session_id}/files/items")
async def upload_items(session_id: str, file: UploadFile = File(...)):
    session = _get_session(session_id)
    session["files"]["items_csv"] = await file.read()
    return {"status": "ok"}


@app.put("/api/v1/sessions/{session_id}/config")
async def update_config(session_id: str, config: Dict[str, Any]):
    session = _get_session(session_id)
    session["config_json"] = config
    session["files"]["config"] = json.dumps(config).encode("utf-8")
    return {"status": "ok"}


@app.put("/api/v1/sessions/{session_id}/config/upload")
async def upload_config(session_id: str, file: UploadFile = File(...)):
    session = _get_session(session_id)
    session["files"]["config"] = await file.read()
    return {"status": "ok"}


@app.post("/api/v1/sessions/{session_id}/analyze")
async def run_analysis(
    session_id: str,
    chain_analysis: bool = True,
    prioritize: bool = True,
    what_if: bool = False,
    enrich: bool = False,
    ollama_model: str = "qwen2.5:7b",
):
    session = _get_session(session_id)
    if not session["files"]["threatmodel"] or not session["files"]["sbom"]:
        raise HTTPException(status_code=400, detail="Threat model and SBOM are required")
    return _perform_analysis(session, chain_analysis, prioritize, what_if, enrich, ollama_model)


@app.post("/api/v1/sessions/{session_id}/inventory")
async def analyze_inventory(
    session_id: str,
    threatmodel: UploadFile = File(...),
    sbom: UploadFile = File(...),
    items_csv: UploadFile | None = File(None),
    config: UploadFile | None = File(None),
    chain_analysis: bool = Form(True),
    prioritize: bool = Form(True),
    what_if: bool = Form(False),
    enrich: bool = Form(False),
    ollama_model: str = Form("qwen2.5:7b"),
):
    session = _get_session(session_id)
    session["files"]["threatmodel"] = await threatmodel.read()
    session["files"]["sbom"] = await sbom.read()
    session["files"]["items_csv"] = await items_csv.read() if items_csv else None
    session["files"]["config"] = await config.read() if config else None
    session["status"] = "running"
    session["progress"] = 75
    return _perform_analysis(session, chain_analysis, prioritize, what_if, enrich, ollama_model)


@app.get("/api/v1/sessions/{session_id}/results")
async def get_results(session_id: str):
    session = _get_session(session_id)
    if not session["results"]:
        raise HTTPException(status_code=404, detail="No results available")
    return session["results"]


@app.get("/api/v1/sessions/{session_id}/results/json")
async def get_results_json(session_id: str):
    session = _get_session(session_id)
    if session["results_json"] is None:
        raise HTTPException(status_code=404, detail="No JSON results available")
    return JSONResponse(content=session["results_json"])


@app.get("/api/v1/sessions/{session_id}/results/vex")
async def get_results_vex(session_id: str):
    session = _get_session(session_id)
    if session["results_vex"] is None:
        raise HTTPException(status_code=404, detail="No VEX results available")
    return JSONResponse(content=session["results_vex"])


@app.get("/api/v1/sessions/{session_id}/outputs/{filename}")
async def get_output_file(session_id: str, filename: str):
    session = _get_session(session_id)
    content = session["output_files"].get(filename)
    if content is None:
        raise HTTPException(status_code=404, detail="Output file not found")
    media_type = "application/json" if filename.endswith(".json") else "text/plain"
    return Response(
        content=content,
        media_type=media_type,
        headers={"content-disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/v1/sessions/{session_id}/progress")
async def get_progress(session_id: str):
    session = _get_session(session_id)
    return {
        "session_id": session_id,
        "status": session["status"],
        "progress": session["progress"],
    }


@app.get("/health")
async def health():
    return {"status": "ok", "service": "mock-tmrescore", "ollama_configured": True}


@app.get("/ui")
async def ui():
    session_count = len(sessions)
    return HTMLResponse(
        f"""
        <html>
          <head><title>Mock TMRescore</title></head>
          <body style=\"font-family: sans-serif; padding: 2rem; background: #111827; color: #f3f4f6;\">
            <h1>Mock TMRescore</h1>
            <p>In-memory mock service for local DTVP integration testing.</p>
            <ul>
              <li>Sessions: {session_count}</li>
              <li>Health: <a href=\"/health\" style=\"color: #60a5fa;\">/health</a></li>
              <li>OpenAPI: <a href=\"/openapi.json\" style=\"color: #60a5fa;\">/openapi.json</a></li>
            </ul>
          </body>
        </html>
        """
    )


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8090)