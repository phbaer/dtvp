import copy
import re

from cvss import CVSS3, CVSS4
from fastapi import HTTPException
from sqlalchemy import select

from dtvp.domain import audit, current_observations, finding_detail, inventory, lock_release
from dtvp.models import Finding, Project, Snapshot
from dtvp.storage import canonical, digest


def base_rating(rating):
    vector = rating.get("vector", "")
    if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/", "CVSS:4.0/")):
        return None
    try:
        parsed = CVSS4(vector) if vector.startswith("CVSS:4") else CVSS3(vector)
        allowed = (
            {"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}
            if vector.startswith("CVSS:4")
            else {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
        )
        supplied = {field.split(":", 1)[0] for field in vector.split("/")[1:]}
        score = parsed.scores()[0]
        if not supplied.issubset(allowed) or float(rating.get("score", score)) != score:
            return None
        return {"vector": vector, "score": score}
    except ValueError, TypeError:
        return None


def create_snapshot(db, artifacts, actor, release, revision_id=None):
    release = lock_release(db, release.id)
    project = actor.require(db, db.get(Project, release.project_id), "snapshot")
    effective, components, active_ids = inventory(db, release)
    if not effective:
        raise HTTPException(409, "Import an SBOM first")
    candidates = [r for r in effective if r.id == revision_id] if revision_id else effective
    if not candidates:
        raise HTTPException(422, "Select an effective SBOM revision")
    selected = max(candidates, key=lambda r: (r.occurred_at, r.created_at, r.id))
    document = selected.document
    # A single coherent SBOM is authoritative. Other source observations stay in the manifest.
    refs = document["component_ids"]
    component_refs = {value: key for key, value in refs.items()}
    observations = current_observations(db, release.id)
    findings = [
        finding_detail(db, f, observations=observations)
        for f in db.scalars(
            select(Finding).where(Finding.release_id == release.id).order_by(Finding.id)
        )
    ]
    bom = copy.deepcopy(document["bom"])
    bom["specVersion"] = "1.6"
    sbom_component_ids = set(refs.values())
    coverage = {
        "inventory": selected.completeness,
        "sources": [r.source for r in effective],
        "matching": document.get(
            "matching", "source-supplied" if document["findings"] else "unknown"
        ),
        "conversion_losses": document.get("losses", []),
        "excluded_components": sorted(active_ids - sbom_component_ids),
        "unresolved_findings": [],
    }
    worklist = {}
    for finding in findings:
        if not finding["active"]:
            continue
        identifier = finding["identifier"]
        assertions = [o["advisory"] for o in finding["observations"]]
        assertions += [e.get("advisory", {}) for e in finding["evidence"]]
        aliases = {identifier}
        for assertion in assertions:
            aliases.update(
                a.get("id", "") for a in assertion.get("aliases", []) if isinstance(a, dict)
            )
        cves = sorted(a for a in aliases if re.fullmatch(r"CVE-\d{4}-\d{4,}", a))
        valid = [base_rating(r) for a in assertions for r in a.get("ratings", [])]
        ratings = {r["vector"]: r for r in valid if r}
        ref = component_refs.get(finding["component_id"])
        if len(cves) != 1 or not ref or len(ratings) != 1:
            coverage["unresolved_findings"].append(
                {
                    "finding_id": finding["id"],
                    "reason": "Need one CVE, an exact component ref, and one original Base vector",
                }
            )
            continue
        cve = cves[0]
        rating = next(iter(ratings.values()))
        entry = worklist.setdefault(
            cve,
            {
                "cve_id": cve,
                "component_refs": [],
                "cvss_vector": rating["vector"],
                "base_score": rating["score"],
                "description": finding["description"],
                "cwe_ids": [],
                "cpe": "",
                "references": [],
            },
        )
        if entry["cvss_vector"] != rating["vector"]:
            coverage["unresolved_findings"].append(
                {
                    "finding_id": finding["id"],
                    "reason": "Conflicting original Base vectors across occurrences",
                }
            )
            entry["conflict"] = True
        entry["component_refs"] = sorted(set(entry["component_refs"]) | {ref})
        for assertion in assertions:
            entry["cwe_ids"] = sorted(
                set(entry["cwe_ids"]) | {f"CWE-{x}" for x in assertion.get("cwes", [])}
            )
            entry["references"] = sorted(
                set(entry["references"])
                | {
                    r["url"]
                    for r in assertion.get("references", [])
                    if isinstance(r, dict) and r.get("url")
                }
            )
    cves = [entry for entry in worklist.values() if not entry.get("conflict")]
    if len(cves) > 1000:
        raise HTTPException(
            422, "VScorer limit exceeded; explicitly partition the release worklist"
        )
    payload = {
        "schema_version": "dtvp.snapshot/1",
        "project": {"id": project.id, "name": project.name, "metadata": project.metadata_json},
        "release": {
            "id": release.id,
            "version": release.version,
            "generation": release.generation,
            "metadata": release.metadata_json,
        },
        "selected_revision": selected.id,
        "coverage": coverage,
        "sbom": bom,
        "original_sha256": selected.artifact_sha,
        "components": [
            {
                "id": c.id,
                "name": c.name,
                "version": c.version,
                "purl": c.purl,
                "refs": [ref for ref, cid in refs.items() if cid == c.id],
                "metadata": c.metadata_json,
            }
            for c in components.values()
            if c.id in sbom_component_ids
        ],
        "findings": findings,
        "vscorer": {"cves": sorted(cves, key=lambda c: c["cve_id"])},
        "source_revisions": [
            {
                "id": r.id,
                "source": r.source,
                "sha256": r.artifact_sha,
                "occurred_at": r.occurred_at.isoformat(),
                "context": r.context,
            }
            for r in effective
        ],
    }
    sha = artifacts.put(canonical(payload))
    snapshot = Snapshot(
        project_id=project.id,
        release_id=release.id,
        author_id=actor.user.id,
        sha=sha,
        manifest={
            "schema_version": "dtvp.snapshot/1",
            "sha256": sha,
            "project_id": project.id,
            "release_id": release.id,
            "generation": release.generation,
            "selected_revision": selected.id,
            "coverage": coverage,
            "files": {
                "sbom": digest(canonical(bom)),
                "vscorer": digest(canonical(payload["vscorer"])),
            },
        },
    )
    db.add(snapshot)
    db.flush()
    audit(db, actor.user.id, "snapshot.create", snapshot.id, project.id)
    return snapshot
