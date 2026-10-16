"""Bounded external package/version matching; no local ranges or human decisions."""

import copy
from datetime import UTC, datetime

from packageurl import PackageURL
from pydantic import Field, field_validator

from dtvp.knowledge.evidence import evidence_ref, expected_documents, publish_documents
from dtvp.knowledge.journal import Conflict, Name, Sha
from dtvp.knowledge.legacy_archive import strict_json
from dtvp.knowledge.ownership import product_heads
from dtvp.parsers import validate_advisory
from dtvp.providers import osv_advisory
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

FORMAT = "dtvp.package-matching/1"
CAPTURE_FORMAT = "dtvp.osv-matching-capture/1"
ENDPOINT = "https://api.osv.dev/v1/query"
MAX_PAGE = 4 * 1024 * 1024
MAX_CAPTURE = 32 * 1024 * 1024
MAX_PAGES = 20
MAX_TOTAL_PAGES = 200
MAX_MATCHES = 2000
MAX_SCAN_BYTES = 64 * 1024 * 1024
MAX_POINTERS = 250000
MAX_SOURCE_OBSERVATIONS = 100000
MAX_CONTEXT_FINDINGS = 100000
LIMITATIONS = [
    "OSV reports matches for the submitted versioned PURL; DTVP performs no local affected-range evaluation or applicability assessment.",
    "Exact input coordinates do not establish build/binary identity; provider version interpretation and returned affected claims remain unverified.",
    "Qualified, unversioned, contradictory and unselected package occurrences remain unqueried with unknown coverage.",
    "No-result is a completed provider lookup, not proof of absence, remediation or approval.",
    "Provider aliases do not merge vulnerability identities; the same package may require separate contextual human assessments.",
    "Responses are nontransactional observations; only complete frozen query captures can be published.",
]


class MatchingInput(RequestModel):
    request_id: Name
    expected_evidence: Sha | None
    expected_versions: dict[Name, Sha] = Field(min_length=1, max_length=200)
    purls: list[str] = Field(min_length=1, max_length=20)
    revision: int = Field(ge=0, strict=True)

    @field_validator("purls")
    @classmethod
    def package_versions(cls, values):
        result = []
        for value in values:
            if len(value) > 3000:
                raise ValueError("OSV PURL exceeds supported length")
            package = PackageURL.from_string(value)
            if not package.version or package.qualifiers or package.subpath:
                raise ValueError("OSV matching requires explicit versioned unqualified PURLs")
            result.append(package.to_string())
        if len(result) != len(set(result)):
            raise ValueError("OSV queries require distinct canonical package PURLs")
        return sorted(result)


def enabled(settings):
    if "osv" not in settings.providers_enabled:
        raise ValueError("OSV matching is disabled")


def selection(journal, project_id, versions, *, current=True):
    if not versions or len(versions) > 200:
        raise ValueError("Matching requires one to 200 pinned product versions")
    if current and product_heads(journal.references(), project_id) != versions:
        raise Conflict("Product version heads changed; prepare a new matching request")
    consumed, pointers, loaded, packages, unsupported = 0, 0, set(), {}, {}

    def budget(sha):
        nonlocal consumed
        if sha not in loaded:
            consumed += journal.objects.path(sha).stat().st_size
            if consumed > MAX_SCAN_BYTES:
                raise ValueError("Matching inventory scan exceeds 64 MiB")
            loaded.add(sha)

    for version, state in sorted(versions.items()):
        budget(state)
        manifest = journal.state(state)
        if (
            manifest.project_id != project_id
            or manifest.version != version
            or version.startswith("@")
        ):
            raise ValueError("Matching input belongs to another product/version")
        budget(manifest.sections["inventory"])
        records = journal.load(manifest.sections["inventory"])["records"]
        pointers += len(records)
        if pointers > MAX_POINTERS:
            raise ValueError("Matching inventory pointer budget exceeded")
        for key, sha in records.items():
            if not (key == "root" or key.startswith(("component:", "part-root:"))):
                continue
            budget(sha)
            component = journal.load(sha)
            raw = component.get("purl")
            reason = None
            try:
                package = PackageURL.from_string(raw) if isinstance(raw, str) else None
                if package is None:
                    reason = "missing_purl"
                elif not package.version:
                    reason = "unversioned_purl"
                elif package.qualifiers or package.subpath:
                    reason = "qualified_or_subpath_purl"
                elif component.get("version") and component["version"] != package.version:
                    reason = "component_version_conflicts_with_purl"
            except ValueError:
                reason = "invalid_purl"
            if reason:
                unsupported[reason] = unsupported.get(reason, 0) + 1
            else:
                packages.setdefault(package.to_string(), []).append(
                    {"version": version, "component_ref": component["bom-ref"]}
                )
    return {
        "packages": packages,
        "unsupported_occurrences": unsupported,
        "eligible_purls": len(packages),
        "eligible_occurrences": sum(map(len, packages.values())),
        "unqueried_coverage": "unknown",
    }


def validate_inputs(journal, project_id, data):
    if journal.resolve(evidence_ref(project_id)) != data.expected_evidence:
        raise Conflict("Evidence selection changed; prepare a new matching request")
    selected = selection(journal, project_id, data.expected_versions)
    if set(data.purls) - selected["packages"].keys():
        raise ValueError("Every OSV query must be an exact eligible PURL in pinned inventory")
    return selected


def normalize_match(item):
    if not isinstance(item, dict):
        raise ValueError("OSV advisory must be an object")
    try:
        advisory = osv_advisory(item)
    except (TypeError, KeyError, AttributeError) as error:
        raise ValueError("Malformed OSV advisory structure") from error
    advisory.pop("upstream", None)  # Exact provider object is retained once beside this projection.
    if "withdrawn" in item:
        advisory["withdrawn"] = item["withdrawn"]
    validate_advisory(advisory)
    return {"advisory": advisory, "raw": item}


def matching_document(document):
    """Supported semantic adapter, separate from VEX and known-ID enrichment."""
    if document.get("publisher") != "OSV" or not isinstance(document.get("observed_at"), str):
        raise ValueError("Matching document requires explicit provider and observation time")
    from dtvp.knowledge.service import validate_time

    validate_time(document["observed_at"])
    package = PackageURL.from_string(document["purl"])
    purl = package.to_string()
    if not package.version or package.qualifiers or package.subpath or purl != document["purl"]:
        raise ValueError("Matching document requires canonical versioned unqualified PURL")
    if document.get("id") != "osv-purl:" + digest(canonical(purl)):
        raise ValueError("Matching document identity differs from exact query PURL")
    matches = document.get("matches")
    if not isinstance(matches, list) or len(matches) > MAX_MATCHES:
        raise ValueError("Matching document requires bounded reported matches")
    if document.get("coverage") != ("matches_reported" if matches else "no_matches_reported"):
        raise ValueError("Matching coverage differs from reported result")
    seen, statements = set(), []
    for item in matches:
        if not isinstance(item, dict) or not isinstance(item.get("raw"), dict):
            raise ValueError("Matching claims require original provider objects")
        advisory = item.get("advisory")
        validate_advisory(advisory)
        if advisory != normalize_match(item["raw"])["advisory"]:
            raise ValueError("Matching advisory projection differs from its provider object")
        withdrawn = item["raw"].get("withdrawn")
        if withdrawn is not None:
            validate_time(withdrawn)
        identifier = advisory.get("id")
        if (
            not isinstance(identifier, str)
            or not identifier
            or len(identifier) > 200
            or identifier in seen
            or any(ord(char) < 32 for char in identifier)
        ):
            raise ValueError(
                "Matching requires distinct bounded provider vulnerability identifiers"
            )
        if item["raw"].get("id") != identifier:
            raise ValueError("Matching advisory identity differs from provider record")
        seen.add(identifier)
        statements.append(
            {
                "vulnerability_id": identifier,
                "product_ids": [],
                "purls": [purl],
                "source_refs": [],
                "status": "reported",
                "normalized_status": None,
                "justification": None,
                "rationale": "External OSV package/version match; applicability not assessed.",
                "unresolved_reasons": ["provider_record_withdrawn"]
                if withdrawn is not None
                else [],
                "raw": {
                    "vulnerability": copy.deepcopy(advisory),
                    "provider_entry": copy.deepcopy(item),
                },
            }
        )
    return {
        "format": FORMAT,
        "document_id": document["id"],
        "publisher": "OSV",
        "statements": statements,
        "matching_coverage": {
            "purl": purl,
            "status": document["coverage"],
            "observed_at": document["observed_at"],
        },
        "limitations": LIMITATIONS,
    }


def read_query(http, purl, *, prior_bytes=0, prior_pages=0):
    """Complete one query including empty pages with tokens; caller checkpoints before next."""
    pages, artifacts, matches, seen_ids, tokens = [], {}, [], set(), set()
    token, total = None, prior_bytes
    for _ in range(MAX_PAGES):
        if prior_pages + len(pages) >= MAX_TOTAL_PAGES:
            raise ValueError("OSV total page budget exceeded")
        body = {"package": {"purl": purl}, **({"page_token": token} if token else {})}
        with http.stream("POST", ENDPOINT, json=body, follow_redirects=False) as response:
            response.raise_for_status()
            if response.status_code != 200:
                raise ValueError("OSV query requires a successful 200 response")
            raw = bytearray()
            for chunk in response.iter_bytes():
                if len(raw) + len(chunk) > MAX_PAGE or total + len(chunk) > MAX_CAPTURE:
                    raise ValueError("OSV page/capture byte budget exceeded")
                raw.extend(chunk)
                total += len(chunk)
        value = strict_json(bytes(raw))
        if not isinstance(value, dict) or not isinstance(value.get("vulns", []), list):
            raise ValueError("OSV query response must contain an advisory array")
        rows = value.get("vulns", [])
        if len(matches) + len(rows) > MAX_MATCHES:
            raise ValueError("OSV query match budget exceeded")
        for item in rows:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("id"), str)
                or not item["id"]
                or len(item["id"]) > 200
                or item["id"] in seen_ids
            ):
                raise ValueError("OSV query contains invalid or repeated advisory identities")
            matches.append(normalize_match(item))
            seen_ids.add(item["id"])
        sha = digest(bytes(raw))
        artifacts[sha] = bytes(raw)
        pages.append(
            {
                "url": ENDPOINT,
                "method": "POST",
                "request": body,
                "status": response.status_code,
                "sha256": sha,
                "bytes": len(raw),
                "representation": "decoded_http_body",
            }
        )
        token = value.get("next_page_token")
        if token is None or token == "":
            return {
                "purl": purl,
                "observed_at": datetime.now(UTC).isoformat(),
                "pages": pages,
                "matches": matches,
                "coverage": "matches_reported" if matches else "no_matches_reported",
            }, artifacts
        if not isinstance(token, str) or len(token) > 8192 or token in tokens:
            raise ValueError("OSV pagination token is invalid or repeated")
        tokens.add(token)
    raise ValueError("OSV pagination did not complete within the query page budget")


def capture_identity(project_id, actor_id, data, capture_sha):
    return digest(canonical([project_id, actor_id, data.request_id])), digest(
        canonical(
            [
                "osv.matching.publish/1",
                project_id,
                actor_id,
                data.model_dump(mode="json"),
                capture_sha,
            ]
        )
    )


def publish_matches(journal, *, settings, project_id, actor_id, data, capture):
    enabled(settings)
    capture_raw = canonical(capture)
    capture_sha = digest(capture_raw)
    request_id, fingerprint = capture_identity(project_id, actor_id, data, capture_sha)
    with journal.writer():
        receipt = journal.receipt(request_id, fingerprint)
    if receipt:
        return receipt
    coverage = validate_inputs(journal, project_id, data)
    if (
        capture.get("format") != CAPTURE_FORMAT
        or capture.get("purls") != data.purls
        or len(capture.get("queries", [])) != len(data.purls)
    ):
        raise ValueError("Frozen OSV capture does not cover the exact selected queries")
    preflight(journal, data, capture, coverage)
    documents = expected_documents(
        journal, project_id, data.expected_evidence, data.expected_versions
    )
    total, page_count = 0, 0
    for purl, query in zip(data.purls, capture["queries"], strict=True):
        if (
            query.get("purl") != purl
            or not isinstance(query.get("pages"), list)
            or not 1 <= len(query["pages"]) <= MAX_PAGES
        ):
            raise ValueError("Frozen OSV query/page binding differs")
        expected_token, raw_matches, seen_tokens = None, [], set()
        raw_shas = []
        for index, page in enumerate(query["pages"]):
            expected_request = {
                "package": {"purl": purl},
                **({"page_token": expected_token} if expected_token else {}),
            }
            if (
                page.get("url") != ENDPOINT
                or page.get("method") != "POST"
                or page.get("request") != expected_request
                or page.get("status") != 200
            ):
                raise ValueError("Frozen OSV page does not bind the exact request/response")
            sha = page["sha256"]
            size = journal.objects.path(sha).stat().st_size
            total += size
            page_count += 1
            if size > MAX_PAGE or total > MAX_CAPTURE or page_count > MAX_TOTAL_PAGES:
                raise ValueError("Frozen OSV capture exceeds byte/page budgets")
            raw = journal.objects.read(sha)
            if digest(raw) != sha or len(raw) != page.get("bytes"):
                raise ValueError("Frozen OSV raw response differs")
            value = strict_json(raw)
            if not isinstance(value, dict) or not isinstance(value.get("vulns", []), list):
                raise ValueError("Frozen OSV response is malformed")
            rows = value.get("vulns", [])
            if len(raw_matches) + len(rows) > MAX_MATCHES:
                raise ValueError("Frozen OSV query exceeds match budget")
            raw_matches.extend(rows)
            expected_token = value.get("next_page_token")
            if expected_token not in (None, ""):
                if (
                    not isinstance(expected_token, str)
                    or len(expected_token) > 8192
                    or expected_token in seen_tokens
                ):
                    raise ValueError("Frozen OSV pagination token is invalid or repeated")
                seen_tokens.add(expected_token)
            if index < len(query["pages"]) - 1 and (
                not isinstance(expected_token, str) or not expected_token
            ):
                raise ValueError("Frozen OSV pagination ends before its declared final page")
            raw_shas.append(sha)
        if expected_token not in (None, "") or len(raw_matches) > MAX_MATCHES:
            raise ValueError("Frozen OSV pagination is incomplete")
        expected_matches = [normalize_match(item) for item in raw_matches]
        if query.get("matches") != expected_matches:
            raise ValueError("Frozen OSV normalization differs from raw provider objects")
        document = {
            "format": FORMAT,
            "id": "osv-purl:" + digest(canonical(purl)),
            "publisher": "OSV",
            "purl": purl,
            "observed_at": query["observed_at"],
            "coverage": query["coverage"],
            "matches": expected_matches,
        }
        from dtvp.knowledge.vex import parse_evidence

        raw_document = canonical(document)
        normalized = parse_evidence(raw_document)
        sha = digest(raw_document)
        binding = digest(canonical(["connector:osv-matching", "OSV", document["id"]]))
        related = [record for record in documents.values() if record.get("binding") == binding]
        if related and data.revision <= max(record["source_revision"] for record in related):
            raise Conflict("OSV query revision must increase for each refreshed package")
        for record in related:
            record.update(active=False, superseded_by=sha)
        journal.objects.put(capture_raw)
        journal.objects.put(raw_document)
        documents["evidence-document:" + sha] = {
            "document": normalized,
            "artifact_sha": sha,
            "additional_artifacts": sorted({*raw_shas, capture_sha}),
            "source": "connector:osv-matching",
            "source_revision": data.revision,
            "binding": binding,
            "active": True,
            "actor_id": actor_id,
            "imported_at": capture["completed_at"],
            "representation": "canonical_json",
            "identity_basis": "publisher_source_document_id",
        }
    return publish_documents(
        journal,
        project_id=project_id,
        actor_id=actor_id,
        data=data,
        documents=documents,
        request_id=request_id,
        fingerprint=fingerprint,
        reason="Import frozen OSV package matching claims",
    )


def preflight(journal, data, capture, coverage):
    """Admit immutable input bytes, source and contextual fanout before snapshots."""
    pointers, consumed, seen, contexts, vulnerability_counts = 0, 0, set(), {}, {}

    def budget(sha):
        nonlocal consumed
        if sha not in seen:
            consumed += journal.objects.path(sha).stat().st_size
            if consumed > MAX_SCAN_BYTES:
                raise ValueError("Matching publication input exceeds 64 MiB")
            seen.add(sha)

    for version, sha in [
        *data.expected_versions.items(),
        *([("@evidence", data.expected_evidence)] if data.expected_evidence else []),
    ]:
        budget(sha)
        manifest = journal.state(sha)
        for name, section_sha in manifest.sections.items():
            budget(section_sha)
            records = journal.load(section_sha)["records"]
            pointers += len(records)
            if pointers > MAX_POINTERS:
                raise ValueError("Matching publication record pointer budget exceeded")
            for key, record_sha in records.items():
                budget(record_sha)
                if name == "ownership" and key.startswith("context:") and version != "@evidence":
                    context = journal.load(record_sha)
                    ref = context.get("component_ref")
                    contexts[(version, ref)] = contexts.get((version, ref), 0) + 1
            if name == "vulnerabilities" and version != "@evidence":
                vulnerability_counts[version] = len(records)
    sources, contextual, additions = 0, 0, {}
    for purl, query in zip(data.purls, capture["queries"], strict=True):
        matches = query.get("matches") if isinstance(query, dict) else None
        if not isinstance(matches, list) or len(matches) > MAX_MATCHES:
            raise ValueError("Frozen query requires bounded match records")
        for occurrence in coverage["packages"][purl]:
            version, ref = occurrence["version"], occurrence["component_ref"]
            sources += len(matches)
            contextual += len(matches) * contexts.get((version, ref), 0)
            additions[version] = additions.get(version, 0) + len(matches)
            if sources > MAX_SOURCE_OBSERVATIONS or contextual > MAX_CONTEXT_FINDINGS:
                raise ValueError("Matching source/context finding fanout exceeds supported budget")
    if any(
        count + additions.get(version, 0) + len(data.purls) > MAX_SOURCE_OBSERVATIONS
        for version, count in vulnerability_counts.items()
    ):
        raise ValueError("Matching per-version vulnerability record budget exceeded")
