"""Frozen, exact-ID provider captures; no package/alias vulnerability matching."""

import copy
import json
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Literal
from urllib.parse import quote

from pydantic import Field, model_validator

from dtvp.knowledge.advisory_documents import FORMAT
from dtvp.knowledge.evidence import EvidenceInput, import_evidence
from dtvp.knowledge.journal import Name, Sha
from dtvp.knowledge.ownership import product_heads
from dtvp.knowledge.workspace import load_sections
from dtvp.non_us_advisories import (
    EUVD_URL,
    JVN_URL,
    euvd_result,
    jvn_result,
    request_parameters,
    supports_identifier,
)
from dtvp.parsers import validate_advisory
from dtvp.providers import ADVISORY_PROVIDERS, client
from dtvp.schemas import RequestModel
from dtvp.storage import digest

CAPTURE_FORMAT = "dtvp.advisory-provider-capture/1"
PUBLISHERS = {
    "nvd": "NVD",
    "circl": "CIRCL Vulnerability-Lookup (mirror)",
    "euvd": "ENISA EUVD",
    "jvn": "MyJVN API (IPA/JVN iPedia)",
}
ENDPOINTS = {
    "euvd": EUVD_URL,
    "jvn": JVN_URL,
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "circl": "https://vulnerability.circl.lu/api/vulnerability/",
}
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_CAPTURE_BYTES = 32 * 1024 * 1024
LIMITATIONS = [
    "Exact-ID enrichment applies only to baseline-reported vulnerabilities; no package, alias, CPE or version-range matching occurs.",
    "Provider and publisher claims are unverified; a mirror is not independent corroboration of its upstream publisher.",
    "Not-found is a provider lookup result, never remediation or absence of a baseline vulnerability.",
    "Separate lookups are nontransactional observations; raw responses and frozen publication inputs are retained.",
]


class AdvisoryRefreshInput(RequestModel):
    request_id: Name
    provider: Literal["nvd", "circl", "euvd", "jvn"]
    identifiers: list[str] = Field(min_length=1, max_length=20)
    expected_evidence: Sha | None
    expected_versions: dict[Name, Sha] = Field(max_length=200)
    revision: int = Field(ge=0, strict=True)

    @model_validator(mode="after")
    def exact_ids(self):
        if any(not supports_identifier(self.provider, value) for value in self.identifiers) or len(
            self.identifiers
        ) != len(set(self.identifiers)):
            raise ValueError(
                "Refresh requires distinct exact identifiers supported by the selected provider"
            )
        self.identifiers = sorted(self.identifiers)
        return self


def enabled(settings, provider):
    if provider not in PUBLISHERS or provider not in settings.providers_enabled:
        raise ValueError("Advisory provider disabled or unsupported")


def baseline_identifiers(journal, project_id, expected_versions, *, require_current=True):
    """Check the complete pinned branch selection; external facts never expand IDs."""
    if require_current and product_heads(journal.references(), project_id) != expected_versions:
        from dtvp.knowledge.journal import Conflict

        raise Conflict("Product versions changed; refresh advisory input heads")
    result = set()
    for version, state in expected_versions.items():
        revision = journal.verify_state(state)
        if revision.project_id != project_id or revision.version != version:
            raise ValueError("Advisory input belongs to another product version")
        sections = load_sections(journal, state)
        from dtvp.knowledge.vex import matching_source_refs

        result.update(matching_source_refs(sections))
        for key, value in sections["vulnerabilities"].items():
            if (
                not key.startswith(("external-evidence:", "evidence-document:"))
                and value.get("ref")
                and value.get("identifier")
            ):
                result.add(value["identifier"])
    return result


def _json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate provider JSON keys")
            value[key] = item
        return value

    def invalid(value):
        raise ValueError("Nonfinite provider JSON")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=invalid)
    except (UnicodeError, RecursionError) as error:
        raise ValueError("Malformed provider JSON") from error


def _body(provider, raw, status):
    if provider == "jvn":
        return {"xml": raw.decode("utf-8")}
    if provider == "euvd" and status == 204:
        if raw:
            raise ValueError("EUVD no-content response contains a body")
        return None
    return _json(raw)


def _verify_result(provider, identifier, result, body, status=200):
    if provider in {"euvd", "jvn"}:
        if status not in ({200, 204} if provider == "euvd" else {200}):
            raise ValueError("Unsupported advisory response status")
        expected = (
            euvd_result(identifier, body, status)
            if provider == "euvd"
            else jvn_result(identifier, body)
        )
        if result != expected:
            raise ValueError("Provider normalized result differs from original source")
        if result["status"] == "found":
            validate_advisory(result["advisory"])
        return
    if not isinstance(body, dict) or not isinstance(result, dict):
        raise ValueError("Provider response must be an object")
    if provider == "nvd":
        values = body.get("vulnerabilities")
        if not isinstance(values, list) or len(values) > 1:
            raise ValueError("NVD exact lookup requires a single-result response")
        count = body.get("totalResults", len(values))
        if isinstance(count, bool) or not isinstance(count, int) or count != len(values):
            raise ValueError("NVD result count differs from exact-ID response")
        found = bool(values)
        if found and (
            not isinstance(values[0], dict)
            or not isinstance(values[0].get("cve"), dict)
            or values[0]["cve"].get("id") != identifier
        ):
            raise ValueError("NVD upstream identifier differs from requested identifier")
    else:
        found = bool(body)
        if found and (
            not isinstance(body.get("cveMetadata"), dict)
            or body["cveMetadata"].get("cveId") != identifier
        ):
            raise ValueError("CIRCL upstream identifier differs from requested identifier")
    if result.get("status") != ("found" if found else "not_found"):
        raise ValueError("Provider normalized status differs from raw response")
    if found:
        advisory = result.get("advisory")
        if (
            not isinstance(advisory, dict)
            or advisory.get("id") != identifier
            or result.get("upstream") != body
        ):
            raise ValueError("Provider normalized advisory scope differs")
        validate_advisory(advisory)
    elif result.get("identifier") != identifier:
        raise ValueError("Provider missing-result identifier differs")


class _Response:
    def __init__(self, response, capture):
        self.response, self.capture, self.parts = response, capture, []

    def __getattr__(self, key):
        return getattr(self.response, key)

    def iter_bytes(self):
        size = 0
        for block in self.response.iter_bytes():
            size += len(block)
            self.capture.total += len(block)
            if size > MAX_RESPONSE_BYTES or self.capture.total > MAX_CAPTURE_BYTES:
                raise ValueError("Advisory response/capture byte budget exceeded")
            self.parts.append(block)
            yield block


class _Capture:
    def __init__(self, http, provider):
        self.http, self.provider = http, provider
        self.total, self.artifacts, self.responses = 0, {}, []
        self.identifier = None

    @contextmanager
    def stream(self, method, url, **kwargs):
        expected = ENDPOINTS[self.provider] + (
            quote(self.identifier, safe="") if self.provider == "circl" else ""
        )
        if method != "GET" or str(url) != expected or len(self.responses) >= 20:
            raise ValueError(
                "Only bounded exact-ID GET requests to the configured provider contract are allowed"
            )
        if self.provider != "circl" and kwargs.get("params") != request_parameters(
            self.provider, self.identifier
        ):
            raise ValueError("Provider request must name only the selected exact identifier")
        kwargs["follow_redirects"] = False
        with self.http.stream(method, url, **kwargs) as response:
            wrapped = _Response(response, self)
            yield wrapped
            raw = b"".join(wrapped.parts)
            sha = digest(raw)
            self.artifacts[sha] = raw
            self.responses.append(
                {
                    "identifier": self.identifier,
                    "url": str(url),
                    "parameters": copy.deepcopy(kwargs.get("params", {})),
                    "status": response.status_code,
                    "sha256": sha,
                    "representation": "decoded_http_body",
                }
            )


def collect_advisories(settings, provider, identifiers, *, http=None):
    """Collect once, then checkpoint returned JSON and bytes before publishing."""
    enabled(settings, provider)
    if (
        not identifiers
        or len(identifiers) > 20
        or len(set(identifiers)) != len(identifiers)
        or any(not supports_identifier(provider, value) for value in identifiers)
    ):
        raise ValueError("At most 20 distinct exact provider-supported identifiers are supported")

    def collect(transport):
        captured = _Capture(transport, provider)
        results = []
        adapter = ADVISORY_PROVIDERS[provider](captured)
        for identifier in sorted(identifiers):
            enabled(settings, provider)
            captured.identifier = identifier
            try:
                result = adapter.get(identifier)
                response = captured.responses[-1]
                body = _body(provider, captured.artifacts[response["sha256"]], response["status"])
                _verify_result(provider, identifier, result, body, response["status"])
            except (TypeError, KeyError, AttributeError, IndexError, RecursionError) as error:
                raise ValueError("Malformed advisory provider response") from error
            results.append(
                {"identifier": identifier, "response_sha256": response["sha256"], "result": result}
            )
        capture = {
            "format": CAPTURE_FORMAT,
            "provider": provider,
            "identifiers": sorted(identifiers),
            "observed_at": datetime.now(UTC).isoformat(),
            "responses": captured.responses,
            "results": results,
            "raw_artifact_shas": sorted(captured.artifacts),
            "limitations": LIMITATIONS,
        }
        return capture, captured.artifacts

    if http is not None:
        return collect(http)
    with client() as transport:
        return collect(transport)


def publish_advisories(journal, *, settings, project_id, actor_id, data, capture):
    """Merge this frozen batch into the prior provider catalog, never refetch/repin."""
    enabled(settings, data.provider)
    if set(data.identifiers) - baseline_identifiers(
        journal, project_id, data.expected_versions, require_current=False
    ):
        raise ValueError(
            "Refresh identifiers must already be claimed by pinned baseline observations"
        )
    if data.expected_evidence:
        prior_state = journal.verify_state(data.expected_evidence)
        if prior_state.project_id != project_id or prior_state.version != "@evidence":
            raise ValueError("Pinned provider catalog belongs to another product")
    if (
        not isinstance(capture, dict)
        or capture.get("format") != CAPTURE_FORMAT
        or capture.get("provider") != data.provider
        or capture.get("identifiers") != data.identifiers
    ):
        raise ValueError("Frozen advisory capture differs from selected refresh")
    results = capture.get("results")
    responses = capture.get("responses")
    if (
        not isinstance(results, list)
        or not isinstance(responses, list)
        or len(results) != len(data.identifiers)
        or len(responses) != len(results)
        or [item.get("identifier") for item in results if isinstance(item, dict)]
        != data.identifiers
    ):
        raise ValueError("Frozen advisory capture lacks exact complete lookup results")
    artifacts = capture.get("raw_artifact_shas")
    if (
        not isinstance(artifacts, list)
        or len(artifacts) != len(set(artifacts))
        or not all(isinstance(sha, str) for sha in artifacts)
    ):
        raise ValueError("Frozen advisory artifact manifest differs")
    if {item.get("sha256") for item in responses if isinstance(item, dict)} != set(artifacts):
        raise ValueError("Frozen advisory response manifest differs")
    for item, response in zip(results, responses, strict=True):
        if (
            response.get("identifier") != item["identifier"]
            or response.get("sha256") != item.get("response_sha256")
            or response.get("representation") != "decoded_http_body"
        ):
            raise ValueError("Frozen advisory result/response binding differs")
        _verify_result(
            data.provider,
            item["identifier"],
            item.get("result"),
            _body(data.provider, journal.objects.read(item["response_sha256"]), response["status"]),
            response["status"],
        )
    capture_sha = journal.store(capture)
    identity = "dtvp-provider-catalog:" + data.provider
    publisher = PUBLISHERS[data.provider]
    source = "connector:" + data.provider
    # Use the pinned selection, not today's ref, so exact receipt replay works
    # even after another publication has moved the live evidence head.
    records = (
        journal.records(data.expected_evidence, "vulnerabilities") if data.expected_evidence else {}
    )
    active = [
        journal.load(sha) for key, sha in records.items() if key.startswith("evidence-document:")
    ]
    prior = [
        record
        for record in active
        if record.get("active", True)
        and record.get("source") == source
        and record["document"].get("document_id") == identity
        and record["document"].get("publisher") == publisher
    ]
    if len(prior) > 1:
        raise ValueError("Provider catalog has multiple active documents")
    catalog = {
        entry["advisory"]["id"]: copy.deepcopy(entry)
        for entry in (prior[0]["document"]["raw"]["advisories"] if prior else [])
    }
    for item in results:
        identifier, result = item["identifier"], item["result"]
        if result["status"] == "found":
            catalog[identifier] = {
                "advisory": copy.deepcopy(result["advisory"]),
                "raw": {
                    "provider_result": copy.deepcopy(result),
                    "response_sha256": item["response_sha256"],
                    "capture_sha256": capture_sha,
                },
            }
        else:
            catalog.pop(identifier, None)
    document = {
        "format": FORMAT,
        "id": identity,
        "publisher": publisher,
        "advisories": [catalog[key] for key in sorted(catalog)],
        "refresh": {
            "capture_sha256": capture_sha,
            "lookups": [
                {
                    "identifier": item["identifier"],
                    "status": item["result"]["status"],
                    "response_sha256": item["response_sha256"],
                }
                for item in results
            ],
            "limitations": LIMITATIONS,
        },
    }
    return import_evidence(
        journal,
        project_id=project_id,
        actor_id=actor_id,
        data=EvidenceInput(
            request_id=data.request_id,
            expected_evidence=data.expected_evidence,
            expected_versions=data.expected_versions,
            source=source,
            revision=data.revision,
            document=document,
        ),
        additional_artifacts=[*artifacts, capture_sha],
    )
