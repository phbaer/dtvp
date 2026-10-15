"""Read-only DT collection, followed by explicit publication of a frozen capture."""

import copy
import json
from contextlib import contextmanager
from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import Field, field_validator

from dtvp.knowledge.composition import CollectionContext
from dtvp.knowledge.journal import Name, Sha
from dtvp.knowledge.service import import_inventory, validate_time
from dtvp.providers import client as provider_client
from dtvp.providers import import_dt
from dtvp.schemas import RequestModel
from dtvp.storage import canonical, digest

FORMAT = "dtvp.dependency-track-capture/1"
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_REQUESTS = 20000
LIMITATIONS = [
    "DT composition, finding pages and individual analyses are separate nontransactional reads; remote snapshot consistency is not established.",
    "Successful pagination establishes retrieved endpoint coverage, not complete software discovery, dependency topology or product coverage.",
    "Historical DT states, comments and identities are attributed source claims, never DTVP human approvals or adopted scores.",
]


class DependencyTrackImportInput(RequestModel):
    request_id: Name
    expected: Sha | None
    build_number: int = Field(ge=0, strict=True)
    occurred_at: str
    context: CollectionContext | None = None
    predecessor: Sha | None = None
    part_id: Name | None = None

    @field_validator("occurred_at")
    @classmethod
    def aware_time(cls, value):
        return validate_time(value)


def _binding(settings, external_project_id):
    endpoint = settings.dt_url.rstrip("/")
    parsed = urlsplit(endpoint)
    if (
        parsed.scheme not in {"https", "http"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not settings.dt_api_key
    ):
        raise ValueError("DT requires a configured deployment URL and read-only API key")
    try:
        identity = str(UUID(str(external_project_id)))
    except ValueError, TypeError, AttributeError:
        raise ValueError("DT requires an explicitly bound external project UUID") from None
    deployment = digest(endpoint.encode())
    return endpoint, identity, deployment, f"dependency-track:{deployment}:{identity}"


class _Response:
    def __init__(self, response, capture):
        self.response = response
        self.capture = capture
        self.parts = []
        self.size = 0
        self.consumed = False

    def __getattr__(self, name):
        return getattr(self.response, name)

    def iter_bytes(self):
        if self.consumed:
            yield from self.parts
            return
        for chunk in self.response.iter_bytes():
            self.size += len(chunk)
            self.capture.total += len(chunk)
            if self.size > MAX_RESPONSE_BYTES or self.capture.total > MAX_CAPTURE_BYTES:
                raise ValueError(
                    "DT response/capture byte limit reached; no baseline may be replaced"
                )
            self.parts.append(chunk)
            yield chunk
        self.consumed = True

    def read(self):
        if not self.consumed:
            list(self.iter_bytes())
        return b"".join(self.parts)

    @property
    def text(self):
        return self.read().decode(self.response.encoding or "utf-8", errors="replace")


class _Capture:
    def __init__(self, http, endpoint):
        self.http = http
        self.prefix = endpoint + "/api/v1/"
        self.total = 0
        self.responses = []
        self.artifacts = {}

    @contextmanager
    def stream(self, method, url, **kwargs):
        if method != "GET" or not str(url).startswith(self.prefix):
            raise ValueError("DT adapter permits only reads from its configured endpoint")
        if len(self.responses) >= MAX_REQUESTS:
            raise ValueError("DT request limit reached; retrieved coverage is incomplete")
        kwargs["follow_redirects"] = False
        with self.http.stream(method, url, **kwargs) as response:
            wrapped = _Response(response, self)
            yield wrapped
            raw = wrapped.read()
            sha = digest(raw)
            self.artifacts[sha] = raw
            self.responses.append(
                {
                    "path": "/api/v1/" + str(url)[len(self.prefix) :],
                    "parameters": copy.deepcopy(kwargs.get("params", {})),
                    "status": response.status_code,
                    "sha256": sha,
                    "representation": "decoded_http_body",
                }
            )


def _validate_finding_identity(bom):
    components = {}

    def visit(values):
        for component in values:
            ref = component.get("bom-ref")
            if not ref or ref in components:
                raise ValueError("DT export has missing or duplicate component references")
            components[ref] = component
            visit(component.get("components", []))

    visit(bom.get("components", []))
    bindings, pairs = {}, set()
    for finding in bom.get("vulnerabilities", []):
        source = json.loads(
            next(
                value["value"]
                for value in finding["properties"]
                if value["name"] == "dtvp:dt-source"
            )
        )
        component, advisory = source["component"], source["vulnerability"]
        pair = (component["uuid"], advisory["uuid"])
        if not all(isinstance(value, str) and value for value in pair) or pair in pairs:
            raise ValueError("DT finding identifiers are absent or repeated across pages")
        pairs.add(pair)
        # Retain every explicit source rating; qualitative severity is not a score.
        ratings = []
        for vector_key, score_key, method in (
            ("cvssV2Vector", "cvssV2BaseScore", "CVSSv2"),
            ("cvssV3Vector", "cvssV3BaseScore", None),
            ("cvssV4Vector", "cvssV4Score", "CVSSv4"),
        ):
            vector, score = advisory.get(vector_key), advisory.get(score_key)
            if vector is not None or score is not None:
                rating = {
                    key: value
                    for key, value in {"vector": vector, "score": score, "method": method}.items()
                    if value is not None
                }
                if advisory.get("severity") is not None:
                    rating["severity"] = advisory["severity"]
                ratings.append(rating)
        if not ratings and advisory.get("severity") is not None:
            ratings.append({"severity": advisory["severity"]})
        finding["ratings"] = ratings
        ref = finding["affects"][0]["ref"]
        exported = components[ref]
        if ref in bindings and bindings[ref] != component["uuid"]:
            raise ValueError("Multiple DT components map ambiguously to one exported reference")
        bindings[ref] = component["uuid"]
        if any(
            component.get(key) and exported.get(key) and component[key] != exported[key]
            for key in ("purl", "name", "version", "group")
        ):
            raise ValueError("DT finding identity conflicts with exported composition")


def collect_dependency_track(settings, external_project_id, *, http=None):
    """Return JSON capture and raw HTTP bodies; caller checkpoints them before publishing."""
    endpoint, identity, deployment, source = _binding(settings, external_project_id)
    started = datetime.now(UTC).isoformat()

    def fetch(transport):
        captured = _Capture(transport, endpoint)
        try:
            sbom = import_dt(captured, endpoint, settings.dt_api_key, identity)
            _validate_finding_identity(sbom)
            # Export and finding API are independently observed channels, including
            # contradictory or absent claims; never collapse them by advisory ID.
            original = json.loads(captured.artifacts[captured.responses[0]["sha256"]])
            exported = original.get("vulnerabilities", [])
            if not isinstance(exported, list):
                raise ValueError("DT exported vulnerabilities must be an array")
            findings = sbom["vulnerabilities"]
            for values, channel in ((findings, "finding-api"), (exported, "sbom-export")):
                for value in values:
                    if not isinstance(value, dict) or not isinstance(
                        value.get("properties", []), list
                    ):
                        raise ValueError("Malformed DT vulnerability observation")
                    value["properties"] = [
                        *[
                            prop
                            for prop in value.get("properties", [])
                            if prop.get("name") != "dtvp:dt-origin"
                        ],
                        {"name": "dtvp:dt-origin", "value": channel},
                    ]
            sbom["vulnerabilities"] = [*findings, *exported]
        except (KeyError, TypeError, AttributeError, StopIteration) as error:
            raise ValueError("Malformed DT export/finding/analysis response") from error
        provenance = {
            "format": "dtvp.dependency-track-intake/1",
            "external_project_id": identity,
            "deployment_sha256": deployment,
            "source": source,
            "fetch_started_at": started,
            "fetch_finished_at": datetime.now(UTC).isoformat(),
            "remote_snapshot_consistent": False,
            "provider_verification": "configured_endpoint_claims_not_independently_attested",
            "responses": captured.responses,
            "limitations": list(LIMITATIONS),
        }
        capture = {
            "format": FORMAT,
            "source": source,
            "sbom": sbom,
            "sbom_sha256": digest(canonical(sbom)),
            "source_provenance": provenance,
            "raw_artifact_shas": sorted(captured.artifacts),
        }
        return capture, captured.artifacts

    if http is not None:
        return fetch(http)
    with provider_client() as transport:
        return fetch(transport)


def publish_dependency_track(
    journal, *, settings, external_project_id, capture, project_id, version, actor_id, data
):
    """Publish only a frozen checkpoint; this function never contacts DT."""
    _, identity, deployment, source = _binding(settings, external_project_id)
    if not isinstance(capture, dict):
        raise ValueError("DT frozen capture must be an object")
    provenance = capture.get("source_provenance", {})
    if (
        capture.get("format") != FORMAT
        or capture.get("source") != source
        or not isinstance(provenance, dict)
        or provenance.get("external_project_id") != identity
        or provenance.get("deployment_sha256") != deployment
        or provenance.get("source") != source
        or provenance.get("remote_snapshot_consistent") is not False
        or not isinstance(capture.get("sbom"), dict)
        or digest(canonical(capture["sbom"])) != capture.get("sbom_sha256")
    ):
        raise ValueError("DT frozen capture or configured source binding differs")
    artifacts, responses = capture.get("raw_artifact_shas"), provenance.get("responses")
    if (
        not isinstance(artifacts, list)
        or not artifacts
        or not all(isinstance(sha, str) for sha in artifacts)
        or len(artifacts) != len(set(artifacts))
    ):
        raise ValueError("DT capture requires distinct raw source artifacts")
    if (
        not isinstance(responses, list)
        or not responses
        or any(
            not isinstance(value, dict)
            or value.get("representation") != "decoded_http_body"
            or not isinstance(value.get("sha256"), str)
            for value in responses
        )
        or {value.get("sha256") for value in responses} != set(artifacts)
    ):
        raise ValueError("DT capture response manifest differs from its raw artifacts")
    capture_sha = journal.store(capture)
    provenance = {**provenance, "capture_sha256": capture_sha}
    artifacts = [*artifacts, capture_sha]
    context = data.context or CollectionContext()
    context = context.model_copy(
        update={
            "collector": context.collector or "Dependency-Track",
            "method": "combined" if context.method == "unknown" else context.method,
            "limitations": list(dict.fromkeys([*context.limitations, *LIMITATIONS])),
        }
    )
    return import_inventory(
        journal,
        project_id=project_id,
        version=version,
        actor_id=actor_id,
        request_id=data.request_id,
        expected=data.expected,
        source=source,
        build_number=data.build_number,
        occurred_at=data.occurred_at,
        sbom=capture["sbom"],
        context=context.model_dump(mode="json"),
        predecessor=data.predecessor,
        part_id=data.part_id,
        source_provenance=provenance,
        additional_artifacts=artifacts,
    )
