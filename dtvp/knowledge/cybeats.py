"""Vendor-SDK-derived read queries; composition remains a separately supplied SBOM."""

import base64
import hashlib
import hmac
import json
import time
from datetime import UTC, datetime
from urllib.parse import urlsplit

from dtvp.knowledge.evidence_conformance import bounded_tree
from dtvp.knowledge.legacy_archive import strict_json
from dtvp.storage import digest

FORMAT = "dtvp.cybeats-read-capture/1"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
OPERATIONS = (
    ("import_status", "/v1/sboms/imports/getbykey", "id"),
    ("vulnerability_report", "/v1/sboms/componentcatalog/software", "importId"),
)
LIMITATIONS = [
    "The public CyBeats SDK documents these POST queries, not a complete SBOM export or transactional snapshot.",
    "Composition comes from a separately supplied CycloneDX/SPDX file; association with the import ID is an operator declaration.",
    "Uploaded captures are caller-supplied unverified source claims; hashes and readiness codes do not authenticate a provider response.",
    "Reports remain opaque attributed source facts; aggregate IDs, scores and counts never establish component applicability or approvals.",
    "No upload, add-import, scan, signed-URL access, source writeback or automatic HTTP retry is performed.",
]


def identifier(value):
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 200
        or not value.isascii()
        or value != value.strip()
        or any(ord(c) < 33 or ord(c) == 127 for c in value)
    ):
        raise ValueError("CyBeats import ID must be bounded nonempty ASCII without whitespace")
    return value


def origin(value):
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 2048
        or any(ord(c) <= 32 or ord(c) == 127 for c in value)
    ):
        raise ValueError("Invalid CyBeats origin")
    endpoint = value.rstrip("/")
    try:
        parts = urlsplit(endpoint)
        if parts.port is not None and not 1 <= parts.port <= 65535:
            raise ValueError("Invalid port")
    except ValueError:
        raise ValueError("Invalid CyBeats origin") from None
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or parts.path
    ):
        raise ValueError("Configure a CyBeats HTTPS origin without a path or credentials")
    return endpoint


def connection(settings):
    if "cybeats" not in settings.providers_enabled:
        raise ValueError("CyBeats collection is disabled")
    endpoint = origin(settings.cybeats_url)
    if any(
        not isinstance(value, str)
        or not 1 <= len(value) <= 4096
        or not value.isascii()
        or any(ord(c) < 33 or ord(c) == 127 for c in value)
        for value in (settings.cybeats_access_key, settings.cybeats_secret_access_key)
    ):
        raise ValueError("CyBeats source credentials are not configured")
    return endpoint


def signed_request(import_id, operation, access_key, secret_key, *, timestamp):
    identifier(import_id)
    _, path, field = next(item for item in OPERATIONS if item[0] == operation)
    # Matches the vendor SDK: timestamp + JSON.stringify(body), HMAC-SHA256,
    # unpadded base64url. Request bytes and signed bytes are identical.
    raw = json.dumps({field: import_id}, ensure_ascii=False, separators=(",", ":")).encode()
    value = (
        base64.urlsafe_b64encode(
            hmac.new(secret_key.encode(), str(timestamp).encode() + raw, hashlib.sha256).digest()
        )
        .decode()
        .rstrip("=")
    )
    return (
        path,
        raw,
        {
            "Content-Type": "application/json",
            "x-fwup-access-key-id": access_key,
            "x-fwup-dtstmp": str(timestamp),
            "x-fwup-vsig": value,
        },
    )


def validate_capture(capture, *, endpoint, import_id):
    identifier(import_id)
    origin(endpoint)
    if (
        not isinstance(capture, dict)
        or capture.get("format") != FORMAT
        or capture.get("endpoint") != endpoint
        or capture.get("import_id") != import_id
    ):
        raise ValueError("CyBeats capture scope differs from the configured source binding")
    bounded_tree(capture)
    from dtvp.knowledge.service import validate_time

    if not isinstance(capture.get("occurred_at"), str) or len(capture["occurred_at"]) > 100:
        raise ValueError("CyBeats observation time must be text")
    validate_time(capture["occurred_at"])
    responses = capture.get("responses")
    if not isinstance(responses, list) or len(responses) != len(OPERATIONS):
        raise ValueError("CyBeats capture must retain both exact read responses")
    originals = []
    for response, (operation, path, _) in zip(responses, OPERATIONS, strict=True):
        if (
            not isinstance(response, dict)
            or response.get("operation") != operation
            or response.get("path") != path
            or response.get("method") != "POST"
            or type(response.get("status")) is not int
            or response["status"] != 200
        ):
            raise ValueError("CyBeats read response manifest differs")
        encoded = response.get("content_base64")
        if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_RESPONSE_BYTES + 2) // 3):
            raise ValueError("CyBeats response exceeds supported byte bounds")
        try:
            raw = base64.b64decode(encoded, validate=True)
            if len(raw) > MAX_RESPONSE_BYTES or digest(raw) != response.get("sha256"):
                raise ValueError("CyBeats response bytes differ from their hash")
            document = strict_json(raw)
            if not isinstance(document, dict):
                raise ValueError("CyBeats response must be an object")
            bounded_tree(document)
        except RecursionError, UnicodeError:
            raise ValueError("Malformed CyBeats response") from None
        originals.append(raw)
        if operation == "import_status":
            data = document.get("data")
            if (
                not isinstance(data, dict)
                or data.get("id") != import_id
                or type(data.get("status")) is not int
                or type(data.get("enrichmentStatus")) is not int
                or data["status"] != 7110
                or data["enrichmentStatus"] != 7010
            ):
                raise ValueError("CyBeats import is not ready or its returned identity differs")
        elif not isinstance(document.get("entities"), list):
            raise ValueError("CyBeats vulnerability report lacks its documented entity list")
    return originals


def reject_credential_echo(settings, originals):
    """Do not persist known source credentials echoed by an upstream response."""
    credentials = [
        value
        for value in (settings.cybeats_access_key, settings.cybeats_secret_access_key)
        if value
    ]
    for raw in originals:
        pending = [strict_json(raw)]
        while pending:
            item = pending.pop()
            if isinstance(item, dict):
                pending.extend(item.keys())
                pending.extend(item.values())
            elif isinstance(item, list):
                pending.extend(item)
            elif isinstance(item, str) and any(secret in item for secret in credentials):
                raise ValueError("CyBeats response contains configured source credentials")


def collect(settings, import_id, *, http=None, before_request=None, clock=None):
    endpoint = connection(settings)
    identifier(import_id)

    def capture(client):
        responses = []
        for operation, _, _ in OPERATIONS:
            if before_request is not None:
                before_request()
            timestamp = int((clock or time.time)())
            path, raw, headers = signed_request(
                import_id,
                operation,
                settings.cybeats_access_key,
                settings.cybeats_secret_access_key,
                timestamp=timestamp,
            )
            with client.stream(
                "POST", endpoint + path, content=raw, headers=headers, follow_redirects=False
            ) as response:
                response.raise_for_status()
                if response.status_code != 200:
                    raise ValueError("Unsupported CyBeats query response status")
                content = bytearray()
                for block in response.iter_bytes():
                    if len(content) + len(block) > MAX_RESPONSE_BYTES:
                        raise ValueError("CyBeats response exceeds 4 MiB; no baseline changed")
                    content.extend(block)
            responses.append(
                {
                    "operation": operation,
                    "method": "POST",
                    "path": path,
                    "status": 200,
                    "sha256": digest(bytes(content)),
                    "content_base64": base64.b64encode(content).decode(),
                }
            )
        value = {
            "format": FORMAT,
            "endpoint": endpoint,
            "import_id": import_id,
            "occurred_at": datetime.now(UTC).isoformat(),
            "responses": responses,
        }
        originals = validate_capture(value, endpoint=endpoint, import_id=import_id)
        reject_credential_echo(settings, originals)
        return value

    if http is not None:
        return capture(http)
    from dtvp.providers import client

    with client() as transport:
        return capture(transport)
