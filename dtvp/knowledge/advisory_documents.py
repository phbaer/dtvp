"""Known-identifier advisory enrichment, without package or alias matching."""

import copy

from dtvp.parsers import validate_advisory

FORMAT = "dtvp.advisory-feed/1"
MAX_ITEMS = 10_000
LIMITATIONS = [
    "Only exact identifiers already claimed by baseline SBOM/DT component observations are enriched; VEX-only identifiers are excluded.",
    "Aliases, affected ranges, package coordinates and provider claims are retained evidence, not vulnerability matching or applicability conclusions.",
    "Publisher identity, provider authenticity, signatures and source CVSS arithmetic are not verified; original Base assertions are never replaced.",
]


def _identifier(value, field):
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 200
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ValueError(
            f"{field} requires a nonempty bounded identifier without control characters"
        )
    return value


def _objects(value, field):
    if (
        not isinstance(value, list)
        or len(value) > MAX_ITEMS
        or any(not isinstance(item, dict) for item in value)
    ):
        raise ValueError(f"{field} requires a bounded array of objects")
    return value


def advisory_document(document):
    """Normalize explicit advisory fields while preserving each complete entry."""
    # parse_evidence already bounds bytes and rejects duplicate keys/nonfinite JSON.
    pending = [(document, 0)]
    while pending:
        value, depth = pending.pop()
        if depth > 64:
            raise ValueError("Advisory JSON nesting exceeds the supported depth")
        if isinstance(value, dict):
            pending.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)
    identity = _identifier(document.get("id"), "Document id")
    publisher = _identifier(document.get("publisher"), "Publisher")
    statements = []
    for entry in _objects(document.get("advisories"), "Advisories"):
        advisory = entry.get("advisory")
        if not isinstance(advisory, dict) or not isinstance(entry.get("raw"), dict):
            raise ValueError("Each advisory requires normalized advisory and raw provider objects")
        identifier = _identifier(advisory.get("id"), "Advisory id")
        validate_advisory(advisory)
        for alias in _objects(advisory.get("aliases", []), "Aliases"):
            _identifier(alias.get("id"), "Alias id")
        _objects(advisory.get("references", []), "References")
        _objects(advisory.get("ratings", []), "Ratings")
        source = advisory.get("source")
        if source is not None:
            if not isinstance(source, dict):
                raise ValueError("Advisory source must be an object")
            _identifier(source.get("name"), "Advisory source name")
        normalized = {
            key: copy.deepcopy(value)
            for key, value in advisory.items()
            if key in {"id", "source", "description", "ratings", "references", "aliases", "cwes"}
        }
        statements.append(
            {
                "vulnerability_id": identifier,
                "known_identifier_only": True,
                "product_ids": [],
                "purls": [],
                "source_refs": [],
                "status": "reported",
                "normalized_status": None,
                "justification": None,
                "rationale": "",
                "unresolved_reasons": [],
                "raw": {"vulnerability": normalized, "provider_entry": copy.deepcopy(entry)},
            }
        )
    return {
        "format": FORMAT,
        "document_id": identity,
        "publisher": publisher,
        "statements": statements,
        "limitations": list(LIMITATIONS),
    }
