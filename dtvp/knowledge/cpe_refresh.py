"""Opt-in, scoped official CPE capture; publication remains explicit and separate."""

import base64
from datetime import UTC, datetime
from typing import Literal

from pydantic import Field, field_validator

from dtvp.knowledge.journal import Name, Sha
from dtvp.knowledge.legacy_archive import strict_json
from dtvp.knowledge.service import validate_time
from dtvp.schemas import RequestModel
from dtvp.storage import digest

ENDPOINT = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
MAX_BYTES = 2 * 1024 * 1024
MAX_RECORDS = 2000


class CpeAcquisition(RequestModel):
    provider: Literal["nvd"] = "nvd"
    endpoint: Literal["https://services.nvd.nist.gov/rest/json/cpes/2.0"] = ENDPOINT
    keyword: str = Field(min_length=3, max_length=200)
    captured_at: str
    artifact_sha256: Sha

    @field_validator("keyword", mode="before")
    @classmethod
    def meaningful_keyword(cls, value):
        if not isinstance(value, str):
            raise ValueError("CPE keyword must be text")
        if value != value.strip() or any(ord(char) < 32 for char in value):
            raise ValueError("Use a meaningful, trimmed CPE keyword without control characters")
        return value

    @field_validator("captured_at")
    @classmethod
    def aware_time(cls, value):
        return validate_time(value)


class CpeRefreshInput(RequestModel):
    request_id: Name
    expected: Sha | None
    keyword: str = Field(min_length=3, max_length=200)
    reason: str = Field(min_length=1, max_length=2000)

    @field_validator("keyword", mode="before")
    @classmethod
    def meaningful_keyword(cls, value):
        return CpeAcquisition.meaningful_keyword(value)

    @field_validator("reason")
    @classmethod
    def meaningful_reason(cls, value):
        if not value.strip():
            raise ValueError("A meaningful refresh reason is required")
        return value


def validate_acquisition(raw, acquisition):
    """Recheck offline/replayed captures too; declared provenance is not a signature."""
    if len(raw) > MAX_BYTES or digest(raw) != acquisition.artifact_sha256:
        raise ValueError("CPE capture exceeds the byte bound or its digest differs")
    body = strict_json(raw)
    if (
        not isinstance(body, dict)
        or body.get("format") != "NVD_CPE"
        or body.get("version") != "2.0"
    ):
        raise ValueError("Expected an NVD CPE 2.0 response")
    values = body.get("products")
    counts = [body.get(key) for key in ("startIndex", "resultsPerPage", "totalResults")]
    if not isinstance(values, list) or any(type(value) is not int for value in counts):
        raise ValueError("CPE capture has invalid pagination")
    start, per_page, total = counts
    if start != 0 or not 0 <= len(values) <= per_page <= MAX_RECORDS or total != len(values):
        raise ValueError("CPE query is incomplete or exceeds 2,000 records; narrow the keyword")
    return body


def capture(settings, data, *, transport=None, now=None):
    """One bounded GET, no redirects/retries/auto-publication or API-key retention."""
    if "nvd" not in settings.providers_enabled:
        raise ValueError("Enable the nvd provider explicitly before CPE refresh")
    if transport is None:
        from dtvp.providers import client

        transport = client()
    from dtvp.knowledge.cpe_sources import CpeSourceInput

    with transport as remote:
        with remote.stream(
            "GET",
            ENDPOINT,
            params={"keywordSearch": data.keyword, "startIndex": 0, "resultsPerPage": MAX_RECORDS},
            follow_redirects=False,
        ) as response:
            response.raise_for_status()
            raw = bytearray()
            for block in response.iter_bytes():
                if len(raw) + len(block) > MAX_BYTES:
                    raise ValueError("CPE response exceeds 2 MiB; narrow the keyword")
                raw.extend(block)
    raw = bytes(raw)
    captured_at = (now or datetime.now(UTC)).isoformat()
    sha = digest(raw)
    acquisition = CpeAcquisition(keyword=data.keyword, captured_at=captured_at, artifact_sha256=sha)
    validate_acquisition(raw, acquisition)
    return CpeSourceInput(
        request_id=data.request_id,
        expected=data.expected,
        kind="dictionary",
        source="nvd-scoped-query",
        revision=sha,
        occurred_at=captured_at,
        reason=data.reason,
        artifact_sha256=sha,
        content_base64=base64.b64encode(raw).decode(),
        acquisition=acquisition,
    )
