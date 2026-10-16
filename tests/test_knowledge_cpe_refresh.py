"""Official scoped capture is bounded, reproducible and separate from adoption."""

import base64
import json
from datetime import UTC, datetime
from types import SimpleNamespace

import httpx
import pytest

from dtvp.knowledge import cpe_refresh as module
from dtvp.knowledge.cpe import current_discovery_policy
from dtvp.knowledge.cpe_sources import CpeSourceApply, apply_source, preview_source
from dtvp.knowledge.journal import Journal
from dtvp.storage import digest
from tests.test_knowledge_cpe_sources import CPE


def body(**changes):
    return {
        "format": "NVD_CPE",
        "version": "2.0",
        "startIndex": 0,
        "resultsPerPage": 1,
        "totalResults": 1,
        "products": [
            {
                "cpe": {
                    "cpeName": CPE,
                    "cpeNameId": "synthetic-1",
                    "titles": [{"title": "Unprojected original evidence", "lang": "en"}],
                }
            }
        ],
    } | changes


def request(**changes):
    return module.CpeRefreshInput.model_validate(
        {
            "request_id": "capture",
            "expected": None,
            "keyword": "library",
            "reason": "Refresh scoped dictionary evidence",
        }
        | changes
    )


def capture(payload=None, *, status=200, enabled=True):
    raw = json.dumps(body() if payload is None else payload).encode()
    seen = []

    def respond(req):
        seen.append(req)
        return httpx.Response(status, content=raw)

    result = module.capture(
        SimpleNamespace(providers_enabled=["nvd"] if enabled else []),
        request(),
        transport=httpx.Client(transport=httpx.MockTransport(respond)),
        now=datetime(2026, 10, 16, tzinfo=UTC),
    )
    return result, raw, seen


def test_capture_retains_exact_source_and_publication_does_not_create_mapping(tmp_path):
    data, raw, seen = capture()
    assert str(seen[0].url).startswith(module.ENDPOINT + "?")
    assert dict(seen[0].url.params) == {
        "keywordSearch": "library",
        "startIndex": "0",
        "resultsPerPage": "2000",
    }
    assert base64.b64decode(data.content_base64) == raw
    assert data.acquisition.artifact_sha256 == digest(raw)
    journal = Journal(tmp_path / "journal")
    before = journal.head()
    preview = preview_source(journal, project_id="p", actor_id="manager", data=data)
    assert journal.head() == before
    assert preview["source"]["coverage"] == "complete_returned_keyword_subset_not_full_dictionary"
    receipt = apply_source(
        journal,
        project_id="p",
        actor_id="manager",
        data=CpeSourceApply(**data.model_dump(), preview_digest=preview["preview_digest"]),
    )
    state, config = current_discovery_policy(journal, "p")
    assert receipt[1].updates[0].target == state
    assert config["rules"] == {} and config["catalog"] == []
    assert config["retained_dictionary"][0]["cpeName"] == CPE
    assert journal.objects.read(data.artifact_sha256) == raw
    assert journal.records(state, "reviews") == {}
    assert config["offline_sources"]["dictionary"]["acquisition"]["keyword"] == "library"


@pytest.mark.parametrize(
    "changes",
    [
        {"totalResults": 2001},
        {"totalResults": 2},
        {"startIndex": 1},
        {"resultsPerPage": True},
        {"totalResults": True},
        {"resultsPerPage": 0},
        {"resultsPerPage": 2001},
        {"format": "NVD_CVE"},
        {"version": "3.0"},
    ],
)
def test_truncated_or_malformed_captures_fail(changes):
    with pytest.raises(ValueError):
        capture(body(**changes))


def test_empty_complete_query_is_explicit_not_absence_of_vulnerabilities():
    data, _, _ = capture(body(products=[], totalResults=0, resultsPerPage=0))
    assert data.acquisition is not None


def test_disabled_provider_makes_no_request():
    with pytest.raises(ValueError, match="Enable"):
        capture(enabled=False)


@pytest.mark.parametrize("status", [302, 429, 503])
def test_no_redirect_following_or_automatic_retry(status):
    with pytest.raises(httpx.HTTPStatusError):
        capture(status=status)


def test_response_byte_bound_and_original_digest_rechecked(monkeypatch):
    monkeypatch.setattr(module, "MAX_BYTES", 12)
    with pytest.raises(ValueError, match="exceeds"):
        capture()
    monkeypatch.undo()
    data, raw, _ = capture()
    with pytest.raises(ValueError, match="digest"):
        module.validate_acquisition(raw + b" ", data.acquisition)


@pytest.mark.parametrize("keyword", ["  library", "library\n", "   ", "ab"])
def test_query_must_be_explicit_and_bounded(keyword):
    with pytest.raises(ValueError):
        request(keyword=keyword)


def test_offline_replay_cannot_bypass_complete_query_validation(tmp_path):
    data, _, _ = capture()
    raw = json.dumps(body(totalResults=2)).encode()
    altered = data.model_copy(
        update={
            "content_base64": base64.b64encode(raw).decode(),
            "artifact_sha256": digest(raw),
            "acquisition": data.acquisition.model_copy(update={"artifact_sha256": digest(raw)}),
        }
    )
    with pytest.raises(ValueError, match="incomplete"):
        preview_source(
            Journal(tmp_path / "journal"), project_id="p", actor_id="manager", data=altered
        )


def test_legacy_request_fingerprint_omits_new_absent_acquisition():
    from dtvp.knowledge.cpe_sources import identity
    from dtvp.storage import canonical
    from tests.test_knowledge_cpe_sources import arguments

    args = arguments()
    old_payload = args["data"].model_dump(mode="json", exclude={"acquisition"})
    assert identity(args["project_id"], args["actor_id"], args["data"])[1] == digest(
        canonical(["cpe.offline-source/1", args["project_id"], args["actor_id"], old_payload])
    )
