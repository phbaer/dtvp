"""Bounded retained CPE sources preserve claims without creating decisions."""

import base64
import csv
import io

import pytest

from dtvp.knowledge import cpe_sources as module
from dtvp.knowledge.cpe import DiscoveryInput, current_discovery_policy, import_discovery_policy
from dtvp.knowledge.journal import Conflict, Journal
from dtvp.storage import canonical, digest

CPE = "cpe:2.3:a:vendor:library:*:*:*:*:*:node.js:*:*"


def dictionary(name=CPE):
    return canonical(
        [
            {
                "cpeName": name,
                "cpeNameId": "record-1",
                "source": "synthetic-dictionary",
                "refs": [{"ref": "https://www.npmjs.com/package/library"}],
            }
        ]
    )


def mappings():
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=module.CSV_COLUMNS)
    writer.writeheader()
    for name, purl in (("library", "pkg:npm/library"), ("unidentified", "")):
        writer.writerow(
            {
                "name": name,
                "purl": purl,
                "cpe": CPE,
                "status": "internal",
                "author": "Historical claimed author",
                "options": "historical text",
            }
        )
    return buffer.getvalue().encode()


def arguments(raw=None, **changes):
    raw = dictionary() if raw is None else raw
    return dict(
        project_id="project",
        actor_id="manager",
        data=module.CpeSourceInput(
            **(
                {
                    "request_id": "import-source",
                    "expected": None,
                    "kind": "dictionary",
                    "source": "organization-curated",
                    "revision": "revision-1",
                    "occurred_at": "2026-10-16T12:00:00Z",
                    "reason": "Reviewed offline source capture",
                    "artifact_sha256": digest(raw),
                    "content_base64": base64.b64encode(raw).decode(),
                }
                | changes
            )
        ),
    )


def apply(journal, args):
    preview = module.preview_source(journal, **args)
    return module.apply_source(
        journal,
        **(
            args
            | {
                "data": module.CpeSourceApply(
                    **args["data"].model_dump(), preview_digest=preview["preview_digest"]
                )
            }
        ),
    )


@pytest.fixture
def journal(tmp_path):
    return Journal(tmp_path / "journal")


def test_preview_pure_retains_raw_and_replaces_dictionary_without_adoption(journal):
    args = arguments()
    before = journal.head(), journal.references(), set(journal.objects.root.rglob("*"))
    preview = module.preview_source(journal, **args)
    assert before == (journal.head(), journal.references(), set(journal.objects.root.rglob("*")))
    assert preview["source"]["ordering"] == "expected_head_CAS_only"
    first = apply(journal, args)[1].updates[0].target
    assert journal.objects.read(digest(dictionary())) == dictionary()
    state, config = current_discovery_policy(journal, "project")
    assert state == first and config["catalog"] == [] and config["rules"] == {}
    assert config["retained_dictionary"][0]["cpeName"] == CPE
    assert all(
        not journal.records(state, section) for section in ("assessments", "reviews", "scoring")
    )
    empty = arguments(
        canonical([]), request_id="replace", expected=state, revision="declared-older-revision"
    )
    second = apply(journal, empty)[1].updates[0].target
    assert (
        module.source_report(journal, project_id="project", policy=second, kind="dictionary")[
            "total"
        ]
        == 0
    )
    assert (
        module.source_report(journal, project_id="project", policy=first, kind="dictionary")[
            "total"
        ]
        == 1
    )
    assert digest(dictionary()) in journal.state(second).artifacts


def test_receipt_precedes_decode_and_old_policy_cas(journal, monkeypatch):
    args = arguments()
    preview = module.preview_source(journal, **args)
    applied = args | {
        "data": module.CpeSourceApply(
            **args["data"].model_dump(), preview_digest=preview["preview_digest"]
        )
    }
    first = module.apply_source(journal, **applied)
    import_discovery_policy(
        journal,
        project_id="project",
        actor_id="manager",
        data=DiscoveryInput(request_id="later", expected=first[1].updates[0].target),
    )
    monkeypatch.setattr(module, "decode", lambda _: pytest.fail("receipt must precede decode"))
    assert module.apply_source(journal, **applied) == first
    altered = applied["data"].model_copy(update={"revision": "different"})
    with pytest.raises(Conflict):
        module.apply_source(journal, **(applied | {"data": altered}))


def test_mapping_csv_claims_attributed_unresolved_not_rules_and_raw_pins_survive_regular_edit(
    journal,
):
    dictionary_state = apply(journal, arguments())[1].updates[0].target
    raw = mappings()
    state = (
        apply(
            journal,
            arguments(raw, request_id="csv", expected=dictionary_state, kind="mapping_history"),
        )[1]
        .updates[0]
        .target
    )
    config = module.retained_policy(journal, "project", state)
    assert config["catalog"] == [] and config["rules"] == {}
    assert len(config["retained_dictionary"]) == 1
    rows = module.source_report(
        journal, project_id="project", policy=state, kind="mapping_history", limit=1
    )
    assert rows["total"] == 2 and rows["next_offset"] == 1
    assert rows["items"][0]["claim"]["author"] == "Historical claimed author"
    assert rows["items"][0]["native_approval"] is False
    assert (
        config["retained_mapping_history"][1]["identity_status"]
        == "identity_unresolved_no_name_guess"
    )
    edited = (
        import_discovery_policy(
            journal,
            project_id="project",
            actor_id="manager",
            data=DiscoveryInput(request_id="configure", expected=state),
        )[1]
        .updates[0]
        .target
    )
    assert {digest(raw), digest(dictionary())} <= set(journal.state(edited).artifacts)
    edited_config = module.retained_policy(journal, "project", edited)
    assert edited_config["offline_sources"] == config["offline_sources"]
    assert edited_config["retained_dictionary"] == config["retained_dictionary"]
    assert edited_config["retained_mapping_history"] == config["retained_mapping_history"]
    assert (
        module.source_report(journal, project_id="project", policy=state, kind="mapping_history")[
            "total"
        ]
        == 2
    )
    with pytest.raises(ValueError):
        module.retained_policy(journal, "other-project", state)


def test_retained_dictionary_ranking_is_explicit_and_not_adopted(journal):
    state = apply(journal, arguments())[1].updates[0].target
    result = module.rank_retained(
        journal,
        project_id="project",
        policy=state,
        component={
            "bom-ref": "lib",
            "name": "library",
            "version": "1",
            "purl": "pkg:npm/library@1",
        },
    )
    assert result["policy_state"] == state
    assert result["report"]["selection"] is None
    assert result["report"]["candidates"]


@pytest.mark.parametrize(
    "raw",
    [
        b"not-json",
        canonical([{"cpeName": "broken", "source": "source"}]),
        canonical([{"cpeName": CPE, "deprecated": "false"}]),
        canonical([{"cpeName": CPE}, {"cpeName": CPE}]),
    ],
)
def test_invalid_dictionary_fail_closed(journal, raw):
    before = journal.head(), journal.references()
    with pytest.raises(ValueError):
        module.preview_source(journal, **arguments(raw))
    assert before == (journal.head(), journal.references())


def test_nvd_projection_preserves_exact_raw_and_reports_extra_fields(journal):
    raw = canonical(
        {
            "products": [
                {
                    "cpe": {
                        "cpeName": CPE,
                        "deprecated": False,
                        "titles": [{"title": "Historical title"}],
                    }
                }
            ]
        }
    )
    args = arguments(raw)
    preview = module.preview_source(journal, **args)
    assert preview["source"]["losses"]["projected_extra_dictionary_fields"] == 1
    state = apply(journal, args)[1].updates[0].target
    assert digest(raw) in journal.state(state).artifacts
    assert journal.objects.read(digest(raw)) == raw


@pytest.mark.parametrize("raw", [b"name,cpe,status\na,b,c\n", b"name,name\na,b\n", b"\xff"])
def test_invalid_csv_fails_without_write(journal, raw):
    with pytest.raises(ValueError):
        module.preview_source(journal, **arguments(raw, kind="mapping_history"))
    assert journal.head() is None


def test_bounds_digest_and_preview_cas(journal, monkeypatch):
    monkeypatch.setattr(module, "MAX_RECORDS", 0)
    with pytest.raises(ValueError, match="2,000"):
        module.preview_source(journal, **arguments())
    monkeypatch.setattr(module, "MAX_RECORDS", 2000)
    with pytest.raises(ValueError, match="digest"):
        module.preview_source(journal, **arguments(artifact_sha256="0" * 64))
    args = arguments()
    proposed = module.preview_source(journal, **args)
    apply(journal, arguments(request_id="concurrent"))
    data = module.CpeSourceApply(
        **args["data"].model_dump(), preview_digest=proposed["preview_digest"]
    )
    with pytest.raises(Conflict):
        module.apply_source(journal, **(args | {"data": data}))


def test_retained_history_budget_is_checked_before_decoding_state(journal, monkeypatch):
    state = apply(journal, arguments())[1].updates[0].target
    original = journal.objects.path

    class Oversized:
        def stat(self):
            from types import SimpleNamespace

            return SimpleNamespace(st_size=65 * 1024 * 1024)

    monkeypatch.setattr(
        journal.objects, "path", lambda sha: Oversized() if sha == state else original(sha)
    )
    monkeypatch.setattr(journal, "state", lambda _: pytest.fail("Budget must precede state decode"))
    with pytest.raises(ValueError, match="byte bound"):
        module.retained_policy(journal, "project", state)
