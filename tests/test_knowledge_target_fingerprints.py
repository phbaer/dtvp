"""Frozen pre-optimization digests guard byte identity, including Unicode/cycles."""

import json
from copy import deepcopy
from pathlib import Path

import pytest

from dtvp.knowledge.assessments import target_fingerprint
from dtvp.knowledge.target_fingerprints import TargetFingerprintBuilder

GOLDENS = json.loads(
    (Path(__file__).parent / "fixtures/knowledge-target-fingerprints.json").read_text()
)["cases"]


@pytest.mark.parametrize("case", GOLDENS, ids=lambda case: case["name"])
def test_prechange_golden_hashes_match_wrapper_and_request_local_builder(case):
    sections, version, context, vulnerability = (
        case[key] for key in ("sections", "version", "context_id", "vulnerability_id")
    )
    before = deepcopy(sections)
    builder = TargetFingerprintBuilder(sections, version)
    assert target_fingerprint(sections, version, context, vulnerability) == case["fingerprint"]
    assert builder.fingerprint(context, vulnerability) == case["fingerprint"]
    assert builder.fingerprint(context, vulnerability) == case["fingerprint"]
    assert sections == before


def baseline():
    case = deepcopy(GOLDENS[0])
    return case, case["sections"]


def test_distinct_claims_and_contexts_share_only_root_fields():
    case, sections = baseline()
    context_id = case["context_id"]
    first = next(iter(sections["vulnerabilities"].values()))
    other = {**deepcopy(first), "identifier": "CVE-2099-9999", "source": "second-provider"}
    sections["vulnerabilities"]["second"] = other
    new_context = deepcopy(sections["ownership"]["context:" + context_id])
    new_context_id = "f" * 64
    new_context["id"] = new_context_id
    new_context["root_basis"] = "different-root-basis"
    new_context["dependency_graph"] = "unknown"
    sections["ownership"]["context:" + new_context_id] = new_context
    builder = TargetFingerprintBuilder(sections, case["version"])
    identifiers = (case["vulnerability_id"], other["identifier"])
    values = {
        builder.fingerprint(context, vulnerability)
        for context in (context_id, new_context_id)
        for vulnerability in identifiers
    }
    for context in (context_id, new_context_id):
        for vulnerability in identifiers:
            assert builder.fingerprint(context, vulnerability) == target_fingerprint(
                sections, case["version"], context, vulnerability
            )
    assert len(values) == 4 and None not in values
    assert builder.cached_roots == 1
    assert builder.fingerprint(context_id, case["vulnerability_id"]) == case["fingerprint"]
    assert builder.fingerprint("missing", identifiers[0]) is None
    assert builder.fingerprint(context_id, "CVE-unknown") is None


def test_source_and_identity_changes_use_new_builder_and_change_digest():
    case, sections = baseline()
    original = TargetFingerprintBuilder(sections, case["version"]).fingerprint(
        case["context_id"], case["vulnerability_id"]
    )
    next(iter(sections["vulnerabilities"].values()))["source"] = "different-provider"
    updated = TargetFingerprintBuilder(sections, case["version"]).fingerprint(
        case["context_id"], case["vulnerability_id"]
    )
    assert updated != original
    # Nightly/source-state bookkeeping remains deliberately excluded.
    for component in sections["inventory"].values():
        if isinstance(component, dict) and "dtvp_origin" in component:
            component["dtvp_origin"]["state"] = "new-nightly"
    assert (
        TargetFingerprintBuilder(sections, case["version"]).fingerprint(
            case["context_id"], case["vulnerability_id"]
        )
        == updated
    )


def test_curated_payload_changes_invalidate_hash_but_wrong_version_does_not_apply():
    case = deepcopy(next(case for case in GOLDENS if case["name"] == "curated_metadata"))
    sections = case["sections"]
    metadata = next(
        value
        for value in sections["history"].values()
        if value.get("payload", {}).get("annotations")
    )
    metadata["payload"]["annotations"]["notes"] = "Changed reviewed cybersecurity context"
    assert (
        TargetFingerprintBuilder(sections, case["version"]).fingerprint(
            case["context_id"], case["vulnerability_id"]
        )
        != case["fingerprint"]
    )
    metadata["payload"]["version"] = "another-version"
    without = TargetFingerprintBuilder(sections, case["version"]).fingerprint(
        case["context_id"], case["vulnerability_id"]
    )
    sections["history"] = {}
    assert (
        TargetFingerprintBuilder(sections, case["version"]).fingerprint(
            case["context_id"], case["vulnerability_id"]
        )
        == without
    )


def test_bounded_lru_eviction_and_oversized_roots_preserve_exact_digests():
    case, sections = baseline()
    original_context = sections["ownership"]["context:" + case["context_id"]]
    root = original_context["root_ref"]
    alternative = "alternative-root"
    sections["inventory"]["component:alternative-root"] = {
        "bom-ref": alternative,
        "name": "Second consuming root",
    }
    sections["inventory"]["dependencies"]["edges"].append(
        {"ref": alternative, "dependsOn": [original_context["component_ref"]]}
    )
    second = {**original_context, "id": "e" * 64, "root_ref": alternative}
    sections["ownership"]["context:" + second["id"]] = second
    normal = TargetFingerprintBuilder(sections, case["version"])
    expected = {
        context: normal.fingerprint(context, case["vulnerability_id"])
        for context in (case["context_id"], second["id"])
    }
    single_sizes = []
    for context in expected:
        builder = TargetFingerprintBuilder(sections, case["version"])
        builder.fingerprint(context, case["vulnerability_id"])
        single_sizes.append(builder.cache_bytes)
    budget = max(single_sizes)
    builder = TargetFingerprintBuilder(sections, case["version"], max_cache_bytes=budget)
    for context in (*expected, *expected):
        assert builder.fingerprint(context, case["vulnerability_id"]) == expected[context]
        assert builder.cache_bytes <= budget and builder.cached_roots == 1
    uncached = TargetFingerprintBuilder(sections, case["version"], max_cache_bytes=1)
    assert (
        uncached.fingerprint(case["context_id"], case["vulnerability_id"])
        == expected[case["context_id"]]
    )
    assert uncached.cache_bytes == uncached.cached_roots == 0
    assert root != alternative
