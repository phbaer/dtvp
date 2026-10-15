"""Offline CPE identity proposals retain provenance without claiming affectedness."""

import copy

import pytest

from dtvp.knowledge.cpe import (
    ALGORITHM_VERSION,
    DiscoveryInput,
    current_discovery_policy,
    import_discovery_policy,
    propose_for_component,
    validate_cpe,
)
from dtvp.knowledge.journal import Conflict, Journal

CPE = "cpe:2.3:a:google:guava:*:*:*:*:*:java:*:*"
COMPONENT = {"bom-ref": "guava", "name": "guava", "version": "33", "purl": "pkg:maven/guava@33"}
RULES = {
    "pkg:maven/guava": {
        "target_purl": "pkg:maven/com.google.guava/guava",
        "source": "POM",
        "reason": "Recovered namespace",
    },
    "pkg:maven/com.google.guava/guava": {
        "cpe": CPE,
        "status": "official",
        "source": "reviewed CSV",
        "reason": "Project identity",
    },
}


def test_reviewed_alias_and_mapping_fixture_preserves_standalone_source_provenance():
    before = copy.deepcopy(RULES)
    result = propose_for_component(COMPONENT, [], RULES)
    assert result["requested_purl"] == "pkg:maven/guava@33"
    assert result["resolved_purl"] == "pkg:maven/com.google.guava/guava@33"
    assert [rule["reason"] for rule in result["reviewed_rules"]] == [
        "Recovered namespace",
        "Project identity",
    ]
    candidate = result["candidates"][0]
    assert candidate["cpe"] == CPE.replace(":guava:*:", ":guava:33:")
    assert candidate["identification_basis"] == "dictionary_supported_identity"
    assert candidate["basis_verification"] == "imported_claim_not_verified"
    assert candidate["applicability"] == "not_assessed"
    assert "confidence" not in candidate and "approved_by" not in candidate
    assert RULES == before


def test_result_digest_is_content_identity_and_input_mutation_does_not_leak():
    first = propose_for_component(COMPONENT, [], RULES)
    second = propose_for_component(COMPONENT, [], RULES)
    assert first == second
    first["reviewed_rules"][0]["reason"] = "tampered"
    first["limitations"].clear()
    third = propose_for_component(COMPONENT, [], RULES)
    assert third == second
    changed = copy.deepcopy(RULES)
    changed["pkg:maven/guava"]["reason"] = "Rechecked identity"
    assert (
        propose_for_component(COMPONENT, [], changed)["content_digest"] != second["content_digest"]
    )
    assert second["algorithm_version"] == ALGORITHM_VERSION
    assert "database_revision" not in second


def test_catalog_exact_identity_qualifiers_subpath_and_versions_remain_distinct():
    purl = "pkg:generic/example/widget@2?arch=amd64#src"
    component = {"name": "widget", "version": "2", "purl": purl}
    cpe = "cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*"
    records = [
        {
            "purl": purl,
            "cpe": cpe,
            "source": "dictionary extract",
            "identification_basis": "dictionary_supported_identity",
        },
        {"purl": purl.replace("amd64", "arm64"), "cpe": cpe, "source": "other architecture"},
        {"purl": purl.replace("@2", "@1"), "cpe": cpe, "source": "other version"},
        {"purl": purl.replace("#src", "#other"), "cpe": cpe, "source": "other subpath"},
    ]
    result = propose_for_component(component, records, {})
    assert len(result["candidates"]) == 1
    assert result["candidates"][0]["provenance"]["source"] == "dictionary extract"
    assert ":widget:2:" in result["candidates"][0]["cpe"]


def test_rule_alias_preserves_qualified_identity_and_rejects_version_changes():
    component = {"purl": "pkg:generic/old@1?arch=amd64#lib", "version": "1"}
    rules = {
        "pkg:generic/old?arch=amd64#lib": {
            "target_purl": "pkg:generic/new",
            "source": "reviewed CSV",
        }
    }
    result = propose_for_component(component, [], rules)
    assert result["resolved_purl"] == "pkg:generic/new@1?arch=amd64#lib"
    rules["pkg:generic/old?arch=amd64#lib"]["target_purl"] = "pkg:generic/new@2"
    with pytest.raises(ValueError, match="package version"):
        propose_for_component(component, [], rules)


def test_name_only_requests_do_not_generate_or_match_guesses():
    result = propose_for_component({"name": "guava", "version": "33"}, [], RULES)
    assert result["requested_purl"] is None and result["resolved_purl"] is None
    assert result["candidates"] == []
    assert any("not ported" in item for item in result["limitations"])


def test_source_reported_cpe_is_unverified_and_not_replaced_in_component():
    component = {
        "name": "widget",
        "version": "1",
        "cpe": "cpe:2.3:a:example:widget:1:update1:*:*:*:*:*:*",
    }
    original = copy.deepcopy(component)
    result = propose_for_component(component, [], {})
    assert result["candidates"][0]["cpe"] == component["cpe"]
    assert result["candidates"][0]["identification_basis"] == "source_reported_identity"
    assert component == original


def test_conflicting_explicit_cpe_versions_are_rejected_not_rewritten():
    catalog = [
        {
            "purl": "pkg:generic/widget",
            "cpe": "cpe:2.3:a:example:widget:1:*:*:*:*:*:*:*",
            "source": "catalog",
        }
    ]
    result = propose_for_component({"purl": "pkg:generic/widget@2", "version": "2"}, catalog, {})
    assert result["candidates"] == []
    assert (
        result["rejected_candidates"][0]["reason"]
        == "explicit_cpe_version_conflicts_with_package_version"
    )
    with pytest.raises(ValueError, match="contradicts"):
        propose_for_component({"purl": "pkg:generic/widget@2", "version": "1"}, [], {})


def test_cyclic_aliases_and_conflicting_rule_actions_rejected():
    cycle = {
        "pkg:generic/a": {"target_purl": "pkg:generic/b", "source": "CSV"},
        "pkg:generic/b": {"target_purl": "pkg:generic/a", "source": "CSV"},
    }
    with pytest.raises(ValueError, match="Cyclic"):
        propose_for_component({"purl": "pkg:generic/a@1"}, [], cycle)
    with pytest.raises(ValueError, match="exactly one"):
        propose_for_component(
            COMPONENT,
            [],
            {"pkg:maven/guava": {"target_purl": "pkg:maven/other", "cpe": CPE, "source": "CSV"}},
        )


@pytest.mark.parametrize(
    "value",
    [
        "cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*",
        r"cpe:2.3:a:vendor:product\:name:1.2\+build:*:*:*:*:*:*:*",
        "cpe:/a:vendor:product:1.2%2bbuild",
        "cpe:/a:vendor:product:1:update:~edition~sw~linux~x86~other:en-us",
    ],
)
def test_supported_cpe_bindings_preserve_escaped_separators_and_uri(value):
    parsed = validate_cpe(value)
    assert parsed["binding"] in {"formatted_string", "uri"}


@pytest.mark.parametrize(
    "value",
    [
        "not-a-cpe",
        "cpe:2.3:a:vendor:product",
        "cpe:2.3:z:vendor:product:1:*:*:*:*:*:*:*",
        "cpe:2.3:a:vendor::1:*:*:*:*:*:*:*",
        "cpe:/a:vendor:product:%ZZ",
        "cpe:/a:vendor:product:space here",
        "cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:\\",
        "cpe:/a:vendor:product\n",
        "cpe:/a:vendor:product:%00",
        "cpe:2.3:a:vendor:pro*duct:1:*:*:*:*:*:*:*",
    ],
)
def test_malformed_or_unsupported_cpe_binding_rejected(value):
    with pytest.raises(ValueError):
        validate_cpe(value)


def test_uri_template_expansion_escapes_version_without_formatted_string_conversion():
    catalog = [{"purl": "pkg:generic/widget", "cpe": "cpe:/a:example:widget", "source": "catalog"}]
    result = propose_for_component(
        {"purl": "pkg:generic/widget@1%2Bpatch", "version": "1+patch"}, catalog, {}
    )
    assert result["candidates"][0]["cpe"] == "cpe:/a:example:widget:1%2Bpatch"
    assert result["candidates"][0]["source_cpe"] == "cpe:/a:example:widget"


def test_explicit_policy_import_is_immutable_cas_idempotent_and_does_not_create_branches(tmp_path):
    journal = Journal(tmp_path / "journal")
    data = DiscoveryInput(request_id="cpe-1", expected=None, catalog=[], rules=RULES)
    receipt = import_discovery_policy(journal, project_id="project", actor_id="admin", data=data)
    first, config = current_discovery_policy(journal, "project")
    assert first
    assert config["rules"]["pkg:maven/guava"]["source"] == "POM"
    assert all(update.ref.kind == "policy" for update in receipt[1].updates)
    before = journal.head()
    assert (
        import_discovery_policy(journal, project_id="project", actor_id="admin", data=data)
        == receipt
    )
    assert journal.head() == before
    with pytest.raises(Conflict):
        import_discovery_policy(
            journal,
            project_id="project",
            actor_id="admin",
            data=data.model_copy(update={"request_id": "stale"}),
        )
    changed = copy.deepcopy(RULES)
    changed["pkg:maven/guava"]["reason"] = "New mapping rationale"
    replacement = DiscoveryInput(request_id="cpe-2", expected=first, catalog=[], rules=changed)
    import_discovery_policy(journal, project_id="project", actor_id="admin", data=replacement)
    second, newer = current_discovery_policy(journal, "project")
    assert second != first and first in journal.state(second).parents
    assert newer["rules_content_digest"] != config["rules_content_digest"]
    old = journal.load(journal.records(first, "inventory")["cpe:configuration"])
    assert old == config
