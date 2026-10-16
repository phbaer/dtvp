"""Pinned supplemental licenses remain separate; /2 preserves material-only scope."""

import copy
import json

import pytest

from dtvp.knowledge import license_reviews as reviews
from dtvp.knowledge.journal import Journal, Ref, Update
from dtvp.knowledge.license_filters import LicenseFilters
from dtvp.knowledge.licenses import license_worklist
from dtvp.knowledge.service import import_inventory
from dtvp.knowledge.workspace import load_sections
from tests.test_knowledge_observations import COLLECTION, bom, ingest, inputs, publish, selected


def branch(journal):
    return journal.resolve(Ref(project_id="product", name="1"))


def snapshot(journal, sections):
    previous = branch(journal)
    state = journal.snapshot(
        project_id="product",
        version="1",
        actor_id="test",
        reason="Fixture change",
        sections=sections,
        parents=[previous],
    )
    journal.publish(
        request_id=state,
        fingerprint=state,
        updates=[Update(ref=Ref(project_id="product", name="1"), expected=previous, target=state)],
    )
    return state


def prepare(tmp_path):
    journal = Journal(tmp_path / "journal")
    document = bom()
    document["components"][0]["licenses"] = [{"license": {"id": "MIT"}}]
    head = (
        import_inventory(
            journal,
            project_id="product",
            version="1",
            actor_id="CI",
            request_id="authority",
            expected=None,
            source="build",
            build_number=1,
            occurred_at="2026-10-16T00:00:00Z",
            sbom=document,
            context=COLLECTION,
        )[1]
        .updates[0]
        .target
    )
    observation = bom("scan-")
    observation["components"][0]["licenses"] = [{"license": {"id": "Apache-2.0"}}]
    observation["components"][0]["properties"] = [
        {"name": "dtvp:spdx-source", "value": json.dumps({"licenseConcluded": "GPL-3.0-only"})}
    ]
    source = ingest(journal, inputs(head, sbom=observation))[1].updates[0].target
    result, _ = publish(journal, selected(journal, head, source))
    return journal, result[1].updates[0].target, source, observation


def disposition(journal, component_ref="lib"):
    value = reviews.LicenseInput(
        request_id="license",
        expected=branch(journal),
        expected_revision=None,
        component_ref=component_ref,
        concluded_expression="LicenseRef-Reviewed",
        disposition="restricted",
        obligations=["Attribution"],
        distribution="Customer binary",
        modification="Unmodified",
        linking="Dynamic",
        rationale="Human terms review",
        provenance={"source": "legal-specialist"},
    )
    reviews.save_license(
        journal,
        project_id="product",
        version="1",
        actor_id="author",
        data=value,
        submit=True,
        authorize=lambda _: None,
    )
    status = reviews.license_status(
        journal, load_sections(journal, branch(journal)), "1", component_ref
    )
    review = reviews.LicenseReviewInput(
        request_id="review-license",
        expected=branch(journal),
        component_ref=component_ref,
        revision=status["assessment"]["revision"],
        action="approve",
        rationale="Independent terms review",
    )
    reviews.review_license(
        journal,
        project_id="product",
        version="1",
        actor_id="reviewer",
        data=review,
        authorize=lambda _: None,
    )
    return reviews.license_status(
        journal, load_sections(journal, branch(journal)), "1", component_ref
    )


def test_pinned_format_separate_evidence_search_and_exact_value_differences(tmp_path):
    journal, state, source, _ = prepare(tmp_path)
    result = license_worklist(journal, state)
    row = next(item for item in result["items"] if item["component_ref"] == "lib")
    assert row["evidence"]["facts"][0]["value"]["license"]["id"] == "MIT"
    supplemental = row["supplemental_evidence"]
    assert supplemental["status"] == "reported" and supplemental["source_claims_differ"]
    assert supplemental["claims"][0]["state"] == source
    pinned = journal.load(journal.records(source, "inventory")["baseline"])
    assert supplemental["claims"][0]["artifact_sha"] == pinned["artifact_sha"]
    assert supplemental["claims"][0]["source_format"] == "cyclonedx-json"
    assert supplemental["claims"][0]["evidence"]["facts"] == [
        {
            "source_field": "licenses",
            "value": {"license": {"id": "Apache-2.0"}},
            "status": "reported",
        }
    ]
    assert "GPL-3.0-only" not in json.dumps(supplemental)
    assert result["statistics"]["by_evidence_status"]["reported"] == 1
    assert result["statistics"]["source_claims_differ"] == 1
    assert LicenseFilters(q="Apache-2.0").matches(row)
    assert not LicenseFilters(evidence_status="unknown").matches(row)
    assert license_worklist(journal, state, limit=1)["statistics"] == result["statistics"]


def test_new_material_approval_survives_nightly_identity_config_and_observation_pointers(tmp_path):
    journal, _, source, document = prepare(tmp_path)
    approved = disposition(journal)
    payload = approved["assessment"]["payload"]
    assert payload["format"] == "dtvp.license-disposition/2"
    assert payload["source_fingerprint_id"] == "dtvp.license-material/2"
    assert payload["source_state"]
    changed = copy.deepcopy(document)
    for component in changed["components"]:
        component["bom-ref"] = component["bom-ref"].replace("scan-", "next-")
    changed["metadata"]["component"]["bom-ref"] = "next-app"
    for edge in changed["dependencies"]:
        edge["ref"] = edge["ref"].replace("scan-", "next-")
        edge["dependsOn"] = [ref.replace("scan-", "next-") for ref in edge["dependsOn"]]
    changed["vulnerabilities"][0]["affects"][0]["ref"] = "next-lib"
    head = branch(journal)
    second = (
        ingest(
            journal,
            inputs(head, request_id="nightly-two", expected=source, build_number=2, sbom=changed),
        )[1]
        .updates[0]
        .target
    )
    publish(journal, selected(journal, head, second, request_id="select-two"))
    sections = load_sections(journal, branch(journal))
    sections["inventory"]["identity"]["bookkeeping_test"] = "new import receipt"
    state = snapshot(journal, sections)
    retained = reviews.license_status(journal, load_sections(journal, state), "1", "lib")
    assert (
        retained["approved"]
        and retained["assessment"]["revision"] == approved["assessment"]["revision"]
    )
    assert reviews.inventory_fingerprint(
        load_sections(journal, state), "1"
    ) != reviews.inventory_fingerprint(load_sections(journal, payload["source_state"]), "1")


@pytest.mark.parametrize(
    "change", ["supplemental_license", "authority_source", "other_component", "graph", "role"]
)
def test_changed_material_revalidates_exact_component_license_approval(tmp_path, change):
    journal, _, _, _ = prepare(tmp_path)
    disposition(journal)
    sections = load_sections(journal, branch(journal))
    if change == "supplemental_license":
        sections["inventory"]["observation_assertions"]["components"]["lib"][0]["component"][
            "licenses"
        ] = [{"license": {"id": "BSD-3-Clause"}}]
        # An altered claim without matching immutable source evidence must fail closed.
        with pytest.raises(ValueError, match="differs from its pinned"):
            reviews.material_fingerprint(journal, sections, "1")
        return
    if change == "authority_source":
        sections["inventory"]["baseline"]["source"] = "different-producer"
    elif change == "other_component":
        sections["inventory"]["root"]["version"] = "2"
    elif change == "graph":
        sections["inventory"]["dependencies"]["edges"][0]["dependsOn"] = []
    else:
        sections["inventory"]["baseline"]["role"] = "observation"
    state = snapshot(journal, sections)
    assert not reviews.license_status(journal, load_sections(journal, state), "1", "lib")[
        "approved"
    ]


def test_legacy_fingerprint_meaning_is_not_rewritten_or_bridged_without_proof(tmp_path):
    journal, _, _, _ = prepare(tmp_path)
    sections = load_sections(journal, branch(journal))
    legacy = {
        "format": reviews.FORMAT,
        "project_id": "product",
        "version": "1",
        "component_ref": "lib",
        "actor_id": "old-author",
        "source_fingerprint": reviews.inventory_fingerprint(sections, "1"),
    }
    key, review_key = reviews.keys("lib")
    revision = journal.store(legacy)
    sections["history"][key] = {"revision": revision, "payload": legacy, "stage": "submitted"}
    sections["history"][review_key] = {"revision": revision, "payload": legacy, "action": "approve"}
    assert reviews.license_status(journal, sections, "1", "lib")["approved"]
    sections["inventory"]["identity"]["new_bookkeeping"] = True
    result = reviews.license_status(journal, sections, "1", "lib")
    assert result["status"] == "stale" and not result["approved"]
    assert "Legacy /1" in result["continuity_diagnostic"]


@pytest.mark.parametrize(
    "change",
    ["unknown_configuration", "configuration_body", "unknown_observation", "source_collection"],
)
def test_unknown_or_changed_context_fields_remain_material(tmp_path, change):
    journal, _, source, _ = prepare(tmp_path)
    sections = load_sections(journal, branch(journal))
    before = reviews.material_fingerprint(journal, sections, "1")
    if change == "unknown_configuration":
        sections["inventory"]["pipeline_configuration"] = {
            "state": "a" * 64,
            "new_license_assumption": "new condition",
        }
    elif change == "configuration_body":
        sections["inventory"]["pipeline_configuration"] = {
            "state": "a" * 64,
            "configuration": {"models": [{"revision": "different-model-context"}]},
        }
    elif change == "unknown_observation":
        sections["inventory"]["observations"]["new_usage_condition"] = "Changed use"
    else:
        # A different pinned source with identical component facts but changed
        # collection/coverage facts still changes the whole license context.
        original = load_sections(journal, source)
        original["inventory"]["baseline"]["collection"]["license_coverage"] = "full"
        changed = journal.snapshot(
            project_id="product",
            version="@observation",
            actor_id="CI",
            reason="Different collection evidence",
            sections=original,
            parents=[source],
            artifacts=journal.state(source).artifacts,
        )
        for values in sections["inventory"]["observation_assertions"]["components"].values():
            for value in values:
                value["state"] = changed
    assert reviews.material_fingerprint(journal, sections, "1") != before


def test_pipeline_state_pin_only_is_immaterial_but_unknown_format_is_not_approved(tmp_path):
    journal, _, _, _ = prepare(tmp_path)
    sections = load_sections(journal, branch(journal))
    sections["inventory"]["pipeline_configuration"] = {
        "state": "a" * 64,
        "configuration": {"models": []},
    }
    before = reviews.material_fingerprint(journal, sections, "1")
    sections["inventory"]["pipeline_configuration"]["state"] = "b" * 64
    assert reviews.material_fingerprint(journal, sections, "1") == before
    disposition(journal)
    sections = load_sections(journal, branch(journal))
    key, review_key = reviews.keys("lib")
    payload = copy.deepcopy(sections["history"][key]["payload"])
    payload["format"] = "dtvp.license-disposition/999"
    revision = journal.store(payload)
    for entry in (key, review_key):
        sections["history"][entry]["payload"] = payload
        sections["history"][entry]["revision"] = revision
    assert not reviews.license_status(journal, sections, "1", "lib")["approved"]


def spdx_document():
    return {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "dataLicense": "CC0-1.0",
        "name": "Synthetic scan",
        "documentNamespace": "https://example.invalid/synthetic/scan",
        "creationInfo": {"creators": ["Tool: synthetic"], "created": "2026-10-16T00:00:00Z"},
        "packages": [
            {
                "SPDXID": "SPDXRef-" + name,
                "name": name,
                "versionInfo": "1",
                "licenseDeclared": "BSD-3-Clause" if name == "extra" else "MIT",
                "licenseConcluded": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:generic/app@1"
                        if name == "app"
                        else "pkg:pypi/" + name + "@1",
                    }
                ],
            }
            for name in ("app", "lib", "extra")
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-app",
            },
            *[
                {
                    "spdxElementId": "SPDXRef-app",
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": "SPDXRef-" + name,
                }
                for name in ("lib", "extra")
            ],
        ],
    }


def test_adopted_spdx_under_cyclonedx_authority_has_only_attributed_supplemental_license(tmp_path):
    journal, state, _, _ = prepare(tmp_path)
    document = spdx_document()
    document["relationships"].append(
        {
            "spdxElementId": "SPDXRef-lib",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": "SPDXRef-extra",
        }
    )
    source = (
        ingest(
            journal,
            inputs(state, request_id="spdx-source", source="spdx-scanner", sbom=document),
        )[1]
        .updates[0]
        .target
    )
    choice = {
        "source": "spdx-scanner",
        "state": source,
        "accepted_components": ["SPDXRef-extra"],
        "accepted_relationships": [
            {"from": "SPDXRef-lib", "to": "SPDXRef-extra", "kind": "DEPENDS_ON"}
        ],
        "reason": "Explicit extra package adoption",
    }
    result, _ = publish(
        journal,
        selected(
            journal,
            state,
            source,
            request_id="select-spdx",
            sources=[choice],
            removal_reason="Replace source view",
        ),
    )
    rows = license_worklist(journal, result[1].updates[0].target)["items"]
    adopted = next(row for row in rows if row["component"]["name"] == "extra")
    assert adopted["inventory_role"] == "adopted_observation"
    assert adopted["evidence"]["status"] == "not_reported" and not adopted["evidence"]["facts"]
    claim = adopted["supplemental_evidence"]["claims"][0]
    assert claim["source_format"] == "spdx-2.3-json"
    assert {fact["source_field"]: fact["value"] for fact in claim["evidence"]["facts"]} == {
        "licenseDeclared": "BSD-3-Clause",
        "licenseConcluded": "NOASSERTION",
    }
    library = next(row for row in rows if row["component_ref"] == "lib")
    assert not library["supplemental_evidence"]["source_claims_differ"]
    assert library["evidence"]["facts"][0]["value"]["license"]["id"] == "MIT"


def test_unproven_component_claim_never_exposes_an_original_artifact_link(tmp_path):
    journal, _, _, _ = prepare(tmp_path)
    sections = load_sections(journal, branch(journal))
    sections["inventory"]["observation_assertions"]["components"]["lib"][0]["component"][
        "licenses"
    ] = [{"license": {"id": "Invented"}}]
    state = snapshot(journal, sections)
    row = next(
        item for item in license_worklist(journal, state)["items"] if item["component_ref"] == "lib"
    )
    claim = row["supplemental_evidence"]["claims"][0]
    assert claim["evidence"]["status"] == "malformed"
    assert claim["artifact_sha"] is None and claim["source_format"] is None
    assert "Invented" not in json.dumps(row["supplemental_evidence"])


def test_supplemental_license_claim_budget_fails_without_truncation(tmp_path, monkeypatch):
    journal, state, _, _ = prepare(tmp_path)
    monkeypatch.setattr("dtvp.knowledge.licenses.MAX_SUPPLEMENTAL_CLAIMS", 0)
    with pytest.raises(ValueError, match="claims exceed bound"):
        license_worklist(journal, state)


@pytest.mark.parametrize("role", ["authority", "observation"])
def test_document_custom_license_terms_are_material_but_nightly_document_ids_are_not(
    tmp_path, role
):
    journal = Journal(tmp_path / "journal")
    if role == "authority":
        document = spdx_document()
        ref = "SPDXRef-lib"
    else:
        document = spdx_document()
        ref = "lib"
        authority_doc = bom()
        head = (
            import_inventory(
                journal,
                project_id="product",
                version="1",
                actor_id="CI",
                request_id="authority",
                expected=None,
                source="build",
                build_number=1,
                occurred_at="2026-10-16T00:00:00Z",
                sbom=authority_doc,
                context=COLLECTION,
            )[1]
            .updates[0]
            .target
        )
    document["hasExtractedLicensingInfos"] = [
        {
            "licenseId": "LicenseRef-Custom",
            "extractedText": "Redistribution permitted with attribution.",
            "new_licensing_condition": "retain unknown definition fields",
        }
    ]
    document["packages"][1]["licenseDeclared"] = "LicenseRef-Custom"
    if role == "authority":
        head = (
            import_inventory(
                journal,
                project_id="product",
                version="1",
                actor_id="CI",
                request_id="authority",
                expected=None,
                source="build",
                build_number=1,
                occurred_at="2026-10-16T00:00:00Z",
                sbom=document,
                context=COLLECTION,
            )[1]
            .updates[0]
            .target
        )
        source = None
    else:
        source = (
            ingest(journal, inputs(head, request_id="source-one", source="scanner", sbom=document))[
                1
            ]
            .updates[0]
            .target
        )
        publish(journal, selected(journal, head, source))
    approved = disposition(journal, ref)
    original_fingerprint = approved["assessment"]["payload"]["source_fingerprint"]

    def update_document(changed, number, old_source):
        head = branch(journal)
        if role == "authority":
            import_inventory(
                journal,
                project_id="product",
                version="1",
                actor_id="CI",
                request_id=f"authority-{number}",
                expected=head,
                source="build",
                build_number=number,
                occurred_at="2026-10-17T00:00:00Z",
                sbom=changed,
                context=COLLECTION,
            )
            return None
        new_source = (
            ingest(
                journal,
                inputs(
                    head,
                    request_id=f"source-{number}",
                    source="scanner",
                    expected=old_source,
                    build_number=number,
                    sbom=changed,
                ),
            )[1]
            .updates[0]
            .target
        )
        publish(journal, selected(journal, head, new_source, request_id=f"select-{number}"))
        return new_source

    unchanged = copy.deepcopy(document)
    unchanged["documentNamespace"] += "/next-night"
    unchanged["creationInfo"]["created"] = "2026-10-17T00:00:00Z"
    source = update_document(unchanged, 2, source)
    current = reviews.license_status(journal, load_sections(journal, branch(journal)), "1", ref)
    assert current["approved"]
    assert current["assessment"]["payload"]["source_fingerprint"] == original_fingerprint
    changed = copy.deepcopy(unchanged)
    changed["hasExtractedLicensingInfos"][0]["extractedText"] = "Redistribution forbidden."
    update_document(changed, 3, source)
    current = reviews.license_status(journal, load_sections(journal, branch(journal)), "1", ref)
    assert current["status"] == "stale" and not current["approved"]
    assert (
        reviews.material_fingerprint(journal, load_sections(journal, branch(journal)), "1")
        != original_fingerprint
    )


def test_unknown_supplemental_assertion_attributes_remain_material(tmp_path):
    journal, _, _, _ = prepare(tmp_path)
    disposition(journal)
    sections = load_sections(journal, branch(journal))
    sections["inventory"]["observation_assertions"]["components"]["lib"][0][
        "new_usage_constraint"
    ] = "Distribution changed"
    state = snapshot(journal, sections)
    assert not reviews.license_status(journal, load_sections(journal, state), "1", "lib")[
        "approved"
    ]
