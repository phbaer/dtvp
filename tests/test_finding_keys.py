"""River's finding key: Dependency-Track's matrix, else the same composite."""

from dtvp.code_analysis_result_services import CodeAnalysisResultStore
from dtvp.finding_keys import (
    composite_finding_key,
    finding_key,
    instance_finding_key,
    stored_finding_key,
)


def test_the_key_of_a_source_finding():
    shaped = {"component": {"uuid": "c1"}, "vulnerability": {"uuid": "v1"}}
    assert finding_key("p1", {**shaped, "matrix": "p1:c1:v1"}) == "p1:c1:v1"
    # Without the matrix, the same composite.
    assert finding_key("p1", shaped) == "p1:c1:v1"
    # A source with its own finding UUIDs keeps them.
    assert finding_key("p1", {**shaped, "uuid": "f-1"}) == "f-1"
    assert finding_key("p1", {"component": {"uuid": "c1"}}) is None
    assert finding_key("p1", None) is None


def test_the_key_of_a_grouped_finding_fills_old_snapshots():
    old = {"finding_uuid": None, "project_uuid": "p1", "component_uuid": "c1", "vulnerability_uuid": "v1"}
    assert instance_finding_key(old) == "p1:c1:v1"
    assert instance_finding_key({**old, "finding_uuid": "p1:c1:v1"}) == "p1:c1:v1"
    assert instance_finding_key({"project_uuid": "p1"}) is None
    assert composite_finding_key("p1", "", "v1") is None


def test_keys_stored_by_older_versions_read_in_todays_form(tmp_path):
    assert stored_finding_key("finding:p1:c1:v1") == "p1:c1:v1"
    assert stored_finding_key("p1:c1:v1") == "p1:c1:v1"

    store = CodeAnalysisResultStore(path_provider=lambda: str(tmp_path / "results.sqlite"))
    # The automatic-assessment workflow recorded this form before findings
    # had a key of their own.
    store.record_application(
        analysis_run_id="run-1",
        finding_uuid="finding:p1:c1:v1",
        group_id="CVE-2026-1",
        status="applied",
        applied_by="rita",
        workflow_id="automatic-assessments",
    )
    [application] = store.list_applications(analysis_run_ids=["run-1"])
    assert application["finding_uuid"] == "p1:c1:v1"
