"""The assessment use cases work without the web layer."""

import logging
from types import SimpleNamespace

import pytest

from dtvp import dt_cache
from dtvp.assessment_services import (
    AssessmentServiceDeps,
    build_assessment_payloads,
    collect_assessment_conflicts,
    fetch_current_assessment_analyses,
)
from dtvp.assessment_use_cases import (
    AssessmentConflictError,
    AssessmentPermissionError,
    AssessmentRequest,
    AssessmentValidationError,
    save_assessment,
    seen_assessments,
)
from dtvp.logic import calculate_aggregated_state, process_assessment_details

INSTANCE = {
    "project_uuid": "p1",
    "component_uuid": "c1",
    "vulnerability_uuid": "v1",
    "finding_uuid": "f1",
}
SSVC = {"model": "ssvc:DT_DP", "version": "1.0.0", "answers": {}, "rationale": "r"}


@pytest.fixture
def deps():
    logger = logging.getLogger("test")
    service_deps = AssessmentServiceDeps(
        cache_manager=dt_cache.cache_manager,
        logger=logger,
        calculate_aggregated_state=calculate_aggregated_state,
        process_assessment_details=process_assessment_details,
    )
    return SimpleNamespace(
        cache_manager=dt_cache.cache_manager,
        logger=logger,
        code_analysis_result_store=None,
        get_user_role=lambda _user: "ANALYST",
        fetch_current_assessment_analyses=lambda req, client: (
            fetch_current_assessment_analyses(service_deps, req, client)
        ),
        collect_assessment_conflicts=lambda req, analyses: (
            collect_assessment_conflicts(service_deps, req, analyses)
        ),
        build_assessment_payloads=lambda req, user, role: (
            build_assessment_payloads(service_deps, req, user, role)
        ),
    )


def _request(**overrides):
    values = {
        "instances": [dict(INSTANCE)],
        "state": "IN_TRIAGE",
        "details": "Looking into it",
        "team": "Team A",
    }
    values.update(overrides)
    return AssessmentRequest(**values)


async def test_save_persists_locally_and_reports_the_revision(deps):
    seen = []

    async def after_persist(payloads):
        seen.extend(payloads)

    results = await save_assessment(
        deps, _request(), user="alice", client=None, after_persist=after_persist
    )

    assert [r["status"] for r in results] == ["success"]
    assert results[0]["uuid"] == "f1"
    assert results[0]["revision"] == 1
    assert results[0]["sync_status"] == "pending"
    stored = dt_cache.cache_manager.get_assessment_overlay("p1", "c1", "v1")
    assert "Looking into it" in stored["analysisDetails"]
    assert "[Status: Pending Review]" in stored["analysisDetails"]
    assert [payload["details"] for _instance, payload in seen] == [
        stored["analysisDetails"]
    ]


async def test_explicit_role_overrides_the_configured_role(deps):
    deps.get_user_role = lambda _user: "REVIEWER"

    await save_assessment(
        deps, _request(), user="alice", client=None, role="ANALYST"
    )

    stored = dt_cache.cache_manager.get_assessment_overlay("p1", "c1", "v1")
    assert "[Status: Pending Review]" in stored["analysisDetails"]


async def test_ssvc_requires_a_reviewer(deps):
    with pytest.raises(AssessmentPermissionError):
        await save_assessment(
            deps, _request(team="General", ssvc=SSVC), user="alice", client=None
        )
    assert dt_cache.cache_manager.get_assessment_overlay("p1", "c1", "v1") is None


async def test_invalid_ssvc_is_a_validation_error(deps):
    with pytest.raises(AssessmentValidationError):
        await save_assessment(
            deps,
            _request(team="General", ssvc={**SSVC, "version": "unknown"}),
            user="rita",
            client=None,
            role="REVIEWER",
        )


async def test_unknown_analysis_run_is_a_validation_error(deps):
    with pytest.raises(AssessmentValidationError):
        await save_assessment(
            deps, _request(analysis_run_ids=["missing"]), user="alice", client=None
        )
    assert dt_cache.cache_manager.get_assessment_overlay("p1", "c1", "v1") is None


async def test_stale_revision_is_a_conflict(deps):
    await save_assessment(deps, _request(), user="alice", client=None)

    stale = _request(
        details="Second opinion",
        original_analysis={"f1": {"dtvpRevision": 0}},
    )
    with pytest.raises(AssessmentConflictError) as excinfo:
        await save_assessment(deps, stale, user="bob", client=None)

    conflict = excinfo.value.conflicts[0]
    assert conflict["finding_uuid"] == "f1"
    assert "Looking into it" in conflict["current"]["analysisDetails"]
    stored = dt_cache.cache_manager.get_assessment_overlay("p1", "c1", "v1")
    assert "Second opinion" not in stored["analysisDetails"]


def test_the_value_an_edit_was_made_on_is_taken_from_the_request():
    other = {**INSTANCE, "component_uuid": "c2", "finding_uuid": "f2"}
    untracked = {**INSTANCE, "component_uuid": "c3", "finding_uuid": "f3"}
    req = _request(
        instances=[dict(INSTANCE), other, untracked],
        original_analysis={
            "f1": {"analysisState": "IN_TRIAGE", "analysisDetails": "Seen", "isSuppressed": True},
            # Only a revision: says nothing about the text the author saw.
            "f2": {"dtvpRevision": 0},
        },
    )

    assert seen_assessments(req) == {
        ("p1", "c1", "v1"): {"state": "IN_TRIAGE", "details": "Seen", "suppressed": True}
    }
    assert seen_assessments(_request()) == {}
