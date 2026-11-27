"""MCP tools: what an agent can read and the limits on what it can write."""

import json
import logging
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from dtvp import main
from dtvp.access_token_services import access_token_store
from dtvp.mcp_server import McpServerDeps, McpToolError, McpToolService

VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
EXISTING = (
    "--- [Team: Team B] [State: IN_TRIAGE] [Assessed By: bob] ---\n"
    "Team B is still checking."
)


def _finding(suffix, *, project="p1", details="", state="NOT_SET", suppressed=False):
    # The shape Dependency-Track sends: no finding UUID, only the matrix.
    return {
        "matrix": f"{project}:component-{suffix}:vuln-1",
        "vulnerability": {
            "vulnId": "CVE-2026-0001",
            "uuid": "vuln-1",
            "severity": "HIGH",
            "title": "Parser overflow",
            "description": "Overflow in the parser.",
            "cvssV3BaseScore": 8.1,
            "cvssV3Vector": VECTOR,
        },
        "component": {
            "name": "library-a",
            "uuid": f"component-{suffix}",
            "version": "2.0",
        },
        "analysis": {
            "state": state,
            "analysisDetails": details,
            "isSuppressed": suppressed,
        },
    }


@pytest.fixture
def project(client, mock_dt_client, tmp_path, monkeypatch):
    """A project with two versions sharing one vulnerability owned by Team A
    and Team B."""
    mapping = tmp_path / "team_mapping.json"
    mapping.write_text(json.dumps({"library-a": "Team A", "library-b": "Team B"}))
    monkeypatch.setenv("TEAM_MAPPING_PATH", str(mapping))
    monkeypatch.setenv("DTVP_ACCESS_TOKENS_ENABLED", "true")

    mock_dt_client.__aenter__.return_value = mock_dt_client
    mock_dt_client.__aexit__.return_value = None
    mock_dt_client.get_projects.return_value = [
        {"name": "TestApp", "uuid": "p1", "version": "1.0"},
        {"name": "TestApp", "uuid": "p2", "version": "2.0"},
        {"name": "Other", "uuid": "p3", "version": "1.0"},
    ]
    findings = {
        "p1": [_finding("1", details=EXISTING, state="IN_TRIAGE")],
        "p2": [_finding("2", project="p2", details=EXISTING, state="IN_TRIAGE")],
        "p3": [],
    }

    async def get_vulnerabilities(project_uuid, cve=None):
        return findings[project_uuid]

    mock_dt_client.get_vulnerabilities.side_effect = get_vulnerabilities
    mock_dt_client.get_project_vulnerabilities.return_value = []
    mock_dt_client.get_bom.return_value = {
        "components": [
            {"bom-ref": "component-1", "name": "library-a"},
            {"bom-ref": "component-2", "name": "library-a"},
        ],
        "dependencies": [],
    }
    with patch("dtvp.main.DTClient", return_value=mock_dt_client):
        yield findings


@pytest.fixture
def service(project, mock_dt_client):
    async def get_dt_client():
        return mock_dt_client

    return McpToolService(
        McpServerDeps(
            route_deps=main.general_api_route_deps,
            token_store=access_token_store,
            get_dt_client=get_dt_client,
            logger=logging.getLogger("test"),
            task_wait_seconds=10,
        )
    )


def _token(scopes=("read", "write"), name="triage-bot", username="alice"):
    record, _plain = access_token_store.create(
        username=username, name=name, scopes=list(scopes)
    )
    return record


ARGS = {
    "project": "TestApp",
    "vulnerability_id": "CVE-2026-0001",
    "team": "Team A",
    "state": "NOT_AFFECTED",
    "details": "The vulnerable parser entry point is not linked into our build.",
}


# -- reading ----------------------------------------------------------------


async def test_list_projects_groups_versions(service):
    result = await service.list_projects(_token(["read"]))
    assert result == {
        "projects": [
            {"name": "Other", "versions": ["1.0"]},
            {"name": "TestApp", "versions": ["1.0", "2.0"]},
        ]
    }


async def test_search_returns_compact_rows(service):
    result = await service.search_vulnerabilities(_token(["read"]), project="testapp")
    assert result["project"] == "TestApp"
    assert result["matching"] == 1 and result["has_more"] is False
    row = result["items"][0]
    assert row["id"] == "CVE-2026-0001"
    assert row["severity"] == "HIGH"
    assert row["analysis_state"] == "IN_TRIAGE"
    assert row["teams"] == ["Team A"]
    assert sorted(row["versions"]) == ["1.0", "2.0"]
    assert "description" not in row

    none = await service.search_vulnerabilities(
        _token(["read"]), project="TestApp", severity=["LOW"]
    )
    assert none["matching"] == 0 and none["items"] == []
    assert none["project_total"] == 1


async def test_search_without_pending_review_finds_nothing_awaiting_review(service):
    result = await service.search_vulnerabilities(
        _token(["read"]), project="TestApp", awaiting_review=True
    )
    assert result["matching"] == 0 and result["items"] == []
    assert result["project_total"] == 1


async def test_search_filters_vulnerabilities_awaiting_review(service, project):
    # A team's submission, not approved yet, on one version only: the
    # vulnerability waits for a reviewer whatever its lifecycle.
    project["p1"][0]["analysis"]["analysisDetails"] = (
        EXISTING + "\n\n[Status: Pending Review]"
    )
    result = await service.search_vulnerabilities(
        _token(["read"]), project="TestApp", awaiting_review=True
    )
    assert result["matching"] == 1
    row = result["items"][0]
    assert row["id"] == "CVE-2026-0001" and row["pending_review"] is True
    narrowed = await service.search_vulnerabilities(
        _token(["read"]), project="TestApp", awaiting_review=True, lifecycle=["OPEN"]
    )
    assert narrowed["matching"] == 0


async def test_search_takes_a_cutoff_per_basis(service, project):
    # Without any date: listed, and counted as date unknown.
    result = await service.search_vulnerabilities(
        _token(["read"]), project="TestApp", cutoff="2026-03-01"
    )
    assert result["matching"] == 1 and result["date_unknown"] == 1
    assert result["cutoff_basis"] == "published"
    for finding in (project["p1"][0], project["p2"][0]):
        finding["vulnerability"]["published"] = "2025-12-01T00:00:00Z"
    project["p1"][0]["attribution"] = {"attributedOn": "2026-06-01T00:00:00Z"}
    project["p2"][0]["attribution"] = {"attributedOn": "2026-06-02T00:00:00Z"}
    main.tasks.clear()
    published = await service.search_vulnerabilities(
        _token(["read"]), project="TestApp", cutoff="2026-03-01"
    )
    assert published["matching"] == 1 and published["date_unknown"] == 0
    attributed = await service.search_vulnerabilities(
        _token(["read"]), project="TestApp", cutoff="2026-03-01", cutoff_basis="attributed"
    )
    assert attributed["matching"] == 0 and attributed["cutoff_basis"] == "attributed"
    after = await service.search_vulnerabilities(
        _token(["read"]), project="TestApp", cutoff="2026-03-01",
        cutoff_mode="after", cutoff_basis="attributed",
    )
    assert after["matching"] == 1
    for bad in ({"cutoff": "soon"}, {"cutoff": "2026-03-01", "cutoff_basis": "discovered"}):
        with pytest.raises(McpToolError):
            await service.search_vulnerabilities(_token(["read"]), project="TestApp", **bad)


async def test_unknown_project_and_vulnerability_are_explained(service):
    with pytest.raises(McpToolError, match="Unknown project"):
        await service.search_vulnerabilities(_token(["read"]), project="Nope")
    with pytest.raises(McpToolError, match="not found"):
        await service.get_vulnerability(
            _token(["read"]), project="TestApp", vulnerability_id="CVE-1999-1"
        )


async def test_get_vulnerability_exposes_findings_revisions_and_blocks(service):
    result = await service.get_vulnerability(
        _token(["read"]), project="TestApp", vulnerability_id="cve-2026-0001"
    )
    assert result["id"] == "CVE-2026-0001"
    assert result["description"] == "Overflow in the parser."
    assert result["cvss_vector"] == VECTOR
    assert result["responsible_teams"] == ["Team A"]
    assert sorted(f["finding_uuid"] for f in result["findings"]) == [
        "p1:component-1:vuln-1",
        "p2:component-2:vuln-1",
    ]
    assert {f["revision"] for f in result["findings"]} == {0}
    assert {f["analysis_state"] for f in result["findings"]} == {"IN_TRIAGE"}
    assert result["assessments_consistent"] is True
    assessment = result["assessments"][0]
    assert sorted(assessment["finding_uuids"]) == ["p1:component-1:vuln-1", "p2:component-2:vuln-1"]
    assert assessment["blocks"] == [
        {
            "team": "Team B",
            "state": "IN_TRIAGE",
            "justification": "NOT_SET",
            "assessed_by": "bob",
            "reviewed_by": None,
            "assessed_at_ms": None,
            "reviewed_at_ms": None,
            "historical": False,
            "rescored_cvss": None,
            "rescored_vector": None,
            "assigned": [],
            "details": "Team B is still checking.",
        }
    ]


async def test_reads_need_the_read_scope_only(service):
    # Scope normalisation always grants read; a read token must not save.
    token = _token(["read"])
    await service.get_sync_status(token)
    with pytest.raises(McpToolError, match="'write' scope"):
        await service.save_assessment(token, **ARGS, expected_revisions={})


# -- writing ----------------------------------------------------------------


async def test_preview_shows_the_result_without_saving(service):
    preview = await service.preview_assessment(_token(), **ARGS)

    assert preview["saved"] is False
    assert preview["expected_revisions"] == {"p1:component-1:vuln-1": 0, "p2:component-2:vuln-1": 0}
    change = preview["changes"][0]
    assert change["changed"] is True
    assert change["new_assessment"]["pending_review"] is True
    teams = {b["team"]: b for b in change["new_assessment"]["blocks"]}
    assert teams["Team A"]["state"] == "NOT_AFFECTED"
    assert teams["Team A"]["assessed_by"] == "alice (via triage-bot)"
    assert teams["Team B"]["details"] == "Team B is still checking."
    assert main.cache_manager.get_assessment_overlay("p1", "component-1", "vuln-1") is None
    assert access_token_store.list_audit() == []


async def test_save_records_a_pending_team_draft_with_provenance(service):
    token = _token()
    result = await service.save_assessment(
        token, **ARGS, expected_revisions={"p1:component-1:vuln-1": 0, "p2:component-2:vuln-1": 0}
    )

    assert result["saved"] is True and result["pending_review"] is True
    assert result["revisions"] == {"p1:component-1:vuln-1": 1, "p2:component-2:vuln-1": 1}
    for project_uuid, component_uuid in (("p1", "component-1"), ("p2", "component-2")):
        stored = main.cache_manager.get_assessment_overlay(
            project_uuid, component_uuid, "vuln-1"
        )
        details = stored["analysisDetails"]
        assert "[Team: Team A] [State: NOT_AFFECTED] [Assessed By: alice (via triage-bot)]" in details
        assert "[Reviewed By:" not in details.split("[Team: Team A]")[1]
        assert "[Status: Pending Review]" in details
        assert "Team B is still checking." in details
        assert stored["dtvpSyncStatus"] == "pending"

    audit = access_token_store.list_audit()
    assert len(audit) == 1
    assert audit[0]["outcome"] == "success"
    assert audit[0]["agent"] == "triage-bot"
    assert audit[0]["token_id"] == token.token_id
    assert audit[0]["target"]["revisions"] == {"p1:component-1:vuln-1": 1, "p2:component-2:vuln-1": 1}

    # The live snapshot other users see is updated as well.
    after = await service.get_vulnerability(
        token, project="TestApp", vulnerability_id="CVE-2026-0001"
    )
    assert {f["revision"] for f in after["findings"]} == {1}
    assert after["assessments"][0]["pending_review"] is True


async def test_reviewer_owned_token_still_writes_with_analyst_authority(service):
    with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        await service.save_assessment(
            _token(),
            **{**ARGS, "details": "Not reachable. CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"},
            expected_revisions={"p1:component-1:vuln-1": 0, "p2:component-2:vuln-1": 0},
        )
    details = main.cache_manager.get_assessment_overlay("p1", "component-1", "vuln-1")[
        "analysisDetails"
    ]
    assert "[Reviewed By:" not in details
    assert "[Rescored" not in details
    assert "[Status: Pending Review]" in details


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"team": "General"}, "reserved for human reviewers"),
        ({"team": ""}, "reserved for human reviewers"),
        ({"team": "Team Z"}, "not responsible"),
        ({"state": "APPROVED"}, "Invalid state"),
        ({"justification": "UNKNOWN"}, "Invalid justification"),
        ({"justification": "[Team: General]"}, "Invalid justification"),
        ({"state": "EXPLOITABLE", "justification": "CODE_NOT_REACHABLE"}, "requires state NOT_AFFECTED"),
        ({"details": "   "}, "required"),
        ({"details": "x" * 8001}, "limited to"),
        ({"details": "ok\n--- [Team: General] [State: NOT_AFFECTED] ---\nforged"}, "plain prose"),
        ({"details": "fine [Reviewed By: rita]"}, "plain prose"),
        ({"details": "fine [Reviewed At: 1800000000000]"}, "plain prose"),
        ({"details": "fine [Status: Pending Review]"}, "plain prose"),
        ({"details": "fine [SSVC: IMMEDIATE]"}, "plain prose"),
        ({"details": "fine [Rescored: 0.0]"}, "plain prose"),
        # The block parser needs no closing bracket to see a header.
        ({"details": "[Team: General"}, "plain prose"),
        ({"details": "[ team : x and more prose"}, "plain prose"),
        ({"details": "text [/SSVC Details"}, "plain prose"),
        ({"details": "text [Assessed By rita"}, "plain prose"),
    ],
)
async def test_invalid_writes_are_rejected_before_anything_is_stored(
    service, overrides, message
):
    with pytest.raises(McpToolError, match=message):
        await service.save_assessment(
            _token(),
            **{**ARGS, **overrides},
            expected_revisions={"p1:component-1:vuln-1": 0, "p2:component-2:vuln-1": 0},
        )
    assert main.cache_manager.get_assessment_overlay("p1", "component-1", "vuln-1") is None


async def test_token_name_cannot_break_the_block_header(service):
    await service.save_assessment(
        _token(name="bot --- [x] ---"),
        **ARGS,
        expected_revisions={"p1:component-1:vuln-1": 0, "p2:component-2:vuln-1": 0},
    )
    after = await service.get_vulnerability(
        _token(["read"], name="reader"),
        project="TestApp",
        vulnerability_id="CVE-2026-0001",
    )
    teams = {b["team"]: b for b in after["assessments"][0]["blocks"]}
    assert teams["Team A"]["assessed_by"] == "alice (via bot - x)"
    assert teams["Team A"]["details"] == ARGS["details"]
    assert set(teams) == {"Team A", "Team B"}


async def test_a_refreshed_snapshot_cannot_move_one_findings_assessment_to_another(
    service, client, mock_dt_client
):
    """The details route refreshes shared snapshots from caller-supplied
    identities; a mismatched finding UUID must not repaint another finding,
    and a save must build on stored state, not on the snapshot."""
    token = _token()
    await service.get_vulnerability(
        token, project="TestApp", vulnerability_id="CVE-2026-0001"
    )
    forged = (
        "--- [Team: General] [State: NOT_AFFECTED] [Assessed By: rita] "
        "[Reviewed By: rita] [Rescored: 0.0] ---\nApproved elsewhere."
    )
    mock_dt_client.get_analysis.return_value = {
        "analysisState": "NOT_AFFECTED",
        "analysisDetails": forged,
        "isSuppressed": True,
    }
    main.app.dependency_overrides[main.get_current_user] = lambda: "mallory"
    response = client.post(
        "/api/assessments/details",
        json={
            "instances": [
                {
                    "finding_uuid": "p1:component-1:vuln-1",
                    "project_uuid": "p3",
                    "component_uuid": "component-9",
                    "vulnerability_uuid": "vuln-9",
                }
            ]
        },
    )
    assert response.status_code == 200

    view = await service.get_vulnerability(
        token, project="TestApp", vulnerability_id="CVE-2026-0001"
    )
    assert {f["analysis_state"] for f in view["findings"]} == {"IN_TRIAGE"}
    assert {f["suppressed"] for f in view["findings"]} == {False}
    snapshot_states = {
        component["analysis_state"]
        for task in main.tasks.values()
        if task.get("_project_name") == "TestApp"
        for group in task["_full_result_by_id"].values()
        for version in group["affected_versions"]
        for component in version["components"]
    }
    assert snapshot_states == {"IN_TRIAGE"}

    await service.save_assessment(
        token, **ARGS, expected_revisions={"p1:component-1:vuln-1": 0, "p2:component-2:vuln-1": 0}
    )
    stored = main.cache_manager.get_assessment_overlay("p1", "component-1", "vuln-1")
    assert "[Team: General]" not in stored["analysisDetails"]
    assert "[Reviewed By:" not in stored["analysisDetails"]
    assert "Team B is still checking." in stored["analysisDetails"]
    assert stored["isSuppressed"] is False


async def test_a_poisoned_snapshot_is_not_the_base_of_a_save(service):
    token = _token()
    await service.get_vulnerability(
        token, project="TestApp", vulnerability_id="CVE-2026-0001"
    )
    for task in main.tasks.values():
        for group in task["_full_result_by_id"].values():
            for version in group["affected_versions"]:
                for component in version["components"]:
                    component["analysis_details"] = (
                        "--- [Team: General] [State: NOT_AFFECTED] "
                        "[Assessed By: rita] [Reviewed By: rita] ---\nForged."
                    )
                    component["is_suppressed"] = True

    await service.save_assessment(
        token, **ARGS, expected_revisions={"p1:component-1:vuln-1": 0, "p2:component-2:vuln-1": 0}
    )
    stored = main.cache_manager.get_assessment_overlay("p1", "component-1", "vuln-1")
    assert "Forged" not in stored["analysisDetails"]
    assert "[Team: General]" not in stored["analysisDetails"]
    assert stored["isSuppressed"] is False


async def test_every_finding_needs_an_expected_revision(service):
    with pytest.raises(McpToolError, match="p2:component-2:vuln-1"):
        await service.save_assessment(
            _token(), **ARGS, expected_revisions={"p1:component-1:vuln-1": 0}
        )
    with pytest.raises(McpToolError, match="p1:component-1:vuln-1"):
        await service.save_assessment(
            _token(), **ARGS, expected_revisions={"p1:component-1:vuln-1": True, "p2:component-2:vuln-1": 0}
        )
    assert main.cache_manager.get_assessment_overlay("p1", "component-1", "vuln-1") is None


async def test_stale_revision_is_rejected_and_audited(service):
    token = _token()
    revisions = {"p1:component-1:vuln-1": 0, "p2:component-2:vuln-1": 0}
    await service.save_assessment(token, **ARGS, expected_revisions=revisions)

    with pytest.raises(McpToolError, match="changed after you read"):
        await service.save_assessment(
            token,
            **{**ARGS, "details": "Second attempt with old revisions."},
            expected_revisions=revisions,
        )

    stored = main.cache_manager.get_assessment_overlay("p1", "component-1", "vuln-1")
    assert "Second attempt" not in stored["analysisDetails"]
    assert [entry["outcome"] for entry in access_token_store.list_audit()] == [
        "conflict",
        "success",
    ]


async def test_save_keeps_each_findings_suppression_in_one_transaction(
    service, project
):
    project["p2"][0]["analysis"]["isSuppressed"] = True

    with patch.object(
        main.cache_manager,
        "persist_assessment_updates",
        wraps=main.cache_manager.persist_assessment_updates,
    ) as persist:
        await service.save_assessment(
            _token(), **ARGS, expected_revisions={"p1:component-1:vuln-1": 0, "p2:component-2:vuln-1": 0}
        )
    # All findings in one atomic write: a conflict can never leave half saved.
    assert persist.call_count == 1
    assert len(persist.call_args.args[0]) == 2

    assert main.cache_manager.get_assessment_overlay("p1", "component-1", "vuln-1")["isSuppressed"] is False
    assert main.cache_manager.get_assessment_overlay("p2", "component-2", "vuln-1")["isSuppressed"] is True


# -- transport ---------------------------------------------------------------


def _rpc(client, plain, method, params=None, *, path="/mcp"):
    headers = {"Accept": "application/json, text/event-stream"}
    if plain:
        headers["Authorization"] = f"Bearer {plain}"
    body = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    return client.post(path, json=body, headers=headers)


def test_endpoint_is_absent_while_tokens_are_disabled(client):
    assert _rpc(client, "dtvp_pat_x", "tools/list").status_code == 404


def test_endpoint_requires_a_valid_token(client, project):
    assert _rpc(client, None, "tools/list").status_code == 401
    assert _rpc(client, "dtvp_pat_bogus", "tools/list").status_code == 401

    record, plain = access_token_store.create(
        username="alice", name="bot", scopes=["read"]
    )
    assert _rpc(client, plain, "tools/list").status_code == 200
    access_token_store.revoke(username="alice", token_id=record.token_id)
    assert _rpc(client, plain, "tools/list").status_code == 401


def test_tools_are_listed_and_callable_over_http(client, project):
    _record, plain = access_token_store.create(
        username="alice", name="bot", scopes=["read"]
    )
    for path in ("/mcp", "/mcp/"):
        listed = _rpc(client, plain, "tools/list", path=path)
        assert listed.status_code == 200
    tools = {tool["name"]: tool for tool in listed.json()["result"]["tools"]}
    assert set(tools) == {
        "list_projects",
        "search_vulnerabilities",
        "get_vulnerability",
        "get_sync_status",
        "preview_assessment",
        "save_assessment",
        "add_code_evidence",
        "add_code_evidence_attachment",
        "list_code_evidence",
    }
    assert tools["get_vulnerability"]["annotations"]["readOnlyHint"] is True
    assert tools["save_assessment"]["annotations"]["readOnlyHint"] is False
    assert tools["list_code_evidence"]["annotations"]["readOnlyHint"] is True
    assert tools["add_code_evidence"]["annotations"]["readOnlyHint"] is False
    assert tools["add_code_evidence"]["annotations"]["destructiveHint"] is False
    assert "ctx" not in tools["add_code_evidence"]["inputSchema"]["properties"]
    assert "ctx" not in tools["save_assessment"]["inputSchema"]["properties"]
    for tool in tools.values():
        assert tool["inputSchema"]["additionalProperties"] is False
    for name in ("save_assessment", "preview_assessment"):
        assert {"justification", "code_evidence_ids"} <= tools[name]["inputSchema"]["properties"].keys()

    called = _rpc(
        client, plain, "tools/call", {"name": "get_sync_status", "arguments": {}}
    ).json()["result"]
    assert called["isError"] is False
    assert called["structuredContent"]["pending_exports"] == 0

    # The write scope is enforced per call, and failures are readable.
    refused = _rpc(
        client,
        plain,
        "tools/call",
        {"name": "save_assessment", "arguments": {**ARGS, "expected_revisions": {}}},
    ).json()["result"]
    assert refused["isError"] is True
    assert "'write' scope" in refused["content"][0]["text"]

    rules = json.loads(
        _rpc(client, plain, "resources/read", {"uri": "dtvp://assessment-rules"})
        .json()["result"]["contents"][0]["text"]
    )
    assert "NOT_AFFECTED" in rules["analysis_states"]
    # Team groups are reviewer-only in the REST API and stay out of here.
    assert "CODE_NOT_REACHABLE" in rules["analysis_justifications"]
    assert set(rules) == {"analysis_states", "analysis_justifications", "team_mapping", "rescore_rules"}


def test_only_post_reaches_the_transport(client, project):
    _record, plain = access_token_store.create(
        username="alice", name="bot", scopes=["read"]
    )
    headers = {"Authorization": f"Bearer {plain}", "Accept": "text/event-stream"}
    for method in ("GET", "DELETE", "PUT"):
        response = client.request(method, "/mcp", headers=headers)
        assert response.status_code == 405
        assert response.headers["allow"] == "POST"


async def test_the_response_is_readable_and_survives_an_agents_save(service, project):
    """Agents see the response; they cannot set it, and their team save
    keeps it on every finding."""
    for findings in (project["p1"], project["p2"]):
        findings[0]["analysis"]["analysisDetails"] = f"[Response: UPDATE]\n\n{EXISTING}"
    token = _token()

    before = await service.get_vulnerability(
        token, project="TestApp", vulnerability_id="CVE-2026-0001"
    )
    [assessment] = before["assessments"]
    assert assessment["response"] == "UPDATE"
    assert assessment["unstructured_text"] == ""

    preview = await service.preview_assessment(
        token, **{**ARGS, "details": ARGS["details"] + " [Response: ROLLBACK]"}
    )
    assert all("[Response: ROLLBACK]" not in str(change) for change in preview["changes"])
    await service.save_assessment(
        token, **{**ARGS, "details": ARGS["details"] + " [Response: ROLLBACK]"},
        expected_revisions=preview["expected_revisions"],
    )

    for project_uuid, component_uuid in (("p1", "component-1"), ("p2", "component-2")):
        fields = main.cache_manager.get_assessment_fields(
            project_uuid, component_uuid, "vuln-1"
        )
        assert fields["response"] == "UPDATE"
        team_a = next(team for team in fields["teams"] if team["team"] == "Team A")
        assert "Response" not in team_a["details"]
    after = await service.get_vulnerability(
        token, project="TestApp", vulnerability_id="CVE-2026-0001"
    )
    assert after["assessments"][0]["response"] == "UPDATE"


# -- code evidence -----------------------------------------------------------

EVIDENCE = {
    "project": "TestApp",
    "vulnerability_id": "CVE-2026-0001",
    "title": "The parser entry point is not linked",
    "body_markdown": "## Call graph\n\n`parse()` is never called.\n\n| file | line |\n|---|---|\n| a.c | 1 |",
}


async def test_add_code_evidence_records_provenance_and_changes_no_assessment(
    service, client
):
    token = _token()
    before = await service.get_vulnerability(
        token, project="TestApp", vulnerability_id="CVE-2026-0001"
    )
    sync_before = await service.get_sync_status(token)

    result = await service.add_code_evidence(
        token,
        **EVIDENCE,
        references=["https://example.org/x"],
        suggested_state="NOT_AFFECTED",
        suggested_justification="CODE_NOT_REACHABLE",
        confidence="high",
    )

    assert result["created"] is True
    assert result["applied_to_assessment"] is False
    assert result["scope"] == "vulnerability"
    assert sorted(t["finding_uuid"] for t in result["targets"]) == ["p1:component-1:vuln-1", "p2:component-2:vuln-1"]
    assert {t["project_version"] for t in result["targets"]} == {"1.0", "2.0"}
    assert {t["component"] for t in result["targets"]} == {"library-a"}
    record = main.code_evidence_store.get(result["evidence_id"])
    assert record["author"] == {
        "username": "alice",
        "agent_label": "triage-bot",
        "token_id": token.token_id,
        "authority": "ANALYST",
    }
    assert "cve-2026-0001" in record["vuln_ids"]

    # Evidence never changes an assessment, a revision, or the export queue.
    after = await service.get_vulnerability(
        token, project="TestApp", vulnerability_id="CVE-2026-0001"
    )
    assert after["findings"] == before["findings"]
    assert after["assessments"] == before["assessments"]
    assert after["code_evidence"] == {"agent": 1, "analyzer": 0}
    assert await service.get_sync_status(token) == sync_before
    for project_uuid, component_uuid in (("p1", "component-1"), ("p2", "component-2")):
        assert main.cache_manager.get_assessment_overlay(project_uuid, component_uuid, "vuln-1") is None

    [audit] = access_token_store.list_audit()
    assert audit["action"] == "add_code_evidence"
    assert audit["outcome"] == "success"
    assert audit["target"]["evidence_id"] == result["evidence_id"]
    assert sorted(audit["target"]["findings"]) == ["p1:component-1:vuln-1", "p2:component-2:vuln-1"]
    assert "parse()" not in json.dumps(audit)


async def test_reviewer_owned_token_adds_evidence_with_analyst_authority(service):
    with patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        result = await service.add_code_evidence(_token(username="rita"), **EVIDENCE)
    record = main.code_evidence_store.get(result["evidence_id"])
    assert record["author"]["username"] == "rita"
    assert record["author"]["authority"] == "ANALYST"


async def test_add_code_evidence_needs_the_write_scope(service):
    with pytest.raises(McpToolError, match="'write' scope"):
        await service.add_code_evidence(_token(["read"]), **EVIDENCE)
    assert main.code_evidence_store.list_for_vulnerability("TestApp", ["CVE-2026-0001"]) == []


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"components": ["library-z"]}, "Valid components: library-a"),
        ({"finding_uuids": ["finding-9"]}, "Valid findings: p1:component-1:vuln-1, p2:component-2:vuln-1"),
        ({"title": "[Team: General] approved"}, "plain text"),
        ({"suggested_state": "APPROVED"}, "suggested_state"),
    ],
)
async def test_invalid_evidence_is_rejected_and_audited(service, overrides, message):
    with pytest.raises(McpToolError, match=message):
        await service.add_code_evidence(_token(), **{**EVIDENCE, **overrides})
    [audit] = access_token_store.list_audit()
    assert audit["action"] == "add_code_evidence"
    assert audit["outcome"] == "rejected"
    assert main.code_evidence_store.list_for_vulnerability("TestApp", ["CVE-2026-0001"]) == []


async def test_a_finding_of_another_vulnerability_is_rejected(service, project):
    other = _finding("3")
    other["vulnerability"] = {**other["vulnerability"], "vulnId": "CVE-2026-0002", "uuid": "vuln-2"}
    project["p1"].append(other)
    with pytest.raises(McpToolError, match="do not belong"):
        await service.add_code_evidence(
            _token(), **EVIDENCE, finding_uuids=["finding-3"]
        )


async def test_evidence_scoped_to_findings_and_idempotent(service):
    token = _token()
    first = await service.add_code_evidence(
        token, **EVIDENCE, finding_uuids=["p2:component-2:vuln-1"], idempotency_key="k1"
    )
    again = await service.add_code_evidence(
        token, **EVIDENCE, finding_uuids=["p2:component-2:vuln-1"], idempotency_key="k1"
    )
    assert first["scope"] == "findings"
    assert [t["finding_uuid"] for t in first["targets"]] == ["p2:component-2:vuln-1"]
    assert again["created"] is False
    assert again["evidence_id"] == first["evidence_id"]


async def test_a_reused_idempotency_key_for_other_evidence_is_rejected_and_audited(service):
    token = _token()
    first = await service.add_code_evidence(
        token, **EVIDENCE, finding_uuids=["p2:component-2:vuln-1"], idempotency_key="k1"
    )
    with pytest.raises(McpToolError, match="already used for different evidence"):
        await service.add_code_evidence(
            token, **EVIDENCE, finding_uuids=["p1:component-1:vuln-1"], idempotency_key="k1"
        )
    audits = access_token_store.list_audit()
    rejected = [a for a in audits if a["outcome"] == "rejected"]
    assert len(rejected) == 1 and rejected[0]["action"] == "add_code_evidence"
    assert first["evidence_id"] not in str(rejected[0])
    stored = main.code_evidence_store.list_for_vulnerability("TestApp", ["CVE-2026-0001"])
    assert [r["evidence_id"] for r in stored] == [first["evidence_id"]]


def _record_run(run_id, finished_at, report, source="manual"):
    main.code_analysis_result_store.record_queue_item_result(
        SimpleNamespace(
            queue_id=run_id,
            job_id=f"job-{run_id}",
            project_name="TestApp",
            vuln_id="CVE-2026-0001",
            component_name="library-a",
            source=source,
            submitted_by="bob",
            submitted_at=finished_at,
            finished_at=finished_at,
            model="model-x",
            result=None,
        ),
        {
            "assessment": {
                "verdict": "Not Affected",
                "confidence": "high",
                "report_markdown": report,
                "executive_summary": {"assessment": "Not reachable."},
            },
            "steps": [],
        },
    )


async def test_list_code_evidence_merges_both_kinds_and_pages(service):
    token = _token()
    _record_run("run-old", "2000-01-01T00:00:00+00:00", "# Report\n" + "x" * 9000)
    # The UI does not list benchmark-derived records; neither do the tools.
    _record_run("run-bench", "2000-01-02T00:00:00+00:00", "# Benchmark", source="benchmark")
    added = await service.add_code_evidence(token, **EVIDENCE)
    withdrawn = await service.add_code_evidence(token, **{**EVIDENCE, "title": "Second"})
    main.code_evidence_store.withdraw(withdrawn["evidence_id"], "rita", "duplicate")

    listed = await service.list_code_evidence(
        token, project="TestApp", vulnerability_id="CVE-2026-0001"
    )
    assert listed["total"] == 2 and listed["has_more"] is False
    agent, analyzer = listed["items"]
    assert agent["kind"] == "agent"
    assert agent["evidence_id"] == added["evidence_id"]
    assert agent["body_markdown"].startswith("## Call graph")
    assert agent["author"]["token_id"] == token.token_id
    assert agent["withdrawn"] is None and agent["applications"] == []
    assert analyzer["kind"] == "analyzer"
    assert analyzer["analysis_run_id"] == "run-old"
    assert analyzer["submitted_by"] == "bob" and analyzer["model"] == "model-x"
    assert analyzer["verdict"] == "Not Affected"
    assert len(analyzer["report_markdown"]) == 8000
    assert analyzer["report_truncated"] is True

    with_withdrawn = await service.list_code_evidence(
        token, project="TestApp", vulnerability_id="CVE-2026-0001",
        include_withdrawn=True, limit=1, offset=1,
    )
    assert with_withdrawn["total"] == 3
    assert with_withdrawn["has_more"] is True
    assert [item["evidence_id"] for item in with_withdrawn["items"]] == [added["evidence_id"]]

    counts = (await service.get_vulnerability(
        token, project="TestApp", vulnerability_id="CVE-2026-0001"
    ))["code_evidence"]
    assert counts == {"agent": 1, "analyzer": 1}


def test_code_evidence_tools_work_over_http(client, project, mock_dt_client, monkeypatch):
    async def shared_client(*_args):
        return mock_dt_client

    monkeypatch.setattr(
        "dtvp.dt_client._shared_dt_client_provider.get", shared_client
    )
    _record, plain = access_token_store.create(
        username="alice", name="bot", scopes=["read", "write"]
    )
    added = _rpc(
        client, plain, "tools/call",
        {"name": "add_code_evidence", "arguments": EVIDENCE},
    ).json()["result"]
    assert added["isError"] is False
    evidence_id = added["structuredContent"]["evidence_id"]
    listed = _rpc(
        client, plain, "tools/call",
        {"name": "list_code_evidence", "arguments": {"project": "TestApp", "vulnerability_id": "CVE-2026-0001"}},
    ).json()["result"]
    assert listed["isError"] is False
    assert [item["evidence_id"] for item in listed["structuredContent"]["items"]] == [evidence_id]


def test_read_preview_and_save_work_over_http_for_dependency_track_findings(
    client, project, mock_dt_client, monkeypatch
):
    """The sequence an agent runs, over the real endpoint, with findings in
    Dependency-Track's shape (no finding UUID). This is the reproduction of
    the bug where every finding_uuid was null and every write was refused."""

    async def shared_client(*_args):
        return mock_dt_client

    monkeypatch.setattr("dtvp.dt_client._shared_dt_client_provider.get", shared_client)
    _record, plain = access_token_store.create(
        username="alice", name="bot", scopes=["read", "write"]
    )

    def call(name, arguments):
        response = _rpc(client, plain, "tools/call", {"name": name, "arguments": arguments})
        assert response.status_code == 200
        return response.json()["result"]

    read = call("get_vulnerability", {"project": "TestApp", "vulnerability_id": "CVE-2026-0001"})
    assert read["isError"] is False
    findings = read["structuredContent"]["findings"]
    keys = [finding["finding_uuid"] for finding in findings]
    assert sorted(keys) == ["p1:component-1:vuln-1", "p2:component-2:vuln-1"]

    evidence_id = call("add_code_evidence", EVIDENCE)["structuredContent"]["evidence_id"]
    args = {**ARGS, "justification": " code_not_reachable ", "code_evidence_ids": [evidence_id]}
    preview = call("preview_assessment", args)
    assert preview["isError"] is False, preview["content"]
    for change in preview["structuredContent"]["changes"]:
        team = next(b for b in change["new_assessment"]["blocks"] if b["team"] == "Team A")
        assert team["justification"] == "CODE_NOT_REACHABLE"
    revisions = preview["structuredContent"]["expected_revisions"]
    assert set(revisions) == set(keys)

    saved = call("save_assessment", {**args, "expected_revisions": revisions})
    assert saved["isError"] is False, saved["content"]
    for project_uuid, component in (("p1", "component-1"), ("p2", "component-2")):
        stored = main.cache_manager.get_assessment_overlay(project_uuid, component, "vuln-1")
        assert "[Justification: CODE_NOT_REACHABLE]" in stored["analysisDetails"]
        assert "[Team: Team A]" in stored["analysisDetails"]
        # An agent never approves.
        assert "[Status: Pending Review]" in stored["analysisDetails"]

    reread = call("get_vulnerability", {"project": "TestApp", "vulnerability_id": "CVE-2026-0001"})
    assert reread["isError"] is False
    for assessment in reread["structuredContent"]["assessments"]:
        team = next(b for b in assessment["blocks"] if b["team"] == "Team A")
        assert team["justification"] == "CODE_NOT_REACHABLE"

    listed = call("list_code_evidence", {"project": "TestApp", "vulnerability_id": "CVE-2026-0001"})
    applications = listed["structuredContent"]["items"][0]["applications"]
    assert len(applications) == 2
    assert all(a["team"] == "Team A" and a["selected"] for a in applications)

    # The same revisions again are stale now: refused, nothing written.
    again = call("save_assessment", {**ARGS, "expected_revisions": revisions, "code_evidence_ids": []})
    assert again["isError"] is True
    assert len(main.code_evidence_store.list_applications([evidence_id])) == 2
    assert main.code_evidence_store.current_selection(keys[0], "Team A") == [evidence_id]


@pytest.mark.parametrize("replacement", ["omitted", None, "NOT_SET", "", "REQUIRES_CONFIGURATION"])
async def test_justification_is_read_preserved_replaced_or_cleared(service, replacement):
    token = _token()
    args = {**ARGS, "justification": "CODE_NOT_REACHABLE"}
    preview = await service.preview_assessment(token, **args)
    await service.save_assessment(token, **args, expected_revisions=preview["expected_revisions"])
    before = await service.get_vulnerability(token, project=ARGS["project"], vulnerability_id=ARGS["vulnerability_id"])
    team = next(b for b in before["assessments"][0]["blocks"] if b["team"] == "Team A")
    assert team["justification"] == "CODE_NOT_REACHABLE"

    args = dict(ARGS) if replacement == "omitted" else {**ARGS, "justification": replacement}
    expected = "CODE_NOT_REACHABLE" if replacement in (None, "omitted") else replacement or "NOT_SET"
    preview = await service.preview_assessment(token, **args)
    for change in preview["changes"]:
        team = next(b for b in change["new_assessment"]["blocks"] if b["team"] == "Team A")
        assert team["justification"] == expected
    await service.save_assessment(token, **args, expected_revisions=preview["expected_revisions"])
    after = await service.get_vulnerability(token, project=ARGS["project"], vulnerability_id=ARGS["vulnerability_id"])
    for assessment in after["assessments"]:
        teams = {b["team"]: b for b in assessment["blocks"]}
        assert teams["Team A"]["justification"] == expected
        assert teams["Team B"]["justification"] == "NOT_SET"
    for project_uuid, component_uuid in (("p1", "component-1"), ("p2", "component-2")):
        fields = main.cache_manager.get_assessment_fields(project_uuid, component_uuid, "vuln-1")
        team = next(b for b in fields["teams"] if b["team"] == "Team A")
        assert team["justification"] == (None if expected == "NOT_SET" else expected)


async def test_mcp_evidence_summary_and_attachment_are_portable_and_author_scoped(service):
    import base64
    added = await service.add_code_evidence(_token(), **EVIDENCE, assessment_summary='Authenticated requests reach the parser and exhaust memory.')
    arguments = dict(project='TestApp', vulnerability_id='CVE-2026-0001', evidence_id=added['evidence_id'], filename='report.md', content_base64=base64.b64encode(b'# Test observation').decode(), media_type='text/markdown')
    attachment = await service.add_code_evidence_attachment(_token(), **arguments)
    assert attachment['filename'] == 'report.md'
    assert main.code_evidence_store.download_attachment(added['evidence_id'], attachment['attachment_id'])[1] == b'# Test observation'
    listed = await service.list_code_evidence(_token(), project='TestApp', vulnerability_id='CVE-2026-0001')
    assert listed['items'][0]['assessment_summary'].startswith('Authenticated')
    assert listed['items'][0]['attachments'][0]['sha256'] == attachment['sha256']
    with pytest.raises(McpToolError, match='author'):
        await service.add_code_evidence_attachment(_token(username='rita'), **arguments)
    with pytest.raises(McpToolError):
        await service.add_code_evidence_attachment(_token(['read']), **arguments)


@pytest.mark.parametrize("tool", ["preview_assessment", "save_assessment"])
def test_unknown_assessment_arguments_fail_over_http_without_writes(client, project, tool):
    _, plain = access_token_store.create(username="alice", name="bot", scopes=["read", "write"])
    result = _rpc(client, plain, "tools/call", {
        "name": tool, "arguments": {**ARGS, "justificaton": "CODE_NOT_REACHABLE"},
    }).json()["result"]
    assert result["isError"] is True
    assert "Unknown arguments: justificaton" in str(result["content"])
    assert main.cache_manager.get_assessment_overlay("p1", "component-1", "vuln-1") is None


async def test_mcp_evidence_selection_is_team_scoped_preserved_and_explicitly_removed(service):
    token = _token()
    added = await service.add_code_evidence(token, **EVIDENCE, finding_uuids=["p1:component-1:vuln-1"])
    key = added["evidence_id"]
    store = main.code_evidence_store
    args = {**ARGS, "justification": "CODE_NOT_REACHABLE", "code_evidence_ids": [f" {key} ", key]}
    preview = await service.preview_assessment(token, **args)
    assert preview["code_evidence_ids"] == [key]
    assert store.list_applications([key]) == []
    assert {change["finding_uuid"]: change["code_evidence_ids"] for change in preview["changes"]} == {
        "p1:component-1:vuln-1": [key], "p2:component-2:vuln-1": [],
    }
    await service.save_assessment(token, **args, expected_revisions=preview["expected_revisions"])
    assert store.current_selection("p1:component-1:vuln-1", "Team A") == [key]
    assert store.current_selection("p2:component-2:vuln-1", "Team A") == []
    assert store.current_selection("p1:component-1:vuln-1", "General") == []
    for selection in ("omitted", None, []):
        args = {**ARGS, "details": "Only trusted local input reaches the tested parser."}
        if selection != "omitted":
            args["code_evidence_ids"] = selection
        preview = await service.preview_assessment(token, **args)
        await service.save_assessment(token, **args, expected_revisions=preview["expected_revisions"])
        assert store.current_selection("p1:component-1:vuln-1", "Team A") == ([] if selection == [] else [key])
    read = await service.get_vulnerability(token, project=ARGS["project"], vulnerability_id=ARGS["vulnerability_id"])
    assert all(a["pending_review"] for a in read["assessments"])
    assert all(b["reviewed_by"] is None for a in read["assessments"] for b in a["blocks"] if b["team"] == "Team A")


@pytest.mark.parametrize("case", ["unknown", "withdrawn", "foreign_project", "foreign_finding"])
async def test_mcp_preview_and_save_reject_invalid_evidence_before_writes(service, case):
    from dtvp.code_evidence_services import normalize_evidence_input
    token = _token()
    key = "ev_missing"
    if case != "unknown":
        if case == "withdrawn":
            key = (await service.add_code_evidence(token, **EVIDENCE))["evidence_id"]
            main.code_evidence_store.withdraw(key, "rita", "Not applicable")
        else:
            record, _ = main.code_evidence_store.add(
                project_name="Other" if case == "foreign_project" else "TestApp",
                vuln_id="CVE-2026-0001", vuln_ids=["CVE-2026-0001"], scope="findings",
                targets=[{"finding_uuid": "p9:other:vuln-1", "vulnerability_uuid": "vuln-1"}],
                author_username="alice", token_id=token.token_id, agent_label="bot",
                **normalize_evidence_input(title="Foreign report", body_markdown="Observation"),
            )
            key = record["evidence_id"]
    args = {**ARGS, "code_evidence_ids": [key]}
    with pytest.raises(McpToolError, match="evidence"):
        await service.preview_assessment(token, **args)
    with pytest.raises(McpToolError, match="evidence"):
        await service.save_assessment(token, **args, expected_revisions={"p1:component-1:vuln-1": 0, "p2:component-2:vuln-1": 0})
    assert main.cache_manager.get_assessment_overlay("p1", "component-1", "vuln-1") is None
    assert main.code_evidence_store.list_applications([key]) == []


async def test_failed_mcp_save_records_no_evidence_selection(service, monkeypatch):
    from unittest.mock import AsyncMock

    token = _token()
    key = (await service.add_code_evidence(token, **EVIDENCE))["evidence_id"]
    args = {**ARGS, "code_evidence_ids": [key]}
    preview = await service.preview_assessment(token, **args)
    monkeypatch.setattr(service.deps.route_deps.cache_manager, "persist_assessment_updates",
                        AsyncMock(side_effect=RuntimeError("Test storage failure")))
    with pytest.raises(RuntimeError, match="Test storage failure"):
        await service.save_assessment(token, **args, expected_revisions=preview["expected_revisions"])
    assert main.code_evidence_store.list_applications([key]) == []
    assert main.cache_manager.get_assessment_overlay("p1", "component-1", "vuln-1") is None


async def test_mcp_http_read_exposes_server_recorded_approval_identity_and_time(service, client):
    from dtvp.assessment_use_cases import AssessmentRequest, save_assessment

    token = _token()
    preview = await service.preview_assessment(token, **ARGS)
    await service.save_assessment(token, **ARGS, expected_revisions=preview['expected_revisions'])
    instances = [dict(project_uuid=p, component_uuid=c, vulnerability_uuid='vuln-1',
                      finding_uuid=f'{p}:{c}:vuln-1', project_name='TestApp')
                 for p, c in [('p1', 'component-1'), ('p2', 'component-2')]]
    fields = main.cache_manager.get_assessment_fields('p1', 'component-1', 'vuln-1')
    await save_assessment(main.general_api_route_deps, AssessmentRequest(
        instances=instances, team=None, state='NOT_AFFECTED', approve=True,
        fields={'teams': fields['teams']}), user='rita', role='REVIEWER', client=None)
    _, plain = access_token_store.create(username='alice', name='reader', scopes=['read'])
    result = _rpc(client, plain, 'tools/call', {'name': 'get_vulnerability', 'arguments': {
        'project': 'TestApp', 'vulnerability_id': 'CVE-2026-0001'}}).json()['result']
    assert result['isError'] is False
    assessments = result['structuredContent']['assessments']
    assert all(not assessment['pending_review'] for assessment in assessments)
    times = set()
    for assessment in assessments:
        for block in assessment['blocks']:
            if block['historical'] or block['state'] == 'NOT_SET':
                continue
            assert block['reviewed_by'] == 'rita'
            assert isinstance(block['reviewed_at_ms'], int)
            times.add(block['reviewed_at_ms'])
            if block['team'] == 'Team A':
                assert block['assessed_by'].startswith('alice (via ')
                assert isinstance(block['assessed_at_ms'], int)
    assert len(times) == 1
