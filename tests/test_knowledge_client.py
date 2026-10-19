import json
import sys

import httpx
import pytest
import respx

from dtvp.cli import main


@respx.mock
def test_coverage_cli_forwards_frozen_selection_and_reports_complete_counts(monkeypatch, capsys):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dtvp",
            "knowledge",
            "--url",
            "http://dtvp.test",
            "coverage",
            "--project",
            "project",
            "--state",
            "a" * 64,
            "--context",
            "b" * 64,
            "--vulnerability",
            "CVE-test",
            "--expected-preview",
            "c" * 64,
            "--limit",
            "1",
        ],
    )
    route = respx.post("http://dtvp.test/api/v1/projects/project/coverage/candidates").mock(
        return_value=httpx.Response(
            200,
            json={
                "preview_digest": "c" * 64,
                "statistics": {"versions": 4},
                "total": 12,
                "items": [
                    {
                        "version": "7.1.2",
                        "context_id": "b" * 64,
                        "team_id": "team",
                        "coverage": {"status": "submitted"},
                        "classification": "material_changed",
                        "capabilities": ["assess"],
                    }
                ],
                "next_offset": 1,
            },
        )
    )
    main()
    assert json.loads(route.calls[0].request.content) == {
        "source": "a" * 64,
        "context_id": "b" * 64,
        "vulnerability_id": "CVE-test",
        "expected_preview": "c" * 64,
    }
    output = capsys.readouterr().out
    assert "Versions: 4 · Targets: 12" in output
    assert "coverage=submitted" in output and "comparison=material_changed" in output
    assert "Read-only candidates" in output


@pytest.mark.parametrize("part", [None, "supplier part"])
@respx.mock
def test_pipeline_cli_uploads_original_bytes_and_explicit_retry_metadata(
    monkeypatch, tmp_path, capsys, part
):
    from email import policy
    from email.parser import BytesParser

    raw = b'\xef\xbb\xbf<?xml version="1.0"?>\r\n<bom>original bytes</bom>\r\n'
    source = tmp_path / "supplier.xml"
    source.write_bytes(raw)
    metadata = {"request_id": "pipeline-run-42", "expected": None, "build_number": 42}
    metadata_file = tmp_path / "metadata.json"
    metadata_file.write_text(json.dumps(metadata))
    argv = [
        "dtvp",
        "knowledge",
        "--url",
        "http://dtvp.test",
        "import-file",
        "--project",
        "project",
        "--version",
        "7.1.1",
        "--file",
        str(source),
        "--metadata",
        str(metadata_file),
    ]
    if part:
        argv.extend(["--part", part])
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    path = "http://dtvp.test/api/v1/projects/project/versions/7.1.1"
    if part:
        path += "/parts/supplier%20part"
    route = respx.post(path + "/files").mock(
        return_value=httpx.Response(201, json={"committed": True})
    )
    main()
    request = route.calls[0].request
    message = BytesParser(policy=policy.default).parsebytes(
        ("Content-Type: " + request.headers["content-type"] + "\r\n\r\n").encode() + request.content
    )
    fields = {
        item.get_param("name", header="content-disposition"): item for item in message.iter_parts()
    }
    assert fields["file"].get_payload(decode=True) == raw
    assert fields["file"].get_filename() == "supplier.xml"
    assert json.loads(fields["metadata"].get_payload(decode=True)) == metadata
    assert json.loads(capsys.readouterr().out) == {"committed": True}


@respx.mock
def test_machine_workspace_cli_uses_http_without_opening_database(monkeypatch, capsys):
    import dtvp.cli as cli

    monkeypatch.setenv("TEST_DTVP_TOKEN", "machine-test-token")
    monkeypatch.setattr(
        cli, "Settings", lambda: (_ for _ in ()).throw(AssertionError("No database"))
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dtvp",
            "knowledge",
            "--url",
            "http://dtvp.test",
            "--token-env",
            "TEST_DTVP_TOKEN",
            "workspace",
            "--project",
            "project",
            "--version",
            "7.1.1",
        ],
    )
    route = respx.get("http://dtvp.test/api/v1/projects/project/versions/7.1.1/workspace").mock(
        return_value=httpx.Response(
            200,
            json={
                "state": "a" * 64,
                "team_labels": {"team": "Shared Libraries"},
                "statistics": {"totals": {"context_findings": 1}, "approved": 1, "submitted": 1},
                "items": [
                    {
                        "vulnerability_id": "CVE-test",
                        "component": {"name": "library", "version": "1"},
                        "context": {"root_ref": "app", "team_id": "team"},
                        "coverage": {"status": "approved"},
                        "source_ratings": [{"score": 9.8}],
                        "published_score": {"score": 0, "current": True},
                        "code_analysis": [
                            {
                                "id": "analysis-one",
                                "provider": "agentyzer",
                                "current": True,
                                "verdict": "not_affected",
                                "application_eligible": False,
                                "rescoring_eligible": False,
                                "ineligibility_reasons": [
                                    "native_vulnerability_request_binding_missing"
                                ],
                            }
                        ],
                    }
                ],
                "next_offset": None,
            },
        )
    )
    main()
    assert route.calls[0].request.headers["authorization"] == "Bearer machine-test-token"
    output = capsys.readouterr().out
    assert "source=9.8 contextual=0" in output
    assert "team=Shared Libraries" in output
    assert "analysis=analysis-one provider=agentyzer" in output
    assert "native_vulnerability_request_binding_missing" in output
    assert "machine-test-token" not in output


@respx.mock
def test_playground_cli_forwards_json_and_csrf_without_domain_logic(monkeypatch, tmp_path, capsys):
    payload = {"request_id": "explicit-request", "expected_versions": {"7.1.1": "b" * 64}}
    body = tmp_path / "review.json"
    body.write_text(json.dumps(payload))
    respx.post("http://dtvp.test/api/v1/playground/login").mock(
        return_value=httpx.Response(
            200, json={}, headers={"Set-Cookie": "dtvp_csrf=csrf-test; Path=/"}
        )
    )
    route = respx.post("http://dtvp.test/api/v1/projects/project/reviews").mock(
        return_value=httpx.Response(201, json={"committed": True})
    )
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dtvp",
            "knowledge",
            "--url",
            "http://dtvp.test",
            "--persona",
            "reviewer",
            "request",
            "POST",
            "/api/v1/projects/project/reviews",
            "--body",
            str(body),
        ],
    )
    main()
    assert json.loads(route.calls[0].request.content) == payload
    assert route.calls[0].request.headers["x-csrf-token"] == "csrf-test"
    assert json.loads(capsys.readouterr().out)["committed"] is True


@respx.mock
def test_workspace_cli_forwards_advanced_filters_and_keeps_server_totals(monkeypatch, capsys):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dtvp",
            "knowledge",
            "--url",
            "http://dtvp.test",
            "workspace",
            "--project",
            "p",
            "--version",
            "7.1.2",
            "--source-severity",
            "critical",
            "--contextual-severity",
            "none",
            "--team-review",
            "approved",
            "--source-conflict",
            "yes",
            "--dependency",
            "transitive",
            "--provider",
            "Supplier",
            "--criticality",
            "critical",
            "--exposure",
            "external",
            "--support-status",
            "unsupported",
            "--metadata-status",
            "current",
        ],
    )
    route = respx.get("http://dtvp.test/api/v1/projects/p/versions/7.1.2/workspace").mock(
        return_value=httpx.Response(
            200,
            json={
                "state": "a" * 64,
                "statistics": {"totals": {"context_findings": 79}, "approved": 70, "submitted": 9},
                "items": [],
                "next_offset": 50,
            },
        )
    )
    main()
    params = route.calls[0].request.url.params
    assert params["source_severity"] == "critical"
    assert params["contextual_severity"] == "none"
    assert params["team_review"] == "approved"
    assert params["source_conflict"] == "yes"
    assert params["dependency"] == "transitive"
    assert params["provider"] == "Supplier"
    assert params["criticality"] == "critical" and params["exposure"] == "external"
    assert params["support_status"] == "unsupported" and params["metadata_status"] == "current"
    assert "Context findings: 79" in capsys.readouterr().out


@respx.mock
def test_compare_cli_uses_pinned_server_diff_and_full_count(monkeypatch, capsys):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dtvp",
            "knowledge",
            "--url",
            "http://dtvp.test",
            "compare",
            "--project",
            "p",
            "--before",
            "a" * 64,
            "--after",
            "b" * 64,
            "--limit",
            "1",
        ],
    )
    route = respx.get("http://dtvp.test/api/v1/projects/p/compare/details").mock(
        return_value=httpx.Response(
            200,
            json={
                "total": 79,
                "items": [{"category": "component", "key": "tls", "classifications": ["material"]}],
                "next_offset": 1,
                "limitations": ["Exact source-local identity only."],
            },
        )
    )
    main()
    assert route.calls[0].request.url.params["before"] == "a" * 64
    output = capsys.readouterr().out
    assert "Total: 79" in output
    assert "component tls: material" in output
    assert "Next offset: 1" in output


@respx.mock
def test_synchronization_cli_displays_server_preview_without_applying(monkeypatch, capsys):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dtvp",
            "knowledge",
            "--url",
            "http://dtvp.test",
            "synchronization",
            "--project",
            "p",
            "--source",
            "a" * 64,
            "--target",
            "b" * 64,
        ],
    )
    route = respx.post("http://dtvp.test/api/v1/projects/p/synchronization/preview").mock(
        return_value=httpx.Response(
            200,
            json={
                "preview_digest": "c" * 64,
                "mode": "two_state",
                "total": 31,
                "items": [
                    {
                        "category": "needs_review",
                        "vulnerability_id": "CVE-test",
                        "source_context_id": "s",
                        "target_context_id": "t",
                    }
                ],
                "next_offset": None,
            },
        )
    )
    main()
    assert json.loads(route.calls[0].request.content) == {
        "source": "a" * 64,
        "target": "b" * 64,
        "basis": None,
    }
    output = capsys.readouterr().out
    assert "Total: 31" in output
    assert "needs_review CVE-test s -> t" in output
    assert "Read-only" in output


@pytest.mark.parametrize("as_json", [False, True])
@respx.mock
def test_portfolio_cli_forwards_selected_heads_filters_and_displays_server_counts(
    monkeypatch, capsys, as_json
):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    args = [
        "dtvp",
        "knowledge",
        "--url",
        "http://dtvp.test",
        "portfolio",
        "--project",
        "p",
        "--version",
        "7.1.1",
        "--version",
        "7.1.2",
        "--expected-heads",
        "a" * 64,
        "--team",
        "team",
        "--q",
        "tls",
        "--lifecycle",
        "approved",
        "--source-severity",
        "critical",
        "--contextual-severity",
        "none",
        "--team-review",
        "approved",
        "--criticality",
        "critical",
        "--exposure",
        "external",
        "--support-status",
        "unsupported",
        "--metadata-status",
        "current",
    ]
    monkeypatch.setattr(sys, "argv", args + (["--json"] if as_json else []))
    group = {
        "context_findings": 79,
        "unique_vulnerabilities": 31,
        "unique_latest_logical_assessments": 12,
        "unique_approved_logical_assessments": 8,
        "reviewed_covered_targets": 50,
        "required_context_review_workload": {
            "required_targets": 79,
            "approved_targets": 50,
            "remaining_targets": 29,
            "not_assessable_targets": 2,
        },
    }
    result = {
        "heads_digest": "a" * 64,
        "heads": {"7.1.1": "b" * 64, "7.1.2": "c" * 64},
        "statistics": group,
        "by_version": {"7.1.1": group},
        "by_team": {"team": group},
        "team_labels": {"team": "Platform"},
        "state_evidence": {
            "7.1.1": {
                "baseline_status": "active",
                "collection_coverage": {
                    "package_coverage": "unknown",
                    "dependency_coverage": "partial",
                    "license_coverage": "unknown",
                },
            }
        },
        "limitations": ["Counts do not verify complete software coverage."],
    }
    route = respx.get("http://dtvp.test/api/v1/projects/p/portfolio").mock(
        return_value=httpx.Response(200, json=result)
    )
    main()
    params = route.calls[0].request.url.params
    assert params.get_list("version") == ["7.1.1", "7.1.2"]
    assert params["expected_heads"] == "a" * 64
    assert params["team_id"] == "team" and params["q"] == "tls"
    assert params["lifecycle"] == "approved" and params["source_severity"] == "critical"
    assert params["contextual_severity"] == "none" and params["team_review"] == "approved"
    assert params["criticality"] == "critical" and params["exposure"] == "external"
    assert params["support_status"] == "unsupported" and params["metadata_status"] == "current"
    output = capsys.readouterr().out
    if as_json:
        assert json.loads(output) == result
    else:
        assert "Context findings: 79" in output
        assert "Unique vulnerabilities: 31" in output
        assert "Latest logical assessments: 12" in output
        assert "Approved logical assessments: 8" in output
        assert "approved targets=50/79" in output and "not assessable=2" in output
        assert "team=Platform" in output
        assert "packages=unknown" in output and "state unfiltered" in output


@pytest.mark.parametrize("submit", [False, True])
@respx.mock
def test_document_cli_preserves_bytes_and_explicit_review_pins(tmp_path, monkeypatch, submit):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    raw = b"%PDF-exact\r\n\x00\xff"
    artifact = tmp_path / "review.pdf"
    artifact.write_bytes(raw)
    metadata = {
        "request_id": "stable-request",
        "expected": "a" * 64,
        "expected_revision": None,
        "issued_receipt_sha": "b" * 64,
        "renderer": {"name": "generator", "version": "1"},
        "configuration": {"template": "reviewed"},
        "document_id": "architecture",
        "title": "Architecture",
        "purpose": "architecture",
        "rationale": "Ready for review",
        "filename": "review.pdf",
        "media_type": "application/pdf",
    }
    config = tmp_path / "metadata.json"
    config.write_text(json.dumps(metadata))
    argv = [
        "dtvp",
        "knowledge",
        "--url",
        "http://dtvp.test",
        "document-register",
        "--project",
        "product",
        "--version",
        "7.1.2",
        "--file",
        str(artifact),
        "--metadata",
        str(config),
    ]
    if submit:
        argv.append("--submit")
    monkeypatch.setattr(sys, "argv", argv)
    route = respx.post(
        "http://dtvp.test/api/v1/projects/product/versions/7.1.2/documents/"
        + ("submit" if submit else "draft")
    ).mock(return_value=httpx.Response(201, json={"committed": True}))
    main()
    from email.parser import BytesParser
    from email.policy import default

    request = route.calls[0].request
    message = BytesParser(policy=default).parsebytes(
        b"Content-Type: " + request.headers["Content-Type"].encode() + b"\r\n\r\n" + request.content
    )
    parts = {
        part.get_param("name", header="content-disposition"): part.get_payload(decode=True)
        for part in message.iter_parts()
    }
    assert parts["file"] == raw
    assert json.loads(parts["metadata"]) == metadata


@pytest.mark.parametrize("preview", [False, True])
@respx.mock
def test_evidence_cli_preserves_original_bytes_and_explicit_collection_pins(
    tmp_path, monkeypatch, preview
):
    from email.parser import BytesParser
    from email.policy import default

    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    raw = b'{ "statements": [], "format": "opaque test input" }\r\n'
    artifact = tmp_path / "evidence.json"
    artifact.write_bytes(raw)
    metadata = {
        "request_id": "evidence-id",
        "source": "supplier",
        "revision": 19,
        "expected_evidence": "a" * 64,
        "expected_versions": {"7.1.2": "b" * 64},
    }
    config = tmp_path / "metadata.json"
    config.write_text(json.dumps(metadata))
    argv = [
        "dtvp",
        "knowledge",
        "--url",
        "http://dtvp.test",
        "evidence-import",
        "--project",
        "product",
        "--file",
        str(artifact),
        "--metadata",
        str(config),
    ]
    if preview:
        argv.append("--preview")
    monkeypatch.setattr(sys, "argv", argv)
    path = "http://dtvp.test/api/v1/projects/product/evidence/files" + (
        "/preview" if preview else ""
    )
    route = respx.post(path).mock(
        return_value=httpx.Response(200 if preview else 201, json={"committed": not preview})
    )
    main()
    request = route.calls[0].request
    message = BytesParser(policy=default).parsebytes(
        b"Content-Type: " + request.headers["Content-Type"].encode() + b"\r\n\r\n" + request.content
    )
    parts = {
        part.get_param("name", header="content-disposition"): part.get_payload(decode=True)
        for part in message.iter_parts()
    }
    assert parts["file"] == raw
    assert json.loads(parts["metadata"]) == metadata
