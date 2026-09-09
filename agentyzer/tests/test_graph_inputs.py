import asyncio
import threading

import pytest

import src.pipeline.graph as pipeline_graph_module
from src.pipeline import nodes
from src.pipeline.graph import (
    STEP_METADATA,
    _snapshot_node_inputs,
    _snapshot_state_inputs,
    _with_input_snapshot,
)
from src.pipeline.verdict_assembly import (
    apply_audit_guardrail as _apply_audit_guardrail,
)
from src.pipeline.verdict_assembly import (
    build_advisory_relevance_summary as _build_advisory_relevance_summary,
)
from src.pipeline.verdict_assembly import (
    build_audit_summary_emphasis as _build_audit_summary_emphasis,
)
from src.pipeline.verdict_assembly import (
    build_audit_view as _build_audit_view,
)
from src.pipeline.verdict_assembly import (
    build_developer_ticket_text as _build_developer_ticket_text,
)
from src.pipeline.verdict_assembly import (
    build_executive_summary as _build_executive_summary,
)
from src.pipeline.verdict_assembly import (
    build_final_claims as _build_final_claims,
)
from src.pipeline.verdict_assembly import (
    build_remediation_view as _build_remediation_view,
)
from src.pipeline.verdict_assembly import (
    build_researcher_view as _build_researcher_view,
)
from src.pipeline.verdict_assembly import (
    build_structured_details as _build_structured_details,
)
from src.pipeline.verdict_assembly import (
    build_version_analysis_summary as _build_version_analysis_summary,
)


class _DummyLLM:
    def __init__(self, last_usage=None):
        self.last_usage = last_usage


def test_build_executive_summary_separates_advisory_from_final_assessment():
    summary = _build_executive_summary(
        vuln_id="GHSA-test-1234",
        component_name="web-app",
        final_state={
            "advisory_relevant": True,
            "advisories": {
                "summary": "A template sanitizer bypass can allow script execution."
            },
            "dep_info": {
                "component_name": "framework-core",
                "presence_basis": "direct",
                "declared_in": ["package.json"],
                "lock_files": ["package-lock.json"],
            },
            "llm_analysis": {
                "reachable": False,
                "reasoning": "Templates use only static attribute names and values.",
            },
            "deep_analysis": {
                "confirmed": False,
                "exploitable": "NO",
                "reasoning": "No attacker-controlled value reaches Angular's namespace handling.",
            },
        },
        verdict_label="Not Affected",
        confidence="High",
        exposure="none",
        reasoning="The locked version is outside the affected range.",
        version_analysis={
            "detected_version": "9.4.2",
            "current_workspace_affected": False,
        },
        remediation_view={"status": "already_not_affected", "recommendations": []},
        audit_view={"status": "pass", "consistency": "strong"},
    )

    assert summary["vulnerability"] == (
        "GHSA-test-1234 · framework-core: "
        "A template sanitizer bypass can allow script execution."
    )
    assert summary["assessment"].startswith(
        "Disposition: Not Affected. Confidence: High. Exposure: none. "
        "Audit: status pass; evidence consistency strong."
    )
    assert "outside the affected range" in summary["assessment"]
    assert summary["why"] == [
        "Advisory applicability: Applicable — the advisory matches the assessed dependency context.",
        "Dependency evidence: framework-core is a direct dependency; declared in package.json; observed in package-lock.json.",
        "Version evidence: current dependency version 9.4.2 is outside the advisory's affected range.",
        "Direct reachability (current workspace): Not confirmed — no complete production path to the vulnerability-specific surface was established. Templates use only static attribute names and values.",
        "Deep exploitability (current workspace): Exploitability: No; vulnerability-specific path: not confirmed. No attacker-controlled value reaches Angular's namespace handling.",
        "Audit assurance: status pass; evidence consistency strong.",
        "Assessment conclusion: The locked version is outside the affected range.",
    ]


def test_build_executive_summary_distinguishes_lookup_failure_from_project_target():
    summary = _build_executive_summary(
        vuln_id="GHSA-37CH-88JC-XWX2",
        component_name="vp-auth-server",
        final_state={
            "advisories": {
                "lookup_failures": ["OSV returned HTTP 404"],
            },
            "dep_info": {
                "presence_basis": "unknown",
                "reason": "The vulnerable package could not be resolved.",
            },
        },
        verdict_label="Inconclusive",
        confidence="Low",
        exposure="unknown",
        reasoning="Advisory evidence is incomplete.",
        version_analysis=None,
        remediation_view=None,
        audit_view=None,
    )

    assert summary["vulnerability"] == (
        "GHSA-37CH-88JC-XWX2 · the unresolved vulnerable dependency: "
        "advisory details could not be retrieved; see the Advisory Lookup evidence."
    )
    assert "vp-auth-server" not in summary["vulnerability"]


def test_build_executive_summary_includes_one_action_without_truncating_text():
    advisory_summary = "impact " * 200 + "ADVISORY_END"
    audit_basis = "version evidence " * 100 + "BASIS_END"
    next_action = (
        "Upgrade the vulnerable dependency "
        + "carefully " * 50
        + "ACTION_END"
    )
    summary = _build_executive_summary(
        vuln_id="CVE-TEST",
        component_name="service",
        final_state={"advisories": {"summary": advisory_summary}},
        verdict_label="Probably Affected",
        confidence="Medium",
        exposure="direct",
        reasoning="evidence " * 200,
        version_analysis=None,
        remediation_view={
            "status": "action_needed",
            "recommendations": [
                next_action,
                "A second action is intentionally omitted.",
            ],
        },
        audit_view={
            "status": "review",
            "consistency": "mixed",
            "checks": [f"Concern: {audit_basis}"],
        },
    )

    assert "Audit: status review; evidence consistency mixed." in summary["assessment"]
    assert "ADVISORY_END" in summary["vulnerability"]
    assert "BASIS_END" in summary["assessment"]
    assert "ACTION_END" in summary["assessment"]
    assert "A second action is intentionally omitted." not in summary["assessment"]
    assert "evidence evidence" not in summary["assessment"]
    assert "Required action: Upgrade the vulnerable dependency" in summary["assessment"]
    assert "…" not in summary["vulnerability"]
    assert "…" not in summary["assessment"]
    assert "BASIS_END" in " ".join(summary["why"])


def test_build_executive_summary_explains_affected_path_with_concrete_evidence():
    summary = _build_executive_summary(
        vuln_id="CVE-PATH",
        component_name="web-service",
        final_state={
            "advisories": {"summary": "Crafted input can reach an unsafe parser."},
            "dep_info": {
                "component_name": "unsafe-parser",
                "presence_basis": "transitive",
                "lock_files": ["package-lock.json"],
            },
            "llm_analysis": {
                "reachable": True,
                "reasoning": "src/upload.ts passes request bodies to parseArchive().",
            },
            "deep_analysis": {
                "confirmed": True,
                "exploitable": "YES",
                "reasoning": "The request body reaches the vulnerable parser without validation.",
            },
            "transitive_analysis": {
                "reachable": "YES",
                "reasoning": "upload-middleware calls unsafe-parser on the production route.",
            },
        },
        verdict_label="Affected",
        confidence="High",
        exposure="transitive",
        reasoning="The affected parser is reachable from an unauthenticated upload route.",
        version_analysis={
            "detected_version": "4.1.0",
            "version_source": "lock file",
            "current_workspace_affected": True,
            "workspace_note": "4.1.0 falls in >=4.0.0, <4.1.2.",
            "verified_affected_project_versions": ["7.2.0", "7.3.0"],
        },
        remediation_view={"status": "action_needed", "recommendations": []},
        audit_view={"status": "pass", "consistency": "strong"},
    )

    why = "\n".join(summary["why"])
    assert "Dependency evidence:" in why
    assert "Version evidence:" in why
    assert "Direct reachability (current workspace): Reachable" in why
    assert "Deep exploitability (current workspace): Exploitability: Yes" in why
    assert "Transitive reachability (current workspace): Classification: Reachable" in why
    assert "Audit assurance: status pass; evidence consistency strong" in why
    assert "unsafe-parser is a transitive dependency" in why
    assert "4.1.0 (lock file) is inside" in why
    assert "product versions 7.2.0, 7.3.0" in why
    assert "src/upload.ts passes request bodies to parseArchive()" in why
    assert "request body reaches the vulnerable parser without validation" in why
    assert "upload-middleware calls unsafe-parser" in why
    assert "unauthenticated upload route" in why


async def _fake_analyze_with_llm(*args, **kwargs):
    return {
        "reachable": False,
        "reasoning": "LLM analysis unavailable: OpenWebUI request failed: Model not found",
        "error": "OpenWebUI request failed: Model not found",
        "risk_areas": [],
        "invocation_paths": [],
    }


async def _fake_deep_analyze_with_llm(*args, **kwargs):
    return {
        "confirmed": False,
        "exploitable": "UNCERTAIN",
        "risk_level": "LOW",
        "mitigations": "unknown",
        "reasoning": "Deep analysis unavailable: OpenWebUI request failed: Model not found",
        "error": "OpenWebUI request failed: Model not found",
    }


def test_inspect_archives_node_reports_tool_results(monkeypatch, tmp_path):
    inspection = {
        "discovered": 2,
        "inspected": 1,
        "archives": [
            {
                "path": "source.zip",
                "format": "zip",
                "nesting_level": 0,
                "members": 3,
                "extracted_bytes": 120,
                "scan_root": "__agentyzer_archives__/run/source/content",
            }
        ],
        "errors": [{"path": "broken.rar", "error": "invalid archive"}],
        "truncated": False,
        "limits": {},
    }
    monkeypatch.setattr(
        nodes.archive_extractor,
        "inspect_repository_archives",
        lambda repo_path, workspace_id: inspection,
    )

    async def _run_inline(function, *args):
        return function(*args)

    monkeypatch.setattr(nodes.asyncio, "to_thread", _run_inline)

    result = asyncio.run(
        nodes.inspect_archives(
            {"repo_path": str(tmp_path), "workspace_id": "archive-run"}
        )
    )

    assert result["archive_inspection"] == inspection
    report = result["step_reports"]["inspect_archives"]
    assert report["status"] == "partial"
    assert report["findings"]["inspected"] == 1
    assert any("source.zip" in evidence for evidence in report["evidence"])


def test_repository_scan_branches_do_blocking_work_concurrently(monkeypatch, tmp_path):
    rendezvous = threading.Barrier(2)

    def _fake_find_component(*_args, **_kwargs):
        rendezvous.wait(timeout=2)
        return {
            "found": False,
            "repo_found": False,
            "sbom_attributed": True,
            "presence_basis": "not_found",
            "direct": False,
            "transitive": False,
            "declared_in": [],
            "locked_version": None,
            "lock_files": [],
        }

    def _fake_analyze_repository(*_args, **_kwargs):
        rendezvous.wait(timeout=2)
        return nodes.ast_analyzer.SymbolGraph()

    monkeypatch.setattr(
        nodes.dependency_scanner,
        "find_component",
        _fake_find_component,
    )
    monkeypatch.setattr(
        nodes.ast_analyzer,
        "analyze_repository",
        _fake_analyze_repository,
    )
    monkeypatch.setattr(
        nodes.code_scanner,
        "search_usage",
        lambda *_args, **_kwargs: ["No direct usage found"],
    )
    monkeypatch.setattr(
        nodes.code_scanner,
        "collect_structure",
        lambda *_args, **_kwargs: "",
    )
    monkeypatch.setattr(
        nodes.code_scanner,
        "collect_snippets",
        lambda *_args, **_kwargs: [],
    )

    state = {
        "repo_path": str(tmp_path),
        "component_name": "demo",
        "scan_targets": ["demo"],
        "sbom_attributed": True,
        "advisories": {"vulnerable_symbols": [], "cwe": []},
        "archive_inspection": {},
    }

    async def _run_branches():
        return await asyncio.gather(
            nodes.scan_dependencies(state),
            nodes.scan_code(state),
        )

    dependency_result, code_result = asyncio.run(_run_branches())

    assert dependency_result["dep_info"]["found"] is False
    assert code_result["usage"] == ["No direct usage found"]


def test_build_advisory_analysis_input_preserves_markdown_details():
    advisory_text = "## Impact\n\nThe vulnerable path reaches `parse_header()`.\n\n- user input is attacker-controlled"
    result = nodes._build_advisory_analysis_input(
        "GHSA-xxxx-yyyy-zzzz",
        {
            "summary": "Short summary",
            "affected_packages": ["npm:libfoo"],
            "cwe": ["CWE-120"],
            "vulnerable_symbols": ["libfoo.parse_header"],
            "raw": {"osv_ghsa": {"details": advisory_text}},
        },
    )

    assert "Summary: Short summary" in result
    assert "Advisory details (verbatim markdown/plaintext):" in result
    assert "## Impact" in result
    assert "`parse_header()`" in result


def test_build_advisory_analysis_input_requests_supplemental_sources_when_incomplete():
    result = nodes._build_advisory_analysis_input(
        "GHSA-xxxx-yyyy-zzzz",
        {
            "summary": "Markdown-only GHSA summary",
            "sources": ["osv", "github_search"],
            "affected_packages": ["PyPI:libfoo"],
            "cwe": ["CWE-79"],
            "affected_ranges": [],
            "affected_versions": [],
            "fixed_versions": [],
            "cvss": [],
            "vulnerable_symbols": [],
            "data_warnings": [
                "Advisory has no affected ranges or explicit version lists"
            ],
            "raw": {
                "osv": {"id": "GHSA-xxxx-yyyy-zzzz"},
                "github_search": {"items": []},
            },
        },
    )

    assert (
        "Vulnerability sources used: osv:available, github_search:available" in result
    )
    assert "CWEs: ['CWE-79']" in result
    assert "Advisory data warnings:" in result
    assert "Critical advisory gaps for analysis:" in result
    assert "Missing affected version ranges or explicit affected versions" in result
    assert "Additional source request:" in result
    assert "prioritize NVD" in result


def test_llm_analyze_code_step_report_includes_backend_error(monkeypatch):
    monkeypatch.setattr(nodes.code_scanner, "analyze_with_llm", _fake_analyze_with_llm)

    result = asyncio.run(
        nodes.llm_analyze_code(
            {
                "ollama": _DummyLLM(),
                "vuln_id": "GHSA-test",
                "scan_targets": ["pkg"],
                "advisories": {"summary": "summary", "affected_packages": ["npm:pkg"]},
                "snippets": [{"file": "app.py", "line": 12, "snippet": "danger()"}],
            }
        )
    )

    findings = result["step_reports"]["llm_analyze_code"]["findings"]
    evidence = result["step_reports"]["llm_analyze_code"]["evidence"]

    assert findings["error"] == "OpenWebUI request failed: Model not found"
    assert any(
        "LLM error: OpenWebUI request failed: Model not found" in line
        for line in evidence
    )


def test_llm_deep_analyze_step_report_includes_backend_error(monkeypatch):
    monkeypatch.setattr(
        nodes.code_scanner, "deep_analyze_with_llm", _fake_deep_analyze_with_llm
    )
    monkeypatch.setattr(
        nodes.code_scanner,
        "extract_path_context",
        lambda *args, **kwargs: [{"file": "app.py", "content": "danger()"}],
    )

    result = asyncio.run(
        nodes.llm_deep_analyze(
            {
                "ollama": _DummyLLM(),
                "vuln_id": "GHSA-test",
                "repo_path": "/tmp/repo",
                "advisories": {"summary": "summary", "affected_packages": ["npm:pkg"]},
                "llm_analysis": {
                    "reachable": True,
                    "invocation_paths": ["app.handler -> danger"],
                },
                "snippets": [{"file": "app.py", "line": 12, "snippet": "danger()"}],
            }
        )
    )

    findings = result["step_reports"]["llm_deep_analyze"]["findings"]
    evidence = result["step_reports"]["llm_deep_analyze"]["evidence"]

    assert findings["error"] == "OpenWebUI request failed: Model not found"
    assert any(
        "LLM error: OpenWebUI request failed: Model not found" in line
        for line in evidence
    )


def test_llm_analyze_code_step_report_includes_usage(monkeypatch):
    monkeypatch.setattr(nodes.code_scanner, "analyze_with_llm", _fake_analyze_with_llm)

    result = asyncio.run(
        nodes.llm_analyze_code(
            {
                "ollama": _DummyLLM(
                    {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}
                ),
                "vuln_id": "GHSA-test",
                "scan_targets": ["pkg"],
                "advisories": {"summary": "summary", "affected_packages": ["npm:pkg"]},
                "snippets": [{"file": "app.py", "line": 12, "snippet": "danger()"}],
            }
        )
    )

    findings = result["step_reports"]["llm_analyze_code"]["findings"]
    evidence = result["step_reports"]["llm_analyze_code"]["evidence"]

    assert findings["llm_usage"] == {
        "prompt_tokens": 11,
        "completion_tokens": 7,
        "total_tokens": 18,
    }
    assert any(
        "LLM usage: prompt=11, completion=7, total=18" in line for line in evidence
    )


def test_llm_deep_analyze_step_report_includes_usage(monkeypatch):
    monkeypatch.setattr(
        nodes.code_scanner, "deep_analyze_with_llm", _fake_deep_analyze_with_llm
    )
    monkeypatch.setattr(
        nodes.code_scanner,
        "extract_path_context",
        lambda *args, **kwargs: [{"file": "app.py", "content": "danger()"}],
    )

    result = asyncio.run(
        nodes.llm_deep_analyze(
            {
                "ollama": _DummyLLM(
                    {"prompt_tokens": 21, "completion_tokens": 9, "total_tokens": 30}
                ),
                "vuln_id": "GHSA-test",
                "repo_path": "/tmp/repo",
                "advisories": {"summary": "summary", "affected_packages": ["npm:pkg"]},
                "llm_analysis": {
                    "reachable": True,
                    "invocation_paths": ["app.handler -> danger"],
                },
                "snippets": [{"file": "app.py", "line": 12, "snippet": "danger()"}],
            }
        )
    )

    findings = result["step_reports"]["llm_deep_analyze"]["findings"]
    evidence = result["step_reports"]["llm_deep_analyze"]["evidence"]

    assert findings["llm_usage"] == {
        "prompt_tokens": 21,
        "completion_tokens": 9,
        "total_tokens": 30,
    }
    assert any(
        "LLM usage: prompt=21, completion=9, total=30" in line for line in evidence
    )


def test_build_version_analysis_summary_includes_fallback_checked_version():
    summary = _build_version_analysis_summary(
        {
            "version_context": {
                "detected_version": "2.0.0",
                "version_source": "lock file",
                "affected": True,
                "note": "lock file matched the advisory",
            },
            "version_inventory": {},
        }
    )

    assert summary is not None
    assert summary["checked_versions"] == [
            {
                "ref": "DETECTED",
                "ref_type": "resolved",
                "product_version": None,
                "version": "2.0.0",
                "source": "lock file",
            "affected": True,
            "notes": "lock file matched the advisory",
        }
    ]


def test_build_version_analysis_summary_marks_not_found_rows_unknown():
    summary = _build_version_analysis_summary(
        {
            "version_context": {
                "affected": False,
                "current_workspace_affected": False,
            },
            "version_inventory": {
                "version_table": [
                    {
                        "ref": "WORKTREE",
                        "ref_type": "worktree",
                        "component_version": "-",
                        "source": "manifest",
                        "affected": "No",
                        "notes": "not found",
                    },
                    {
                        "ref": "WORKTREE",
                        "ref_type": "worktree",
                        "component_version": ">=2.0.0",
                        "source": "manifest-constraint",
                        "affected": "Unknown",
                        "notes": "not a resolved installed version",
                    },
                ],
                "worst_case": {"affected": False},
            },
        }
    )

    assert summary is not None
    assert summary["checked_versions"][0]["affected"] is None
    assert summary["checked_versions"][0]["notes"] == "not found"
    assert summary["checked_versions"][1]["affected"] is None
    assert summary["checked_versions"][1]["version"] == ">=2.0.0"


def test_build_version_analysis_summary_includes_product_version_coverage():
    summary = _build_version_analysis_summary(
        {
            "version_context": {
                "affected": True,
                "current_workspace_affected": False,
                "project_versions": ["1.0.0", "1.1.0"],
                "project_version_refs": {"1.0.0": ["v1.0.0"]},
                "covered_product_versions": ["1.0.0"],
                "verified_affected_project_versions": ["1.0.0"],
                "unmatched_project_versions": ["1.1.0"],
            },
            "version_inventory": {
                "version_table": [
                    {
                        "ref": "v1.0.0",
                        "ref_type": "tag",
                        "product_version": "1.0.0",
                        "component_version": "4.17.21",
                        "source": "lock",
                        "affected": "YES",
                        "notes": "version is in the affected range",
                    },
                    {
                        "ref": "1.1.0",
                        "ref_type": "product-version",
                        "product_version": "1.1.0",
                        "component_version": "-",
                        "source": "dtvp",
                        "affected": "No",
                        "notes": "DTVP reported this affected product version, but no matching tag or branch was found in the repository",
                    },
                ],
                "worst_case": {"affected": True},
            },
        }
    )

    assert summary is not None
    assert summary["project_versions"] == ["1.0.0", "1.1.0"]
    assert summary["project_version_refs"] == {"1.0.0": ["v1.0.0"]}
    assert summary["covered_product_versions"] == ["1.0.0"]
    assert summary["verified_affected_project_versions"] == ["1.0.0"]
    assert summary["unmatched_project_versions"] == ["1.1.0"]
    assert summary["checked_versions"][0]["product_version"] == "1.0.0"
    assert summary["checked_versions"][1]["product_version"] == "1.1.0"
    assert summary["checked_versions"][1]["affected"] is None


def test_build_version_analysis_summary_keeps_workspace_and_historical_flags():
    summary = _build_version_analysis_summary(
        {
            "version_context": {
                "detected_version": "4.18.1",
                "version_source": "lock file",
                "affected": True,
                "current_workspace_affected": False,
                "note": "current workspace version is outside the affected range, but one or more tracked releases shipped an affected version",
                "workspace_note": "lock file — version is outside the affected ranges",
            },
            "version_inventory": {
                "worst_case": {
                    "historical_affected": [
                        {
                            "ref": "6.15.0",
                            "ref_type": "tag",
                            "component_version": "4.17.21",
                        }
                    ]
                }
            },
        }
    )

    assert summary is not None
    assert summary["affected"] is True
    assert summary["current_workspace_affected"] is False
    assert (
        summary["workspace_note"]
        == "lock file — version is outside the affected ranges"
    )
    assert summary["historical_affected"] == [
        {"ref": "6.15.0", "ref_type": "tag", "component_version": "4.17.21"}
    ]


def test_build_researcher_view_describes_historical_only_affected_versions():
    view = _build_researcher_view(
        final_state={"dep_info": {"found": True, "direct": False, "transitive": True}},
        advisory_relevance=None,
        version_analysis={
            "detected_version": "4.18.1",
            "version_source": "lock file",
            "affected": True,
            "current_workspace_affected": False,
        },
        verdict_label="Probably Affected",
        reasoning="Historical releases were affected.",
    )

    assert any(
        "tracked releases shipped an affected version" in finding
        for finding in view["findings"]
    )


def test_detect_project_ecosystems_includes_nested_manifests(tmp_path):
    nested = tmp_path / "services" / "dicom-worker"
    nested.mkdir(parents=True)
    (nested / "package.json").write_text('{"name":"dicom-worker"}\n')

    ecosystems = nodes._detect_project_ecosystems(str(tmp_path))

    assert "npm" in ecosystems


def test_list_project_manifests_includes_nested_manifest_paths(tmp_path):
    nested = tmp_path / "apps" / "service-a"
    nested.mkdir(parents=True)
    (nested / "pyproject.toml").write_text('[project]\nname = "service-a"\n')

    manifests = nodes._list_project_manifests(str(tmp_path))

    assert "apps/service-a/pyproject.toml" in manifests


def test_snapshot_state_inputs_excludes_audit_fields_and_serializes_objects():
    dummy = _DummyLLM()
    snapshot = _snapshot_state_inputs(
        {
            "component_name": "werkzeug",
            "ollama": dummy,
            "step_reports": {"ignored": True},
            "evidence": ["ignored"],
        }
    )

    assert snapshot == {
        "component_name": "werkzeug",
        "ollama": repr(dummy),
    }


def test_with_input_snapshot_injects_full_node_inputs():
    async def node(state):
        await asyncio.sleep(0)
        return {
            "step_reports": {
                "analyze_versions": {
                    "title": "Version Analysis",
                    "status": "ok",
                    "findings": {"locked_version": "2.0.0"},
                    "evidence": [],
                }
            }
        }

    wrapped = _with_input_snapshot("analyze_versions", node)
    state = {
        "component_name": "werkzeug",
        "debug": True,
        "advisories": {"affected_ranges": [{"type": "SEMVER"}]},
        "dep_info": {"locked_version": "2.0.0"},
        "evidence": ["ignored"],
        "step_reports": {"ignored": True},
        "repo_path": "/tmp/repo",
    }

    result = asyncio.run(wrapped(state))
    inputs = result["step_reports"]["analyze_versions"]["findings"]["inputs"]

    assert inputs == {
        "advisories": {"affected_ranges": [{"type": "SEMVER"}]},
        "component_name": "werkzeug",
        "dep_info": {"locked_version": "2.0.0"},
        "repo_path": "/tmp/repo",
    }


def test_snapshot_node_inputs_filters_to_relevant_fields():
    snapshot = _snapshot_node_inputs(
        "fetch_advisory",
        {
            "vuln_id": "CVE-2024-49766",
            "component_name": "werkzeug",
            "advisories": {"affected_versions": ["2.0.0", "3.0.2"]},
            "repo_path": "/tmp/repo",
        },
    )

    assert snapshot == {"vuln_id": "CVE-2024-49766"}


def test_analyze_versions_passes_project_version_file_configuration(monkeypatch):
    captured = {}

    monkeypatch.setattr(
        nodes.version_analyzer,
        "select_component_affected_constraints",
        lambda *_args, **_kwargs: {
            "affected_ranges": [],
            "affected_versions": [],
            "fixed_versions": [],
            "selected_range_count": 0,
            "selected_version_count": 0,
            "excluded_packages": [],
        },
    )

    def fake_inventory(*_args, **kwargs):
        captured.update(kwargs)
        return {
            "version_table": [],
            "worst_case": {"affected": False},
            "comparison_inputs": {},
            "trace": [],
        }

    monkeypatch.setattr(nodes.version_analyzer, "inventory_versions", fake_inventory)

    asyncio.run(
        nodes.analyze_versions(
            {
                "component_name": "example-project",
                "scan_target": "example-lib",
                "component_cfg": {
                    "project_version_files": [
                        {
                            "path": "config/release.json",
                            "field": "project.release",
                        }
                    ]
                },
                "advisories": {},
                "dep_info": {},
                "repo_path": "/tmp/example-project",
                "affected_product_versions": ["3.1.0"],
            }
        )
    )

    assert captured["affected_product_versions"] == ["3.1.0"]
    assert captured["project_version_files"] == [
        {"path": "config/release.json", "field": "project.release"}
    ]


def test_with_input_snapshot_skips_inputs_without_debug():
    async def node(state):
        await asyncio.sleep(0)
        return {
            "step_reports": {
                "analyze_versions": {
                    "title": "Version Analysis",
                    "status": "ok",
                    "findings": {"locked_version": "2.0.0"},
                    "evidence": [],
                }
            }
        }

    wrapped = _with_input_snapshot("analyze_versions", node)
    result = asyncio.run(
        wrapped(
            {
                "component_name": "werkzeug",
                "dep_info": {"locked_version": "2.0.0"},
            }
        )
    )

    assert "inputs" not in result["step_reports"]["analyze_versions"]["findings"]


def test_with_input_snapshot_emits_progress_events():
    events = []

    async def node(state):
        await asyncio.sleep(0)
        return {
            "step_reports": {
                "analyze_versions": {
                    "title": "Version Analysis",
                    "status": "affected",
                    "findings": {"locked_version": "2.0.0"},
                    "evidence": [],
                }
            }
        }

    async def progress_callback(event):
        await asyncio.sleep(0)
        events.append(event)

    wrapped = _with_input_snapshot("analyze_versions", node)
    asyncio.run(
        wrapped(
            {
                "component_name": "werkzeug",
                "progress_callback": progress_callback,
            }
        )
    )

    assert [event["phase"] for event in events] == ["start", "completed"]
    assert events[0]["agent"] == STEP_METADATA["analyze_versions"]["agent"]
    assert events[1]["status"] == "affected"
    assert events[1]["report"]["title"] == "Version Analysis"


def test_with_input_snapshot_emits_model_wait_heartbeat(monkeypatch):
    events = []

    async def run_case():
        release = asyncio.Event()

        async def node(state):
            await release.wait()
            return {
                "step_reports": {
                    "llm_analyze_code": {
                        "title": "LLM Reachability Analysis",
                        "status": "ok",
                        "findings": {},
                        "evidence": [],
                    }
                }
            }

        async def progress_callback(event):
            events.append(event)

        monkeypatch.setattr(pipeline_graph_module, "MODEL_HEARTBEAT_SECONDS", 0.01)
        wrapped = _with_input_snapshot("llm_analyze_code", node)
        task = asyncio.create_task(
            wrapped(
                {
                    "component_name": "werkzeug",
                    "progress_callback": progress_callback,
                }
            )
        )
        await asyncio.sleep(0.03)
        release.set()
        await task

    asyncio.run(run_case())

    phases = [event["phase"] for event in events]
    assert phases[0] == "start"
    assert "heartbeat" in phases
    assert phases[-1] == "completed"
    heartbeat = next(event for event in events if event["phase"] == "heartbeat")
    assert heartbeat["step"] == "llm_analyze_code"
    assert "Waiting for model response" in heartbeat["activity"]


def test_build_advisory_relevance_summary_detects_llm_source():
    summary = _build_advisory_relevance_summary(
        {
            "filter_advisory": {
                "status": "filtered",
                "findings": {
                    "relevant": False,
                    "reasons": [
                        "LLM relevance decision (high confidence)",
                        "Priority ERP is standalone software, not a Python package",
                    ],
                },
            }
        }
    )

    assert summary == {
        "relevant": False,
        "status": "filtered",
        "source": "llm",
        "reasons": [
            "LLM relevance decision (high confidence)",
            "Priority ERP is standalone software, not a Python package",
        ],
    }


def test_build_structured_details_includes_advisory_filter_section():
    details = _build_structured_details(
        vuln_id="CVE-2023-23459",
        component_name="eventservice",
        repo_url="https://example.invalid/repo.git",
        repo_path="/tmp/repo",
        verdict_label="Not Affected",
        confidence="High",
        affected=False,
        exposure="none",
        reasoning="The advisory was filtered as irrelevant before repository analysis.",
        adj_cvss={},
        cvss_vec=None,
        cvss_score=None,
        advisory_relevance={
            "relevant": False,
            "status": "filtered",
            "source": "llm",
            "reasons": [
                "LLM relevance decision (high confidence)",
                "Priority ERP is standalone software, not a Python dependency",
            ],
        },
        advisories={
            "summary": "Priority ERP before 22.1 has an authentication bypass.",
            "affected_packages": ["NVD:priority"],
        },
        dep_info={"found": False},
        result={},
    )

    assert "Filter decision:  filtered out" in details
    assert "Decision source:  LLM" in details
    assert "Priority ERP is standalone software, not a Python dependency" in details


def test_build_audit_view_fails_unsupported_not_affected_downgrade():
    audit_view = _build_audit_view(
        final_state={
            "dep_info": {"found": True},
            "llm_analysis": {"reachable": True},
            "deep_analysis": {"exploitable": "YES"},
            "transitive_analysis": {"reachable": "UNCERTAIN"},
        },
        verdict_label="Not Affected",
        affected=False,
        reasoning="The downgrade is questionable.",
        version_analysis={"affected": True},
        adjusted_cvss={"adjusted_score": 0.0},
    )

    assert audit_view["status"] == "fail"
    assert audit_view["downgrade_target"] is True
    assert audit_view["downgrade_supported"] is False
    assert any(
        "conflicts" in check.lower() or "weaker" in check.lower()
        for check in audit_view["checks"]
    )


def test_build_audit_view_allows_historical_only_not_affected_with_exclusion_evidence():
    audit_view = _build_audit_view(
        final_state={
            "dep_info": {"found": True},
            "llm_analysis": {"reachable": False},
            "deep_analysis": {"exploitable": "NO"},
            "transitive_analysis": {"reachable": "NO"},
        },
        verdict_label="Not Affected",
        affected=False,
        reasoning="Production code does not import or invoke the vulnerable functionality.",
        version_analysis={"affected": True, "current_workspace_affected": False},
        adjusted_cvss={"adjusted_score": 0.0},
    )

    assert audit_view["status"] == "pass"
    assert audit_view["downgrade_supported"] is True
    assert any(
        "affirmatively excludes reachability" in check for check in audit_view["checks"]
    )


def test_build_audit_view_allows_deep_exclusion_after_generic_reachability():
    audit_view = _build_audit_view(
        final_state={
            "dep_info": {"found": True},
            "llm_analysis": {"reachable": True},
            "deep_analysis": {"confirmed": False, "exploitable": "NO"},
            "transitive_analysis": {"reachable": "NO"},
        },
        verdict_label="Not Affected",
        affected=False,
        reasoning=(
            "The dependency is used, but full-source review excludes the "
            "vulnerability-specific runtime template path."
        ),
        version_analysis={"affected": True, "current_workspace_affected": True},
        adjusted_cvss={"adjusted_score": 0.0},
    )

    assert audit_view["status"] == "pass"
    assert audit_view["consistency"] == "strong"
    assert audit_view["downgrade_supported"] is True
    assert audit_view["final_claims"]["issues"] == []
    assert any(
        "deep analysis affirmatively exclude" in check
        for check in audit_view["checks"]
    )
    assert any(
        "after generic dependency reachability" in check
        for check in audit_view["checks"]
    )


def test_build_final_claims_flags_fixed_version_floor_contradiction():
    claims = _build_final_claims(
        result={
            "verdict": "Affected",
            "affected": True,
            "reasoning": (
                "Evidence: Project uses zlib 1.2.13 which is within the "
                "affected range. Fix: Upgrade zlib to version 1.2.11 or higher."
            ),
        },
        version_analysis={
            "detected_version": "1.2.13",
            "affected": True,
            "current_workspace_affected": True,
        },
        final_state={
            "dep_info": {"found": True},
            "llm_analysis": {"reachable": True},
        },
    )

    issue = claims["issues"][0]
    assert issue["kind"] == "fixed_version_floor_contradiction"
    assert issue["claim"]["fixed_version_floor"] == "1.2.11"
    assert issue["evidence"]["detected_version"] == "1.2.13"


def test_build_final_claims_ignores_advisory_fixed_ranges_without_text_claim():
    claims = _build_final_claims(
        result={
            "verdict": "Not Affected",
            "affected": False,
            "reasoning": "The current workspace lock is patched and unreachable.",
        },
        version_analysis={
            "detected_version": "1.2.13",
            "affected": False,
            "current_workspace_affected": False,
            "affected_ranges_summary": ["SEMVER range: introduced=0 fixed=1.2.11"],
        },
        final_state={
            "dep_info": {"found": True},
            "llm_analysis": {"reachable": False},
            "deep_analysis": {"exploitable": "NO"},
            "transitive_analysis": {"reachable": "NO"},
        },
    )

    assert not [
        issue
        for issue in claims["issues"]
        if issue["kind"] == "fixed_version_floor_contradiction"
    ]


def test_build_audit_view_includes_structured_claim_issues():
    audit_view = _build_audit_view(
        final_state={
            "dep_info": {"found": True},
            "llm_analysis": {"reachable": True},
            "deep_analysis": {},
            "transitive_analysis": {},
        },
        verdict_label="Affected",
        affected=True,
        reasoning=(
            "Evidence: Project uses zlib 1.2.13 which is within the affected "
            "range. Fix: Upgrade zlib to version 1.2.11 or higher."
        ),
        version_analysis={
            "detected_version": "1.2.13",
            "affected": True,
            "current_workspace_affected": True,
        },
        adjusted_cvss={"adjusted_score": 9.8},
    )

    assert audit_view["status"] == "review"
    assert audit_view["consistency"] == "mixed"
    assert audit_view["claim_issues"][0]["kind"] == "fixed_version_floor_contradiction"
    assert any(
        "final claims are inconsistent" in check
        and "1.2.13" in check
        and "1.2.11" in check
        for check in audit_view["checks"]
    )


def test_build_researcher_view_marks_sbom_attributed_presence_without_repo_match():
    researcher_view = _build_researcher_view(
        final_state={
            "dep_info": {
                "found": True,
                "repo_found": False,
                "sbom_attributed": True,
                "presence_basis": "sbom_attributed",
            }
        },
        advisory_relevance=None,
        version_analysis=None,
        verdict_label="Probably Affected",
        reasoning="Evidence remains plausible because the package was attributed from the project SBOM.",
    )

    assert (
        "Dependency presence: present via SBOM attribution, but not rediscovered in local manifests or lock files"
        in researcher_view["findings"]
    )


def test_build_structured_details_marks_sbom_attributed_presence_without_repo_match():
    details = _build_structured_details(
        vuln_id="CVE-2024-9999",
        component_name="benchmark",
        repo_url="https://example.invalid/repo.git",
        repo_path="/tmp/repo",
        verdict_label="Probably Affected",
        confidence="Low",
        affected=True,
        exposure="transitive",
        reasoning="Current evidence is incomplete but the dependency is still attributed to the project.",
        adj_cvss={"adjusted_score": 0.0},
        cvss_vec=None,
        cvss_score=0.0,
        advisory_relevance=None,
        advisories={},
        dep_info={
            "found": True,
            "repo_found": False,
            "sbom_attributed": True,
            "presence_basis": "sbom_attributed",
        },
        result={},
    )

    assert (
        "Dependency:      found (sbom-attributed; not rediscovered locally)" in details
    )


def test_scan_dependencies_keeps_presence_unknown_without_advisory_package(
    monkeypatch, tmp_path
):
    def _unexpected_find_component(*_args, **_kwargs):
        pytest.fail("the assessed project must not be scanned as its own dependency")

    monkeypatch.setattr(
        nodes.dependency_scanner, "find_component", _unexpected_find_component
    )

    result = asyncio.run(
        nodes.scan_dependencies(
            {
                "repo_path": str(tmp_path),
                "component_name": "vp-auth-server",
                "scan_targets": [],
            }
        )
    )

    assert result["scan_target"] == ""
    assert result["dep_info"]["presence_basis"] == "unknown"
    assert result["dep_info"]["component_name"] == ""
    assert result["dep_info"]["requested_component"] == "vp-auth-server"
    assert "was not scanned" in result["dep_info"]["reason"]


def test_scan_dependencies_does_not_transfer_sbom_attribution_to_another_package(
    monkeypatch, tmp_path
):
    captured: dict[str, object] = {}

    def _fake_find_component(repo_path, component_name, *, sbom_attributed=False):
        captured["repo_path"] = repo_path
        captured["component_name"] = component_name
        captured["sbom_attributed"] = sbom_attributed
        return {
            "found": False,
            "repo_found": False,
            "sbom_attributed": sbom_attributed,
            "presence_basis": "not_found",
            "direct": False,
            "transitive": False,
            "declared_in": [],
            "locked_version": None,
            "lock_files": [],
        }

    monkeypatch.setattr(
        nodes.dependency_scanner, "find_component", _fake_find_component
    )

    result = asyncio.run(
        nodes.scan_dependencies(
            {
                "repo_path": str(tmp_path),
                "component_name": "vp-auth-server",
                "scan_targets": ["path-to-regexp"],
                "sbom_attributed": True,
            }
        )
    )

    assert captured == {
        "repo_path": str(tmp_path),
        "component_name": "path-to-regexp",
        "sbom_attributed": False,
    }
    assert result["dep_info"]["presence_basis"] == "not_found"


def test_scan_dependencies_selects_the_advisory_package_found_in_the_repo(
    monkeypatch, tmp_path
):
    scanned: list[str] = []

    def _fake_find_component(repo_path, component_name, *, sbom_attributed=False):
        scanned.append(component_name)
        repo_found = component_name == "target-package"
        return {
            "found": repo_found or sbom_attributed,
            "repo_found": repo_found,
            "sbom_attributed": sbom_attributed,
            "presence_basis": "manifest" if repo_found else "sbom_attributed",
            "direct": repo_found,
            "transitive": False,
            "declared_in": ["package.json"] if repo_found else [],
            "locked_version": "3.2.1" if repo_found else None,
            "lock_files": ["package-lock.json"] if repo_found else [],
        }

    monkeypatch.setattr(
        nodes.dependency_scanner, "find_component", _fake_find_component
    )

    result = asyncio.run(
        nodes.scan_dependencies(
            {
                "repo_path": str(tmp_path),
                "component_name": "CVE-2026-1234",
                "scan_targets": ["wrong-package", "target-package"],
            }
        )
    )

    assert scanned == ["wrong-package", "target-package"]
    assert result["scan_target"] == "target-package"
    assert result["dep_info"]["component_name"] == "target-package"
    assert result["dep_info"]["locked_version"] == "3.2.1"


def test_scan_dependencies_prefers_requested_component_without_repo_evidence(
    monkeypatch, tmp_path
):
    scanned: list[str] = []

    def _fake_find_component(repo_path, component_name, *, sbom_attributed=False):
        scanned.append(component_name)
        return {
            "found": sbom_attributed,
            "repo_found": False,
            "sbom_attributed": sbom_attributed,
            "presence_basis": "sbom_attributed",
            "direct": False,
            "transitive": False,
            "declared_in": [],
            "locked_version": None,
            "lock_files": [],
        }

    monkeypatch.setattr(
        nodes.dependency_scanner, "find_component", _fake_find_component
    )

    result = asyncio.run(
        nodes.scan_dependencies(
            {
                "repo_path": str(tmp_path),
                "component_name": "target-package",
                "scan_targets": ["wrong-package", "target-package"],
            }
        )
    )

    assert scanned == ["target-package", "wrong-package"]
    assert result["scan_target"] == "target-package"
    assert result["dep_info"]["presence_basis"] == "sbom_attributed"


def test_run_pipeline_defaults_sbom_attributed_true(monkeypatch, tmp_path):
    captured: dict[str, object] = {}

    class _FakeGraph:
        async def ainvoke(self, initial_state):
            captured["initial_state"] = initial_state
            return {
                **initial_state,
                "result": {
                    "affected": False,
                    "verdict": "Inconclusive",
                    "confidence": "Low",
                    "exposure": "none",
                    "reasoning": "stub",
                },
                "step_reports": {},
            }

    monkeypatch.setattr(pipeline_graph_module, "graph", _FakeGraph())

    result = asyncio.run(
        pipeline_graph_module.run_pipeline(
            vuln_id="CVE-2024-9999",
            component_cfg={"name": "demo-component"},
            focus_path=str(tmp_path),
        )
    )

    initial_state = captured["initial_state"]
    assert initial_state["sbom_attributed"] is True
    assert result["assessment"]["verdict"] == "Inconclusive"
    assert result["assessment"]["dependency_presence"]["sbom_attributed"] is False


def test_run_pipeline_respects_sbom_attributed_override(monkeypatch, tmp_path):
    captured: dict[str, object] = {}

    class _FakeGraph:
        async def ainvoke(self, initial_state):
            captured["initial_state"] = initial_state
            return {
                **initial_state,
                "result": {
                    "affected": False,
                    "verdict": "Inconclusive",
                    "confidence": "Low",
                    "exposure": "none",
                    "reasoning": "stub",
                },
                "step_reports": {},
            }

    monkeypatch.setattr(pipeline_graph_module, "graph", _FakeGraph())

    result = asyncio.run(
        pipeline_graph_module.run_pipeline(
            vuln_id="CVE-2024-9999",
            component_cfg={"name": "demo-component", "sbom_attributed": False},
            focus_path=str(tmp_path),
        )
    )

    initial_state = captured["initial_state"]
    assert initial_state["sbom_attributed"] is False
    assert result["assessment"]["verdict"] == "Inconclusive"
    assert result["assessment"]["dependency_presence"]["sbom_attributed"] is False


def test_run_pipeline_cleans_isolated_worktree_after_graph_failure(monkeypatch):
    captured: dict[str, object] = {}

    class _FailingGraph:
        async def ainvoke(self, initial_state):
            captured["workspace_id"] = initial_state["workspace_id"]
            raise RuntimeError("pipeline failed")

    async def _fake_cleanup(component_cfg, *, workspace_id):
        captured["cleanup_component_cfg"] = component_cfg
        captured["cleanup_workspace_id"] = workspace_id

    monkeypatch.setattr(pipeline_graph_module, "graph", _FailingGraph())
    monkeypatch.setattr(
        pipeline_graph_module.dependency_scanner,
        "cleanup_repo_worktree",
        _fake_cleanup,
    )
    component_cfg = {
        "name": "demo-component",
        "url": "https://example.invalid/core.git",
    }

    with pytest.raises(RuntimeError, match="pipeline failed"):
        asyncio.run(
            pipeline_graph_module.run_pipeline(
                vuln_id="CVE-2024-9999",
                component_cfg=component_cfg,
            )
        )

    assert captured["cleanup_component_cfg"] == component_cfg
    assert captured["cleanup_workspace_id"] == captured["workspace_id"]


def test_build_remediation_view_requires_action_when_audit_fails_downgrade():
    remediation_view = _build_remediation_view(
        final_state={"what_if": {}},
        verdict_label="Not Affected",
        adjusted_cvss={"adjusted_score": 0.0},
        version_analysis={"affected": False},
        exposure="none",
        audit_view={"status": "fail"},
    )

    assert remediation_view["status"] == "action_needed"
    assert "downgrade" in remediation_view["summary"].lower()
    assert remediation_view["recommendations"]


def test_build_remediation_view_targets_vulnerable_dependency_not_component():
    remediation_view = _build_remediation_view(
        final_state={
            "component_name": "owned-service",
            "scan_targets": ["vulnerable-parser"],
            "dep_info": {"component_name": "vulnerable-parser"},
            "what_if": {
                "component_not_found": False,
                "remediation": [
                    {"target_version": "2.0.0", "change": "first fixed release"}
                ],
            },
        },
        verdict_label="Affected",
        adjusted_cvss={"adjusted_score": 9.8},
        version_analysis={"affected": True},
        exposure="direct",
    )

    recommendations = "\n".join(remediation_view["recommendations"])
    assert "Upgrade vulnerable-parser to 2.0.0" in recommendations
    assert "Upgrade owned-service" not in recommendations


def test_build_developer_ticket_text_omits_runtime_internals():
    ticket = _build_developer_ticket_text(
        vuln_id="CVE-2026-0002",
        component_name="owned-service",
        final_state={
            "component_name": "owned-service",
            "scan_targets": ["vulnerable-parser"],
            "llm_analysis": {
                "invocation_paths": [
                    "[PRODUCTION] api.py::handler -> parser.parse()"
                ],
                "reasoning": "Repository Clone completed before analysis.",
            },
        },
        verdict_label="Affected",
        confidence="High",
        affected=True,
        exposure="direct",
        reasoning="Public request input reaches vulnerable-parser.",
        advisories={"summary": "Parser overflow on oversized input."},
        dep_info={"component_name": "vulnerable-parser", "locked_version": "1.0.0"},
        version_analysis={
            "detected_version": "1.0.0",
            "affected": True,
            "affected_ranges_summary": ["SEMVER range: introduced=0 fixed=2.0.0"],
        },
        researcher_view={
            "findings": [
                "Dependency presence: found as a direct dependency",
                "Direct reachability: reachable from production code",
            ],
        },
        remediation_view={
            "recommendations": ["Upgrade vulnerable-parser to 2.0.0"]
        },
        audit_view={"checks": ["Supports verdict: direct production reachability was identified."]},
        adjusted_cvss={"adjusted_score": 9.8},
    )

    assert "owned-service" in ticket
    assert "vulnerable-parser" in ticket
    assert "Upgrade vulnerable-parser to 2.0.0" in ticket
    assert "Repository Clone" not in ticket
    assert "Upgrade owned-service" not in ticket


def test_build_structured_details_prominently_flags_failed_downgrade():
    details = _build_structured_details(
        vuln_id="CVE-2024-9999",
        component_name="benchmark",
        repo_url="https://example.invalid/repo.git",
        repo_path="/tmp/repo",
        verdict_label="Not Affected",
        confidence="Low",
        affected=False,
        exposure="none",
        reasoning="Current evidence is contradictory.",
        adj_cvss={"adjusted_score": 0.0},
        cvss_vec=None,
        cvss_score=0.0,
        advisory_relevance=None,
        advisories={},
        dep_info={"found": True},
        result={},
        audit_view={
            "status": "fail",
            "downgrade_target": True,
            "conclusion": "The downgrade is not supported by the available evidence.",
        },
    )

    assert "AUDIT STATUS:   FAIL" in details
    assert "Do not rely on the downgrade to Not Affected / low-info" in details
    assert (
        "AUDIT BASIS:    The downgrade is not supported by the available evidence."
        in details
    )


def test_build_audit_summary_emphasis_prefixes_failed_downgrade():
    summary = _build_audit_summary_emphasis(
        {
            "status": "fail",
            "downgrade_target": True,
            "conclusion": "The downgrade is not supported.",
        },
        "Current codebase excluded.",
    )

    assert summary.startswith("AUDIT FAILURE:")
    assert "Current codebase excluded." in summary


def test_build_audit_summary_emphasis_prefixes_review_state():
    summary = _build_audit_summary_emphasis(
        {
            "status": "review",
            "downgrade_target": True,
            "conclusion": "The downgrade needs more evidence.",
        },
        "",
    )

    assert summary.startswith("AUDIT REVIEW REQUIRED:")
    assert summary.endswith("The downgrade needs more evidence.")


def test_apply_audit_guardrail_promotes_historical_only_not_affected():
    guarded = _apply_audit_guardrail(
        {
            "verdict": "Not Affected",
            "affected": False,
            "confidence": "Low",
            "reasoning": "Current workspace lock is patched.",
            "adjusted_cvss": {
                "original_score": 6.3,
                "adjusted_score": 0.0,
                "original_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                "adjusted_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                "reasons": ["detected version 4.18.1 (lock file)"],
            },
        },
        {"status": "fail", "downgrade_target": True},
        {
            "affected": True,
            "current_workspace_affected": False,
        },
    )

    assert guarded["verdict"] == "Probably Affected"
    assert guarded["affected"] is True
    assert guarded["confidence"] == "Medium"
    assert "AUDIT GUARDRAIL" in guarded["reasoning"]
    assert guarded["adjusted_cvss"]["adjusted_score"] == 6.3
    assert (
        guarded["adjusted_cvss"]["adjusted_vector"]
        == guarded["adjusted_cvss"]["original_vector"]
    )


def test_apply_audit_guardrail_requires_package_and_version_advisory_evidence():
    guarded = _apply_audit_guardrail(
        {
            "verdict": "Not Affected",
            "affected": False,
            "confidence": "High",
            "exposure": "none",
            "reasoning": "The selected project was not found as a dependency.",
        },
        {"status": "pass", "checks": []},
        None,
        {
            "advisory_relevant": True,
            "advisories": {
                "affected_packages": [],
                "affected_ranges": [],
                "affected_versions": [],
            },
        },
    )

    assert guarded["verdict"] == "Inconclusive"
    assert guarded["affected"] is False
    assert guarded["confidence"] == "Low"
    assert guarded["exposure"] == "unknown"
    assert "INCOMPLETE ADVISORY" in guarded["reasoning"]
    assert "affected package identity" in guarded["summary"]
    assert "affected version constraints" in guarded["summary"]


def test_apply_audit_guardrail_softens_fixed_version_floor_contradiction():
    guarded = _apply_audit_guardrail(
        {
            "verdict": "Affected",
            "affected": True,
            "confidence": "High",
            "reasoning": (
                "Evidence: Project uses zlib 1.2.13 which is within the "
                "affected range. Fix: Upgrade zlib to version 1.2.11 or higher."
            ),
            "version_context": {"detected_version": "1.2.13"},
        },
        {"status": "pass", "checks": []},
        {
            "detected_version": "1.2.13",
            "affected": True,
            "current_workspace_affected": True,
        },
        {
            "dep_info": {"found": True},
            "llm_analysis": {"reachable": True},
        },
    )

    assert guarded["verdict"] == "Inconclusive"
    assert guarded["affected"] is False
    assert guarded["confidence"] == "Low"
    assert "FINAL SANITY CHECK" in guarded["reasoning"]
    assert "1.2.13" in guarded["summary"]
    assert "1.2.11" in guarded["summary"]


def test_audit_guardrail_caps_version_only_affected_verdict():
    result = {
        "verdict": "Affected",
        "affected": True,
        "confidence": "High",
        "exposure": "transitive",
        "reasoning": (
            "Desc: CVE-2026-5038 leaves orphaned upload files. "
            "Surface: multipart uploads via diskStorage. "
            "Evidence: package-lock.json contains multer 2.1.1 in the "
            "affected range, but local analysis found no direct imports. "
            "Fix: Upgrade multer to 2.2.0. "
            "Validate: Confirm whether diskStorage is used."
        ),
    }
    final_state = {
        "dep_info": {
            "found": True,
            "repo_found": True,
            "transitive": True,
            "locked_version": "2.1.1",
            "lock_files": ["package-lock.json"],
        },
        "llm_analysis": {"reachable": False},
        "deep_analysis": {"confirmed": False, "exploitable": "NO"},
        "transitive_analysis": {"reachable": "NO"},
        "result": result,
    }
    version_analysis = {
        "detected_version": "2.1.1",
        "affected": True,
        "current_workspace_affected": True,
    }
    audit = _build_audit_view(
        final_state=final_state,
        verdict_label=result["verdict"],
        affected=result["affected"],
        reasoning=result["reasoning"],
        version_analysis=version_analysis,
    )

    assert any(
        issue["kind"] == "affected_without_confirmed_path"
        for issue in audit["final_claims"]["issues"]
    )

    guarded = _apply_audit_guardrail(
        result,
        audit,
        version_analysis,
        final_state,
    )
    assert guarded["verdict"] == "Probably Affected"
    assert guarded["affected"] is True
    assert guarded["confidence"] == "Medium"
    assert "VERSION-ONLY EVIDENCE" in guarded["reasoning"]
    assert "diskStorage" in guarded["reasoning"]


def test_audit_guardrail_keeps_affected_when_vulnerable_surface_is_reachable():
    result = {
        "verdict": "Affected",
        "affected": True,
        "confidence": "High",
        "exposure": "direct",
        "reasoning": "Production upload handling calls multer diskStorage.",
    }
    final_state = {
        "dep_info": {"found": True, "locked_version": "2.1.1"},
        "llm_analysis": {"reachable": True},
        "deep_analysis": {"confirmed": True, "exploitable": "YES"},
        "transitive_analysis": {"reachable": "NO"},
        "result": result,
    }
    version_analysis = {
        "detected_version": "2.1.1",
        "affected": True,
        "current_workspace_affected": True,
    }
    claims = _build_final_claims(
        result=result,
        version_analysis=version_analysis,
        final_state=final_state,
    )

    assert not any(
        issue["kind"] == "affected_without_confirmed_path"
        for issue in claims["issues"]
    )
    assert (
        _apply_audit_guardrail(
            result,
            {"status": "pass", "final_claims": claims},
            version_analysis,
            final_state,
        )
        == result
    )


def test_upstream_platform_research_supports_probably_affected_scope():
    result = {
        "verdict": "Affected",
        "affected": True,
        "confidence": "High",
        "exposure": "transitive",
        "reasoning": (
            "The local extension does not call Netty, but external research "
            "confirms that the upstream Keycloak runtime is vulnerable."
        ),
        "research_log": [
            {
                "round": 0,
                "required": True,
                "directives": [
                    {
                        "type": "search",
                        "target": "Keycloak netty CVE-2026-47691 dependency version",
                    }
                ],
                "results_summary": (
                    "--- Search results for: Keycloak netty CVE-2026-47691 --- "
                    "Keycloak runtime dependency information and affected versions."
                ),
            }
        ],
    }
    final_state = {
        "dep_info": {
            "found": True,
            "repo_found": False,
            "sbom_attributed": True,
            "presence_basis": "sbom_attributed",
        },
        "llm_analysis": {"reachable": False},
        "deep_analysis": {"confirmed": False, "exploitable": "NO"},
        "transitive_analysis": {"reachable": "NO"},
        "user_guidance": "This project extends Keycloak.",
        "result": result,
    }
    version_analysis = {
        "affected": False,
        "current_workspace_affected": False,
    }

    audit = _build_audit_view(
        final_state=final_state,
        verdict_label=result["verdict"],
        affected=result["affected"],
        reasoning=result["reasoning"],
        version_analysis=version_analysis,
    )
    guarded = _apply_audit_guardrail(
        result,
        audit,
        version_analysis,
        final_state,
    )
    guarded_audit = _build_audit_view(
        final_state=final_state,
        verdict_label=guarded["verdict"],
        affected=guarded["affected"],
        reasoning=guarded["reasoning"],
        version_analysis=version_analysis,
    )

    assert audit["final_claims"]["evidence"]["upstream_platform_support"] is True
    assert not any(
        issue["kind"] == "unsupported_affected"
        for issue in audit["final_claims"]["issues"]
    )
    assert guarded["verdict"] == "Probably Affected"
    assert guarded["affected"] is True
    assert guarded["confidence"] == "Medium"
    assert "UPSTREAM PLATFORM SCOPE" in guarded["reasoning"]
    assert guarded_audit["status"] == "pass"


def test_upstream_guidance_without_successful_research_remains_unsupported():
    result = {
        "verdict": "Probably Affected",
        "affected": True,
        "confidence": "Medium",
        "exposure": "transitive",
        "reasoning": "Analyst guidance says upstream Keycloak is vulnerable.",
        "research_log": [
            {
                "round": 0,
                "required": True,
                "scope": "upstream_platform",
                "directives": [{"type": "search", "target": "Keycloak Netty"}],
                "results_summary": (
                    "--- Search failed: Keycloak Netty "
                    "(provider challenge page) ---"
                ),
            }
        ],
    }
    final_state = {
        "dep_info": {
            "found": True,
            "repo_found": False,
            "sbom_attributed": True,
        },
        "llm_analysis": {"reachable": False},
        "deep_analysis": {"confirmed": False, "exploitable": "NO"},
        "transitive_analysis": {"reachable": "NO"},
        "user_guidance": "This project extends Keycloak.",
        "result": result,
    }
    version_analysis = {
        "affected": False,
        "current_workspace_affected": False,
    }
    claims = _build_final_claims(
        result=result,
        version_analysis=version_analysis,
        final_state=final_state,
    )

    assert claims["evidence"]["upstream_platform_research"] is False
    assert any(issue["kind"] == "unsupported_affected" for issue in claims["issues"])

    guarded = _apply_audit_guardrail(
        result,
        {"status": "fail", "final_claims": claims},
        version_analysis,
        final_state,
    )
    assert guarded["verdict"] == "Inconclusive"
    assert guarded["affected"] is False


def test_run_pipeline_promotes_unsupported_historical_only_not_affected(
    monkeypatch,
    tmp_path,
):
    captured: dict[str, object] = {}

    class _FakeGraph:
        async def ainvoke(self, initial_state):
            captured["initial_state"] = initial_state
            return {
                **initial_state,
                "advisories": {
                    "affected_packages": ["npm:lodash"],
                    "affected_ranges": [
                        {
                            "type": "SEMVER",
                            "event": {"introduced": "0", "fixed": "4.17.22"},
                            "package": "lodash",
                        }
                    ],
                },
                "dep_info": {"found": True, "transitive": True},
                "version_inventory": {
                    "worst_case": {
                        "affected": True,
                        "current_workspace_affected": False,
                        "historical_affected": [
                            {
                                "ref": "6.15.0",
                                "ref_type": "tag",
                                "component_version": "4.17.21",
                            }
                        ],
                    }
                },
                "result": {
                    "affected": False,
                    "verdict": "Not Affected",
                    "confidence": "Low",
                    "exposure": "transitive",
                    "reasoning": "Workspace lock is outside the affected range.",
                    "adjusted_cvss": {
                        "original_score": 6.3,
                        "adjusted_score": 0.0,
                        "original_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                        "adjusted_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                        "version_context": {
                            "detected_version": "4.18.1",
                            "version_source": "lock file",
                            "affected": True,
                            "current_workspace_affected": False,
                            "note": "current workspace version is outside the affected range, but one or more tracked releases shipped an affected version",
                        },
                    },
                    "version_context": {
                        "detected_version": "4.18.1",
                        "version_source": "lock file",
                        "affected": True,
                        "current_workspace_affected": False,
                        "note": "current workspace version is outside the affected range, but one or more tracked releases shipped an affected version",
                    },
                },
                "step_reports": {
                    "aggregate_verdict": {
                        "title": "Final Verdict",
                        "status": "Not Affected",
                        "findings": {
                            "verdict": "Not Affected",
                            "confidence": "Low",
                            "affected": False,
                            "exposure": "transitive",
                            "reasoning": "Workspace lock is outside the affected range.",
                        },
                        "evidence": [
                            "Final verdict: Not Affected (confidence=Low)"
                        ],
                    },
                },
            }

    monkeypatch.setattr(pipeline_graph_module, "graph", _FakeGraph())

    result = asyncio.run(
        pipeline_graph_module.run_pipeline(
            vuln_id="GHSA-test",
            component_cfg={"name": "lodash"},
            focus_path=str(tmp_path),
        )
    )

    assessment = result["assessment"]
    assert assessment["verdict"] == "Probably Affected"
    assert assessment["affected"] is True
    assert assessment["analysis"] == "IN_TRIAGE"
    assert assessment["audit_view"]["status"] != "fail"
    assert assessment["cvss_score"] == 6.3
    final_step = next(step for step in result["steps"] if step["step"] == "aggregate_verdict")
    assert final_step["status"] == "Probably Affected"
    assert final_step["findings"]["verdict"] == "Probably Affected"
    assert final_step["evidence"][0] == "Final verdict: Probably Affected (confidence=Medium)"


def test_run_pipeline_keeps_not_affected_when_historical_only_but_unreachable(
    monkeypatch,
    tmp_path,
):
    class _FakeGraph:
        async def ainvoke(self, initial_state):
            return {
                **initial_state,
                "advisories": {
                    "affected_packages": ["npm:lodash"],
                    "affected_ranges": [
                        {
                            "type": "SEMVER",
                            "event": {"introduced": "0", "fixed": "4.17.22"},
                            "package": "lodash",
                        }
                    ],
                },
                "dep_info": {"found": True, "transitive": True},
                "llm_analysis": {
                    "reachable": False,
                    "reasoning": "production code does not import or invoke the vulnerable _.unset or _.omit functions, eliminating any runtime exploitability",
                },
                "deep_analysis": {"exploitable": "NO"},
                "transitive_analysis": {"reachable": "NO"},
                "version_inventory": {
                    "worst_case": {
                        "affected": True,
                        "current_workspace_affected": False,
                        "historical_affected": [
                            {
                                "ref": "6.15.0",
                                "ref_type": "tag",
                                "component_version": "4.17.21",
                            }
                        ],
                    }
                },
                "result": {
                    "affected": False,
                    "verdict": "Not Affected",
                    "confidence": "High",
                    "exposure": "transitive",
                    "reasoning": "production code does not import or invoke the vulnerable _.unset or _.omit functions, eliminating any runtime exploitability",
                    "adjusted_cvss": {
                        "original_score": 6.3,
                        "adjusted_score": 0.0,
                        "original_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                        "adjusted_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                        "version_context": {
                            "detected_version": "4.18.1",
                            "version_source": "lock file",
                            "affected": True,
                            "current_workspace_affected": False,
                            "note": "current workspace version is outside the affected range, but one or more tracked releases shipped an affected version",
                        },
                    },
                    "version_context": {
                        "detected_version": "4.18.1",
                        "version_source": "lock file",
                        "affected": True,
                        "current_workspace_affected": False,
                        "note": "current workspace version is outside the affected range, but one or more tracked releases shipped an affected version",
                    },
                },
                "step_reports": {},
            }

    monkeypatch.setattr(pipeline_graph_module, "graph", _FakeGraph())

    result = asyncio.run(
        pipeline_graph_module.run_pipeline(
            vuln_id="GHSA-test",
            component_cfg={"name": "lodash"},
            focus_path=str(tmp_path),
        )
    )

    assessment = result["assessment"]
    assert assessment["verdict"] == "Not Affected"
    assert assessment["affected"] is False
    assert assessment["audit_view"]["status"] == "pass"
    assert assessment["analysis"] == "NOT_AFFECTED"
