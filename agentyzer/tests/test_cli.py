from src import cli


def test_print_assessment_pretty_prints_debug_sections(capsys):
    cli._print_assessment(
        {
            "assessment": {
                "affected": True,
                "verdict": "Affected",
                "confidence": "High",
                "exposure": "direct",
                "version_analysis": {
                    "detected_version": "2.0.0",
                    "version_source": "lock file",
                    "affected": True,
                    "note": "version is in the explicit affected versions list",
                    "checked_versions": [
                        {
                            "ref": "LOCKED",
                            "ref_type": "lock",
                            "version": "2.0.0",
                            "affected": True,
                            "source": None,
                            "notes": "lock file — version is in the explicit affected versions list",
                        },
                        {
                            "ref": "v3.1.0",
                            "ref_type": "tag",
                            "version": "3.1.0",
                            "affected": False,
                            "source": "manifest",
                            "notes": "version is outside the affected ranges",
                        },
                    ],
                },
                "summary": "Direct dependency with reachable vulnerable code path.",
                "reasoning": "Version and reachability both confirm impact.",
                "adjusted_cvss": {
                    "original_score": 6.3,
                    "adjusted_score": 6.3,
                    "version": "4.0",
                    "reasons": ["version matched"],
                    "version_context": {
                        "detected_version": "2.0.0",
                        "version_source": "lock file",
                        "affected_ranges_summary": [
                            "SEMVER range: introduced=0 fixed=3.0.6 (source=osv_ghsa)",
                            "Explicit affected versions: 2 listed",
                        ],
                        "comparison_inputs": {
                            "component_name": "werkzeug",
                            "locked_version": "2.0.0",
                            "affected_ranges_summary": [
                                "ECOSYSTEM range: introduced=0 fixed=3.0.6 (source=osv_ghsa)"
                            ],
                            "affected_versions_count": 2,
                        },
                        "comparison_trace": [
                            "Affected ranges: 1 SEMVER/ECOSYSTEM, 0 GIT, 2 explicit versions",
                            "version=2.0.0: MATCH in explicit affected versions list",
                        ],
                    },
                },
            },
            "steps": [
                {
                    "step": "analyze_versions",
                    "title": "Version Analysis",
                    "status": "affected",
                    "findings": {
                        "inputs": {
                            "component_name": "werkzeug",
                            "debug": True,
                            "advisories": {
                                "affected_ranges_count": 1,
                                "affected_versions_count": 2,
                            },
                        }
                    },
                    "evidence": ["Locked version: 2.0.0"],
                }
            ],
        }
    )

    out = capsys.readouterr().out
    assert "Version analysis: 2.0.0 (lock file, affected)" in out
    assert "Project versions analyzed:" in out
    assert (
        "- LOCKED (lock): 2.0.0 — AFFECTED (lock file — version is in the explicit affected versions list)"
        in out
    )
    assert (
        "- v3.1.0 (tag): 3.1.0 — not affected [manifest] (version is outside the affected ranges)"
        in out
    )
    assert "version debug inputs:" in out
    assert "component: werkzeug" in out
    assert "affected range summaries:" in out
    assert "trace:" in out
    assert "- Affected ranges: 1 SEMVER/ECOSYSTEM, 0 GIT, 2 explicit versions" in out
    assert "node inputs:" in out
    assert "advisory summary:" in out
    assert "explicit affected versions: 2" in out


def test_print_assessment_uses_friendly_labels_and_order(capsys):
    cli._print_assessment(
        {
            "assessment": {
                "affected": True,
                "verdict": "Affected",
                "confidence": "High",
                "exposure": "direct",
                "summary": "Test.",
                "reasoning": "Test.",
                "adjusted_cvss": {
                    "original_score": 6.3,
                    "adjusted_score": 6.3,
                    "version": "4.0",
                    "reasons": [],
                    "version_context": {
                        "detected_version": "2.0.0",
                        "version_source": "lock file",
                        "affected_ranges_summary": [],
                        "comparison_inputs": {
                            "debug": True,
                            "repo_path": "/tmp/repo",
                            "component_name": "werkzeug",
                            "locked_version": "2.0.0",
                        },
                    },
                },
            },
            "steps": [],
        }
    )

    out = capsys.readouterr().out
    component_index = out.index("component: werkzeug")
    repo_index = out.index("repository path: /tmp/repo")
    debug_index = out.index("debug mode: True")
    assert component_index < repo_index < debug_index


def test_print_assessment_includes_advisory_relevance(capsys):
    cli._print_assessment(
        {
            "assessment": {
                "affected": False,
                "verdict": "Not Affected",
                "confidence": "High",
                "exposure": "none",
                "advisory_relevance": {
                    "relevant": False,
                    "source": "llm",
                    "reasons": [
                        "LLM relevance decision (high confidence)",
                        "Priority ERP is standalone software, not a Python package",
                    ],
                },
                "summary": "Filtered before repo analysis.",
                "reasoning": "The advisory does not target the project ecosystem.",
                "adjusted_cvss": None,
            },
            "steps": [],
        }
    )

    out = capsys.readouterr().out
    assert "Advisory filter: filtered out (llm)" in out
    assert "Priority ERP is standalone software, not a Python package" in out


def test_print_assessment_omits_debug_sections_when_absent(capsys):
    cli._print_assessment(
        {
            "assessment": {
                "affected": False,
                "verdict": "Not Affected",
                "confidence": "High",
                "exposure": "none",
                "summary": "No affected version detected.",
                "reasoning": "Locked version is outside the advisory range.",
                "adjusted_cvss": {
                    "original_score": 6.3,
                    "adjusted_score": 0.0,
                    "version": "4.0",
                    "reasons": ["version not affected"],
                    "version_context": {
                        "detected_version": "3.1.0",
                        "version_source": "lock file",
                        "affected_ranges_summary": [
                            "SEMVER range: introduced=0 fixed=3.0.6 (source=osv_ghsa)"
                        ],
                    },
                },
            },
            "steps": [],
        }
    )

    out = capsys.readouterr().out
    assert "version debug inputs:" not in out
    assert "trace:" not in out


def test_print_assessment_includes_multi_role_views(capsys):
    cli._print_assessment(
        {
            "assessment": {
                "affected": False,
                "verdict": "Not Affected",
                "confidence": "High",
                "exposure": "none",
                "summary": "Current codebase excluded.",
                "reasoning": "The assessed version is outside the advisory range.",
                "researcher_view": {
                    "objective": "Check whether the weakness applies.",
                    "conclusion": "The current codebase is not affected.",
                    "findings": [
                        "Dependency presence: vulnerable component not found in the assessed project"
                    ],
                },
                "remediation_view": {
                    "objective": "Keep the finding at low/info or not affected.",
                    "summary": "No remediation needed.",
                    "recommendations": ["Reassess after dependency changes."],
                },
                "audit_view": {
                    "objective": "Critically review the downgrade.",
                    "status": "pass",
                    "consistency": "strong",
                    "downgrade_target": True,
                    "downgrade_supported": True,
                    "checks": [
                        "Supports verdict: the vulnerable component was not found in the assessed project."
                    ],
                    "conclusion": "The evidence supports the downgrade.",
                },
                "adjusted_cvss": None,
            },
            "steps": [],
        }
    )

    out = capsys.readouterr().out
    assert "Researcher view:" in out
    assert "Remediation view:" in out
    assert "Audit view:" in out
    assert "status: pass" in out
    assert "consistency: strong" in out


def test_print_assessment_summarizes_bulky_debug_values(capsys):
    cli._print_assessment(
        {
            "assessment": {
                "affected": True,
                "verdict": "Affected",
                "confidence": "High",
                "exposure": "direct",
                "summary": "Test.",
                "reasoning": "Test.",
                "adjusted_cvss": None,
            },
            "steps": [
                {
                    "step": "aggregate_verdict",
                    "title": "Final Verdict",
                    "status": "Affected",
                    "findings": {
                        "inputs": {
                            "llm_analysis": {
                                "reachable": True,
                                "confidence": "High",
                                "reasoning": "Reachable through request path.",
                            },
                            "version_inventory": {
                                "version_table": [
                                    {"ref": "LOCKED", "affected": "YES"},
                                    {"ref": "WORKTREE", "affected": "YES"},
                                ],
                                "worst_case": {"affected": True},
                            },
                            "usage": [
                                "src/app.py:10 uses werkzeug",
                                "src/routes.py:40 imports Request",
                                "src/views.py:5 imports Response",
                                "src/extra.py:8 extra hit",
                            ],
                        }
                    },
                    "evidence": [],
                }
            ],
        }
    )

    out = capsys.readouterr().out
    assert "LLM analysis: reachable=True, confidence=High" in out
    assert "version inventory: 2 version rows, worst_case_affected=True" in out
    assert (
        "code usage hits: 4 items: src/app.py:10 uses werkzeug, src/routes.py:40 imports Request, src/views.py:5 imports Response, ..."
        in out
    )
