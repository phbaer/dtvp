import asyncio

import pytest

from src.agents import verdict


def test_strip_version_details_from_reasoning_removes_checked_versions_block():
    reasoning = (
        "The dependency is present and reachable from production code. "
        "Checked versions: LOCKED (2.0.0, AFFECTED), main (2.0.0, AFFECTED), "
        "v1.9.0 (1.9.0, not affected). All checked versions are within the advisory range. "
        "This is a direct exposure."
    )

    stripped = verdict._strip_version_details_from_reasoning(reasoning)

    assert "Checked versions:" not in stripped
    assert "All checked versions" not in stripped
    assert stripped == "The dependency is present and reachable from production code"


def test_verdict_prompt_pins_uncertain_transitive_cases_to_probable_affected():
    prompt = verdict._VERDICT_SYSTEM_PROMPT

    assert "Keep analysis private" in prompt
    assert "Use four compact lenses before answering" in prompt
    assert "Auditor: reject unsupported downgrades" in prompt
    assert "VERDICT: Affected|Probably Affected|Inconclusive|Not Affected" in (
        verdict._VERDICT_RESPONSE_CONTRACT
    )
    assert "Do not add markdown, JSON, preamble" in verdict._VERDICT_RESPONSE_CONTRACT
    assert (
        "Current version affected + transitive path UNCERTAIN -> request source/search if not already fetched; then Probably Affected, not Not Affected."
        in prompt
    )
    assert "request FETCH_SEARCH, FETCH_URL, or FETCH_SOURCE before final fields" in prompt
    assert (
        "Not Affected/exposure=none require affirmative exclusion for the assessed codebase"
        in prompt
    )
    assert "missing local rediscovery does not disprove an SBOM-attributed dependency" in prompt
    assert "Analyst guidance is a hypothesis or investigation hint, not evidence" in prompt
    assert "dependency evidence is only SBOM/input attribution and the version is unknown" in prompt
    assert "guidance names an upstream platform/framework/runtime" in prompt
    assert "Validate: fetch/check/confirm" in prompt


def test_upstream_guidance_extracts_platform_names():
    guidance = (
        "This project extends Keycloak.\n"
        "If the extension is not affected, still consider whether upstream Keycloak itself is vulnerable."
    )

    assert verdict._extract_upstream_platforms_from_guidance(guidance) == ["Keycloak"]


def test_mandatory_upstream_research_query_for_sbom_only_unknown_version():
    query = verdict._mandatory_upstream_research_query(
        vuln_id="CVE-2026-47691",
        advisory_packages=["NVD:netty"],
        dep_info={
            "found": True,
            "sbom_attributed": True,
            "repo_found": False,
            "presence_basis": "sbom_attributed",
        },
        version_ctx={"detected_version": None},
        llm_analysis={"reachable": False},
        transitive_analysis={},
        user_guidance="This project extends Keycloak.",
        vulnerable_component="netty",
    )

    assert query == "Keycloak netty CVE-2026-47691 dependency version"


def test_llm_verdict_prefetches_upstream_research_for_keycloak_guidance(
    monkeypatch,
):
    captured_directives = []

    async def fake_fulfill(directives, vulnerable_component=""):
        captured_directives.append((directives, vulnerable_component))
        return (
            f"--- Search results for: {directives[0]['target']} ---\n"
            "Search results:\n"
            "1. Keycloak dependency documentation\n"
        )

    class FakeOllama:
        def __init__(self):
            self.prompts = []

        async def generate(self, prompt, **kwargs):
            self.prompts.append(prompt)
            return (
                "VERDICT: Inconclusive\n"
                "CONFIDENCE: Low\n"
                "AFFECTED: true\n"
                "EXPOSURE: transitive\n"
                "REASONING: Desc: Netty DNS issue. Surface: upstream platform "
                "uncertain. Evidence: mandatory search was provided. Fix: update "
                "the dependency through the platform. Validate: verify the resolved tree."
            )

    monkeypatch.setattr(verdict, "fulfill_directives", fake_fulfill)
    ollama = FakeOllama()

    result = asyncio.run(
        verdict._llm_verdict(
            ollama=ollama,
            vuln_id="CVE-2026-47691",
            advisories={
                "summary": "Netty DNS cache poisoning.",
                "affected_packages": ["NVD:netty"],
                "affected_ranges": [],
            },
            dep_info={
                "found": True,
                "sbom_attributed": True,
                "repo_found": False,
                "presence_basis": "sbom_attributed",
            },
            usage=[],
            version_inventory={
                "version_table": [
                    {
                        "ref": "WORKTREE",
                        "ref_type": "worktree",
                        "component_version": "-",
                        "source": "manifest",
                        "notes": "not found",
                        "affected": "?",
                    }
                ],
                "worst_case": {"affected": False},
            },
            llm_analysis={"reachable": False, "reasoning": "No direct path."},
            transitive_analysis={},
            user_guidance=(
                "This project extends Keycloak.\n"
                "If the extension is not affected, still consider whether upstream Keycloak itself is vulnerable."
            ),
            vulnerable_component="netty",
        )
    )

    assert captured_directives == [
        (
            [
                {
                    "type": "search",
                    "target": "Keycloak netty CVE-2026-47691 dependency version",
                }
            ],
            "netty",
        )
    ]
    assert (
        "--- RESEARCH RESULTS (mandatory upstream-platform check) ---"
        in ollama.prompts[0]
    )
    assert (
        "Search results for: Keycloak netty CVE-2026-47691 dependency version"
        in ollama.prompts[0]
    )
    assert "FETCH_SEARCH: Keycloak netty CVE-2026-47691 dependency version" in (
        ollama.prompts[0]
    )
    assert result["research_log"][0]["required"] is True
    assert result["research_log"][0]["directives"][0]["type"] == "search"


def test_heuristic_verdict_does_not_treat_repo_miss_as_absence():
    result = verdict._heuristic_verdict(
        dep_found=False,
        dep_direct=False,
        dep_transitive=False,
        reach="Not Reachable",
        worst_affected=True,
        has_advisory_data=True,
        llm_reachable=False,
        transitive_reachable="",
        adjusted_cvss=None,
        version_inventory={"version_table": [], "worst_case": {"affected": True}},
        dep_info={},
    )

    assert result["verdict"] == "Probably Affected"
    assert result["affected"] is True
    assert result["exposure"] == "transitive"


def test_format_transitive_evidence_includes_snippets_and_research():
    text = verdict._format_transitive_evidence(
        {
            "reachable": "UNCERTAIN",
            "confidence": "Low",
            "intermediary": "flask",
            "usage_hits": 2,
            "reasoning": "Flask may delegate request parsing to werkzeug internals.",
            "dependency_chains": ["flask → werkzeug (via uv.lock)"],
            "snippets": [
                {
                    "file": "src/app.py",
                    "line": 10,
                    "snippet": "from flask import Request\nvalue = Request(args)\n",
                }
            ],
            "structure_excerpt": "=== src/app.py ===\n  from flask import Request\n",
            "research_log": [
                {
                    "round": 1,
                    "results_summary": "Fetched flask source showing request handling wrappers around werkzeug request objects.",
                }
            ],
        }
    )

    assert "Dependency chains:" in text
    assert "Project snippets using intermediary packages:" in text
    assert "--- src/app.py:10 ---" in text
    assert "Intermediary/source research results:" in text
    assert "flask source showing request handling wrappers" in text


def test_extract_version_context_keeps_overall_note_for_historical_affected_only():
    ctx = verdict._extract_version_context(
        {
            "version_table": [
                {
                    "ref": "LOCKED",
                    "component_version": "4.18.1",
                    "source": "lock",
                    "notes": "lock file — version is outside the affected ranges",
                }
            ],
            "worst_case": {
                "affected": True,
                "current_workspace_affected": False,
                "note": "current workspace version is outside the affected range, but one or more tracked releases shipped an affected version",
                "historical_affected": [
                    {
                        "ref": "6.15.0",
                        "ref_type": "tag",
                        "component_version": "4.17.21",
                    }
                ],
            },
        },
        {"locked_version": "4.18.1"},
    )

    assert ctx["detected_version"] == "4.18.1"
    assert ctx["affected"] is True
    assert ctx["current_workspace_affected"] is False
    assert "tracked releases shipped an affected version" in ctx["note"]
    assert ctx["workspace_note"] == "lock file — version is outside the affected ranges"


def test_fix_contradictions_promotes_historical_only_not_affected_without_unreachability():
    result = verdict._fix_contradictions(
        {
            "verdict": "Not Affected",
            "affected": False,
            "confidence": "Low",
            "reasoning": "Workspace lock is patched.",
        },
        llm_reachable=False,
        deep_confirmed=False,
        deep_exploitable="UNCERTAIN",
        dep_found=True,
        dep_direct=False,
        transitive_reachable="UNCERTAIN",
        worst_affected=True,
        current_workspace_affected=False,
    )

    assert result["verdict"] == "Probably Affected"
    assert result["affected"] is True
    assert "tracked release shipped an affected version" in result["reasoning"]


def test_fix_contradictions_promotes_historical_only_inconclusive_without_unreachability():
    result = verdict._fix_contradictions(
        {
            "verdict": "Inconclusive",
            "affected": False,
            "confidence": "Low",
            "reasoning": "Workspace is patched but historical evidence is mixed.",
        },
        llm_reachable=False,
        deep_confirmed=False,
        deep_exploitable="UNCERTAIN",
        dep_found=True,
        dep_direct=False,
        transitive_reachable="UNCERTAIN",
        worst_affected=True,
        current_workspace_affected=False,
    )

    assert result["verdict"] == "Probably Affected"
    assert result["affected"] is True
    assert "overrode weak LLM verdict" in result["reasoning"]


def test_fix_contradictions_rejects_sbom_only_unknown_version_not_affected():
    result = verdict._fix_contradictions(
        {
            "verdict": "Not Affected",
            "affected": False,
            "confidence": "High",
            "exposure": "none",
            "reasoning": "Evidence: no Netty dependency is present in the analyzed workspace or manifests.",
        },
        llm_reachable=False,
        deep_confirmed=False,
        deep_exploitable="UNCERTAIN",
        dep_found=True,
        dep_direct=False,
        dep_info={
            "sbom_attributed": True,
            "repo_found": False,
            "presence_basis": "sbom_attributed",
        },
        transitive_reachable="",
        worst_affected=False,
        current_workspace_affected=False,
        version_unknown=True,
    )

    assert result["verdict"] == "Inconclusive"
    assert result["affected"] is False
    assert result["exposure"] == "transitive"
    assert "SBOM-attributed but not rediscovered locally" in result["reasoning"]
    assert "no Netty dependency is present" not in result["reasoning"]
