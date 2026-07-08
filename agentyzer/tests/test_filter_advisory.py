"""Tests for the filter_advisory pipeline node."""

import asyncio

from src.pipeline.nodes import _detect_project_ecosystems, filter_advisory


class _FakeLLM:
    def __init__(self, response: str, *, fail: bool = False):
        self.response = response
        self.fail = fail
        self.prompts: list[str] = []

    async def generate(self, prompt: str, **kwargs):
        self.prompts.append(prompt)
        if self.fail:
            raise RuntimeError("boom")
        return self.response


# -- _detect_project_ecosystems ------------------------------------------


def test_detect_ecosystems_python_project(tmp_path):
    (tmp_path / "pyproject.toml").touch()
    (tmp_path / "requirements.txt").touch()
    eco = _detect_project_ecosystems(str(tmp_path))
    assert eco == {"PyPI"}


def test_detect_ecosystems_node_project(tmp_path):
    (tmp_path / "package.json").touch()
    eco = _detect_project_ecosystems(str(tmp_path))
    assert eco == {"npm"}


def test_detect_ecosystems_multi(tmp_path):
    (tmp_path / "pyproject.toml").touch()
    (tmp_path / "package.json").touch()
    eco = _detect_project_ecosystems(str(tmp_path))
    assert eco == {"PyPI", "npm"}


def test_detect_ecosystems_no_repo():
    assert _detect_project_ecosystems(None) == set()
    assert _detect_project_ecosystems("") == set()
    assert _detect_project_ecosystems("/nonexistent") == set()


# -- filter_advisory node ------------------------------------------------


def _run(coro):
    return asyncio.run(coro)


def _make_state(**overrides):
    base = {
        "component_name": "eventservice",
        "component_cfg": {},
        "advisories": {},
        "scan_targets": [],
        "repo_path": "",
    }
    base.update(overrides)
    return base


def test_no_advisory_data_passes_through():
    result = _run(filter_advisory(_make_state()))
    assert result["advisory_relevant"] is True


def test_osv_ecosystem_match_python(tmp_path):
    """PyPI advisory + Python project → relevant."""
    (tmp_path / "pyproject.toml").touch()
    state = _make_state(
        advisories={"affected_packages": ["PyPI:werkzeug"]},
        repo_path=str(tmp_path),
    )
    result = _run(filter_advisory(state))
    assert result["advisory_relevant"] is True


def test_osv_ecosystem_mismatch_npm_vs_python(tmp_path):
    """npm advisory + Python project → irrelevant."""
    (tmp_path / "pyproject.toml").touch()
    state = _make_state(
        advisories={"affected_packages": ["npm:lodash"]},
        repo_path=str(tmp_path),
    )
    result = _run(filter_advisory(state))
    assert result["advisory_relevant"] is False
    assert (
        "ecosystem mismatch"
        in result["step_reports"]["filter_advisory"]["findings"]["reasons"][0]
    )


def test_nvd_only_advisory_no_name_match():
    """NVD-only advisory with product name not matching component → irrelevant."""
    state = _make_state(
        advisories={
            "affected_packages": ["NVD:priority"],
            "cpe_entries": [
                {
                    "part": "a",
                    "vendor": "priority-software",
                    "product": "priority",
                    "cpe": "cpe:2.3:a:priority-software:priority:*:*:*:*:*:*:*:*",
                }
            ],
        },
        scan_targets=["priority"],
        component_name="eventservice",
    )
    result = _run(filter_advisory(state))
    assert result["advisory_relevant"] is False
    assert (
        "NVD CPE data"
        in result["step_reports"]["filter_advisory"]["findings"]["reasons"][0]
    )


def test_nvd_only_advisory_name_matches_component():
    """NVD-only advisory but product matches component name → relevant."""
    state = _make_state(
        advisories={
            "affected_packages": ["NVD:eventservice"],
            "cpe_entries": [
                {
                    "part": "a",
                    "vendor": "example",
                    "product": "eventservice",
                    "cpe": "cpe:2.3:a:example:eventservice:*:*:*:*:*:*:*:*",
                }
            ],
        },
        component_name="eventservice",
    )
    result = _run(filter_advisory(state))
    assert result["advisory_relevant"] is True


def test_mixed_osv_and_nvd_uses_osv_ecosystem(tmp_path):
    """When both OSV and NVD packages are present, OSV ecosystem rules apply."""
    (tmp_path / "pyproject.toml").touch()
    state = _make_state(
        advisories={
            "affected_packages": ["PyPI:werkzeug", "NVD:werkzeug"],
            "cpe_entries": [
                {
                    "part": "a",
                    "vendor": "palletsprojects",
                    "product": "werkzeug",
                    "cpe": "cpe:2.3:a:palletsprojects:werkzeug:*:*:*:*:*:*:*:*",
                }
            ],
        },
        repo_path=str(tmp_path),
    )
    result = _run(filter_advisory(state))
    assert result["advisory_relevant"] is True


def test_unknown_project_ecosystem_assumes_relevant():
    """When we can't determine the project ecosystem, assume relevant."""
    state = _make_state(
        advisories={"affected_packages": ["npm:lodash"]},
        # No repo_path, no ecosystem in component_cfg
    )
    result = _run(filter_advisory(state))
    assert result["advisory_relevant"] is True


def test_unknown_project_ecosystem_can_use_llm_to_filter():
    state = _make_state(
        advisories={
            "affected_packages": ["npm:lodash"],
            "cpe_entries": [],
        },
        summary="Lodash prototype pollution in Node.js applications",
        ollama=_FakeLLM(
            '{"relevant": false, "confidence": "high", '
            '"reasons": ["Advisory targets npm/Node.js while project ecosystem is unknown but component naming suggests non-JS service"]}'
        ),
    )
    result = _run(filter_advisory(state))
    assert result["advisory_relevant"] is False
    assert result["result"]["verdict"] == "Not Affected"
    assert state["ollama"].prompts


def test_nvd_only_advisory_uses_llm_before_filtering():
    state = _make_state(
        advisories={
            "affected_packages": ["NVD:priority"],
            "cpe_entries": [
                {
                    "part": "a",
                    "vendor": "priority-software",
                    "product": "priority",
                    "cpe": "cpe:2.3:a:priority-software:priority:*:*:*:*:*:*:*:*",
                }
            ],
        },
        summary="Priority ERP before 22.1 has an authentication bypass.",
        vuln_id="CVE-2023-23459",
        ollama=_FakeLLM(
            '{"relevant": false, "confidence": "high", '
            '"reasons": ["The advisory concerns Priority ERP, a standalone ERP application, not a Python package dependency"]}'
        ),
    )
    result = _run(filter_advisory(state))
    assert result["advisory_relevant"] is False
    assert (
        "LLM relevance decision"
        in result["step_reports"]["filter_advisory"]["findings"]["reasons"][0]
    )


def test_llm_parse_failure_falls_back_to_existing_default():
    state = _make_state(
        advisories={"affected_packages": ["npm:lodash"]},
        ollama=_FakeLLM("not json"),
    )
    result = _run(filter_advisory(state))
    assert result["advisory_relevant"] is True


def test_llm_failure_is_recorded_in_filter_reasons():
    state = _make_state(
        advisories={
            "affected_packages": ["NVD:priority"],
            "cpe_entries": [
                {
                    "part": "a",
                    "vendor": "priority-software",
                    "product": "priority",
                    "cpe": "cpe:2.3:a:priority-software:priority:*:*:*:*:*:*:*:*",
                }
            ],
        },
        vuln_id="CVE-2023-23459",
        summary="Priority ERP before 22.1 has an authentication bypass.",
        ollama=_FakeLLM("", fail=True),
    )

    result = _run(filter_advisory(state))

    assert result["advisory_relevant"] is False
    reasons = result["step_reports"]["filter_advisory"]["findings"]["reasons"]
    assert any("LLM relevance check failed: boom" in reason for reason in reasons)


def test_explicit_ecosystem_in_component_cfg(tmp_path):
    """Ecosystem set in component_cfg is used for matching."""
    state = _make_state(
        advisories={"affected_packages": ["Maven:commons-io"]},
        component_cfg={"ecosystem": "PyPI"},
    )
    result = _run(filter_advisory(state))
    assert result["advisory_relevant"] is False


def test_irrelevant_result_populates_verdict():
    """When filtered out, the result dict is pre-populated for aggregate_verdict."""
    state = _make_state(
        advisories={
            "affected_packages": ["NVD:priority"],
            "cpe_entries": [
                {
                    "part": "a",
                    "vendor": "priority-software",
                    "product": "priority",
                    "cpe": "...",
                }
            ],
        },
        vuln_id="CVE-2023-23459",
    )
    result = _run(filter_advisory(state))
    assert result["advisory_relevant"] is False
    assert result["result"]["verdict"] == "Not Affected"
    assert result["result"]["affected"] is False
    assert "CVE-2023-23459" in result["result"]["reasoning"]
