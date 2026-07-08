import pytest

from src.agents import code_scanner, verdict
from src.llm import prompt_registry
from src.llm.prompt_registry import (
    get_prompt_value,
    load_prompt_bundle,
    validate_all_prompt_bundles,
)
from src.pipeline import nodes


def test_prompt_registry_loads_named_bundles():
    common_bundle = load_prompt_bundle("common")
    verdict_bundle = load_prompt_bundle("verdict")
    advisory_bundle = load_prompt_bundle("advisory_relevance")

    assert set(common_bundle) >= {
        "web_research_addendum",
        "research_continuation_instruction",
    }
    assert set(verdict_bundle) >= {
        "system",
        "analysis_protocol",
        "response_contract",
        "reasoning_contract",
    }
    assert set(advisory_bundle) >= {"system", "instructions", "input_preamble"}


def test_runtime_prompt_constants_match_registry_values():
    assert verdict._VERDICT_SYSTEM_PROMPT == get_prompt_value("verdict", "system")
    assert verdict._VERDICT_RESEARCH_ADDENDUM == get_prompt_value(
        "common", "web_research_addendum"
    )
    assert verdict._VERDICT_SYSTEM_WITH_RESEARCH == (
        f"{get_prompt_value('verdict', 'system')}\n\n"
        f"{get_prompt_value('common', 'web_research_addendum')}"
    )
    assert verdict._VERDICT_ANALYSIS_PROTOCOL == get_prompt_value(
        "verdict", "analysis_protocol"
    )
    assert verdict._VERDICT_RESPONSE_CONTRACT == get_prompt_value(
        "verdict", "response_contract"
    )
    assert verdict._VERDICT_REASONING_CONTRACT == get_prompt_value(
        "verdict", "reasoning_contract"
    )
    assert code_scanner._SYSTEM_PROMPT == get_prompt_value(
        "code_reachability", "system"
    )
    assert code_scanner._ANALYSIS_PROTOCOL == get_prompt_value(
        "code_reachability", "analysis_protocol"
    )
    assert code_scanner._REACHABILITY_RESPONSE_CONTRACT == get_prompt_value(
        "code_reachability", "response_contract"
    )
    assert code_scanner._DEEP_SYSTEM_PROMPT == get_prompt_value(
        "deep_analysis", "system"
    )
    assert code_scanner._DEEP_ANALYSIS_PROTOCOL == get_prompt_value(
        "deep_analysis", "analysis_protocol"
    )
    assert code_scanner._DEEP_RESPONSE_CONTRACT == get_prompt_value(
        "deep_analysis", "response_contract"
    )
    assert code_scanner._TRANSITIVE_SYSTEM_PROMPT == get_prompt_value(
        "transitive_analysis", "system"
    )
    assert code_scanner._TRANSITIVE_ANALYSIS_PROTOCOL == get_prompt_value(
        "transitive_analysis", "analysis_protocol"
    )
    assert code_scanner._TRANSITIVE_RESPONSE_CONTRACT == get_prompt_value(
        "transitive_analysis", "response_contract"
    )
    assert get_prompt_value("common", "research_continuation_instruction")
    assert nodes._ADVISORY_RELEVANCE_SYSTEM == get_prompt_value(
        "advisory_relevance", "system"
    )
    assert nodes._ADVISORY_RELEVANCE_INPUT_PREAMBLE == get_prompt_value(
        "advisory_relevance", "input_preamble"
    )


def test_validate_all_prompt_bundles_loads_known_configs():
    validate_all_prompt_bundles()


def test_prompts_require_reproducible_attack_paths_and_ticket_summary():
    reachability = get_prompt_value("code_reachability", "system")
    deep = get_prompt_value("deep_analysis", "system")
    transitive = get_prompt_value("transitive_analysis", "system")
    verdict_prompt = get_prompt_value("verdict", "system")
    reachability_protocol = get_prompt_value(
        "code_reachability", "analysis_protocol"
    )
    reachability_contract = get_prompt_value(
        "code_reachability", "response_contract"
    )
    deep_protocol = get_prompt_value("deep_analysis", "analysis_protocol")
    deep_contract = get_prompt_value("deep_analysis", "response_contract")
    transitive_protocol = get_prompt_value(
        "transitive_analysis", "analysis_protocol"
    )
    transitive_contract = get_prompt_value(
        "transitive_analysis", "response_contract"
    )
    verdict_protocol = get_prompt_value("verdict", "analysis_protocol")
    verdict_contract = get_prompt_value("verdict", "response_contract")
    verdict_reasoning = get_prompt_value("verdict", "reasoning_contract")
    advisory = get_prompt_value("advisory_relevance", "instructions")
    common = get_prompt_value("common", "web_research_addendum")
    continuation = get_prompt_value("common", "research_continuation_instruction")

    assert "Keep analysis private" in reachability
    assert "vulnerable dependency/API" in reachability_protocol
    assert "do not reveal the private ledger" in reachability_protocol
    assert "REACHABLE: YES|NO" in reachability_contract
    assert "Do not add markdown, JSON, preamble" in reachability_contract
    assert "source-to-sink path" in deep
    assert "do not reveal the private ledger" in deep_protocol
    assert "EXPLOITABLE: YES|NO|UNCERTAIN" in deep_contract
    assert "dependency chain carries the vulnerable component" in transitive
    assert "Component API, Chain, Surface, Evidence" in transitive
    assert "Use tools before final fields" in transitive_protocol
    assert "CONFIDENCE: High|Medium|Low" in transitive_contract
    assert "first emit only FETCH_SOURCE" in transitive
    assert "Use four compact lenses before answering" in verdict_prompt
    assert "Desc, Surface, Evidence, Fix, Validate" in verdict_prompt
    assert "Analyst guidance is a hypothesis or investigation hint, not evidence" in verdict_prompt
    assert "request source/search if not already fetched" in verdict_prompt
    assert "dependency evidence is only SBOM/input attribution" in verdict_prompt
    assert "guidance names an upstream platform/framework/runtime" in verdict_prompt
    assert "private evidence table" in verdict_protocol
    assert "do not reveal the private evidence table" in verdict_protocol
    assert (
        "VERDICT: Affected|Probably Affected|Inconclusive|Not Affected"
        in verdict_contract
    )
    assert "EXPOSURE: direct|transitive|none" in verdict_contract
    assert "Example input" not in reachability_protocol
    assert "Example output" not in verdict_protocol
    assert "Keep REASONING single-line and <=140 words" in verdict_reasoning
    assert "Keep relevant=true unless the mismatch is clear and evidence-backed" in advisory
    assert "FETCH_SEARCH" in common
    assert "fetch before answering UNCERTAIN" in common
    assert "Do not finish by saying to fetch/check/validate later" in common
    assert "at most one FETCH_URL" in continuation


def test_load_prompt_bundle_rejects_missing_required_keys(monkeypatch, tmp_path):
    prompts_dir = tmp_path / "prompts"
    prompts_dir.mkdir()
    (prompts_dir / "verdict.yaml").write_text(
        "system: ok\nanalysis_protocol: ok\n"
    )

    monkeypatch.setattr(prompt_registry, "_PROMPTS_DIR", prompts_dir)
    prompt_registry.clear_prompt_cache()

    with pytest.raises(ValueError, match="missing required non-empty string keys"):
        load_prompt_bundle("verdict")

    prompt_registry.clear_prompt_cache()


def test_load_prompt_bundle_maps_legacy_few_shot_to_analysis_protocol(
    monkeypatch, tmp_path
):
    prompts_dir = tmp_path / "prompts"
    prompts_dir.mkdir()
    (prompts_dir / "code_reachability.yaml").write_text(
        "system: ok\nfew_shot: legacy protocol\nresponse_contract: ok\n"
    )

    monkeypatch.setattr(prompt_registry, "_PROMPTS_DIR", prompts_dir)
    prompt_registry.clear_prompt_cache()

    bundle = load_prompt_bundle("code_reachability")

    assert bundle["analysis_protocol"] == "legacy protocol"
    assert get_prompt_value("code_reachability", "analysis_protocol") == (
        "legacy protocol"
    )

    prompt_registry.clear_prompt_cache()


def test_load_prompt_bundle_falls_back_to_bundled_defaults(monkeypatch, tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()

    monkeypatch.setattr(prompt_registry, "_CONFIG_DIR", config_dir)
    monkeypatch.setattr(prompt_registry, "_PROMPTS_DIR", None)
    prompt_registry.clear_prompt_cache()

    bundle = load_prompt_bundle("common")

    assert bundle["web_research_addendum"]
    assert bundle["research_continuation_instruction"]

    prompt_registry.clear_prompt_cache()


def test_load_prompt_bundle_uses_override_when_bundle_exists(monkeypatch, tmp_path):
    prompts_dir = tmp_path / "prompts"
    prompts_dir.mkdir()
    (prompts_dir / "common.yaml").write_text(
        "web_research_addendum: override\nresearch_continuation_instruction: continue\n"
    )

    monkeypatch.setattr(prompt_registry, "_PROMPTS_DIR", prompts_dir)
    prompt_registry.clear_prompt_cache()

    bundle = load_prompt_bundle("common")

    assert bundle["web_research_addendum"] == "override"
    assert bundle["research_continuation_instruction"] == "continue"

    prompt_registry.clear_prompt_cache()
