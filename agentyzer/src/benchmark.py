"""Probabilistic assessment benchmark comparison.

This module compares an existing vulnerability assessment with an Agentyzer
analysis result. The existing assessment may have been created by a person or
by automation. It does not rescan source code; source analysis belongs to the
normal assessment pipeline. The comparison step judges whether the two
assessment artifacts agree on state, evidence, reasoning, and rescoring.
"""

from __future__ import annotations

import json
import re
from copy import deepcopy
from typing import Any

from src.llm.prompt_registry import get_prompt_value

BENCHMARK_SCHEMA_VERSION = "agentyzer.benchmark-comparison/v1"
_SYSTEM_PROMPT = get_prompt_value("benchmark_comparison", "system")
_INPUT_PREAMBLE = get_prompt_value("benchmark_comparison", "input_preamble")


def _compact(value: Any, *, limit: int = 14_000) -> str:
    text = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True)
    if len(text) <= limit:
        return text
    return f"{text[:limit].rstrip()}\n...<truncated>"


def _extract_json_object(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped, flags=re.IGNORECASE)
        stripped = re.sub(r"\s*```$", "", stripped)
    try:
        parsed = json.loads(stripped)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", stripped, flags=re.DOTALL)
    if not match:
        return {}
    try:
        parsed = json.loads(match.group(0))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _coerce_score(value: Any, fallback: int = 3) -> int:
    try:
        return max(1, min(5, int(round(float(value)))))
    except (TypeError, ValueError):
        return fallback


def _grade_for_score(score: int) -> str:
    return {5: "A", 4: "B", 3: "C", 2: "D", 1: "F"}[score]


def _tone_for_score(score: int) -> str:
    return {5: "green", 4: "cyan", 3: "amber", 2: "orange", 1: "red"}[score]


def _label_for_score(score: int) -> str:
    return {
        5: "Strong match",
        4: "Good match",
        3: "Partial match",
        2: "Weak match",
        1: "Contradiction",
    }[score]


def _normalize_rating(value: Any, fallback: dict[str, Any]) -> dict[str, Any]:
    rating = dict(value) if isinstance(value, dict) else {}
    fallback_score = _coerce_score(fallback.get("score"), 3)
    score = _coerce_score(rating.get("score"), fallback_score)
    try:
        confidence = max(0.0, min(1.0, float(rating.get("confidence", 0.7) or 0.0)))
    except (TypeError, ValueError):
        confidence = 0.7
    return {
        "score": score,
        "max_score": 5,
        "grade": _grade_for_score(score),
        "label": str(rating.get("label") or _label_for_score(score)).strip(),
        "tone": str(rating.get("tone") or _tone_for_score(score)).strip(),
        "confidence": confidence,
    }


def _normalize_findings(value: Any, fallback: list[dict[str, Any]]) -> list[dict[str, str]]:
    raw_findings = value if isinstance(value, list) else fallback
    findings: list[dict[str, str]] = []
    for item in raw_findings:
        if not isinstance(item, dict):
            continue
        findings.append(
            {
                "kind": str(item.get("kind") or "reasoning"),
                "severity": str(item.get("severity") or "info"),
                "title": str(item.get("title") or "Benchmark finding"),
                "detail": str(item.get("detail") or ""),
            }
        )
    return findings[:12]


def deterministic_benchmark_fallback(
    benchmark: dict[str, Any],
    *,
    reason: str | None = None,
) -> dict[str, Any]:
    result = deepcopy(benchmark)
    result["schema_version"] = BENCHMARK_SCHEMA_VERSION
    result["comparison_method"] = "deterministic_fallback"
    result.setdefault(
        "rating",
        {
            "score": 3,
            "max_score": 5,
            "grade": "C",
            "label": "Fallback comparison",
            "tone": "amber",
        },
    )
    result.setdefault("human", {})
    result.setdefault("automated", {})
    result.setdefault("deltas", {})
    result["evaluator"] = {
        "provider": "agentyzer",
        "probabilistic": False,
        "available": False,
        "reason": reason or "Probabilistic benchmark comparison was not available.",
    }
    result.setdefault("findings", [])
    result.setdefault("recommendation", "Review deterministic benchmark differences manually.")
    return result


def _merge_llm_judgment(
    benchmark: dict[str, Any],
    parsed: dict[str, Any],
    *,
    llm_metadata: dict[str, Any],
) -> dict[str, Any]:
    result = deepcopy(benchmark)
    fallback_rating = benchmark.get("rating") if isinstance(benchmark.get("rating"), dict) else {}
    fallback_findings = benchmark.get("findings") if isinstance(benchmark.get("findings"), list) else []

    result["schema_version"] = BENCHMARK_SCHEMA_VERSION
    result["comparison_method"] = "agentyzer_probabilistic"
    result["rating"] = _normalize_rating(parsed.get("rating"), fallback_rating)
    result["findings"] = _normalize_findings(parsed.get("findings"), fallback_findings)
    result["recommendation"] = str(
        parsed.get("recommendation")
        or benchmark.get("recommendation")
        or "Review the benchmark result manually."
    )
    result["reasoning_summary"] = str(parsed.get("reasoning_summary") or "").strip()
    result["evaluator"] = {
        "provider": "agentyzer",
        "probabilistic": True,
        "available": True,
        **llm_metadata,
    }
    return result


async def compare_benchmark_with_llm(
    benchmark: dict[str, Any],
    llm_client: Any,
) -> dict[str, Any]:
    prompt = f"{_INPUT_PREAMBLE}\n\n{_compact(benchmark)}"
    try:
        raw_response = await llm_client.generate(
            prompt,
            system=_SYSTEM_PROMPT,
            temperature=0.2,
            timeout=180,
            num_predict=1400,
        )
    except Exception as exc:
        return deterministic_benchmark_fallback(
            benchmark,
            reason=f"LLM benchmark comparison failed: {exc}",
        )

    parsed = _extract_json_object(raw_response)
    if not parsed:
        return deterministic_benchmark_fallback(
            benchmark,
            reason="LLM benchmark comparison did not return valid JSON.",
        )

    return _merge_llm_judgment(
        benchmark,
        parsed,
        llm_metadata={
            "backend": type(llm_client).__name__,
            "host": getattr(llm_client, "host", None),
            "model": getattr(llm_client, "model", None),
        },
    )
