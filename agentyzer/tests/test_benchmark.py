import asyncio

from src.benchmark import compare_benchmark_with_llm, deterministic_benchmark_fallback


class FakeLLM:
    host = "mock://llm"
    model = "judge"

    def __init__(self, response: str | Exception):
        self.response = response
        self.calls = []

    async def generate(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def test_compare_benchmark_with_llm_merges_probabilistic_judgment():
    benchmark = {
        "schema_version": "dtvp.code-analysis-benchmark/v1",
        "rating": {"score": 3, "max_score": 5, "grade": "C", "label": "Partial match", "tone": "amber"},
        "human": {"state": "NOT_AFFECTED"},
        "automated": {"state": "EXPLOITABLE"},
        "deltas": {"state_match": False},
        "findings": [],
        "recommendation": "Review manually.",
    }
    llm = FakeLLM(
        """
        {
          "rating": {"score": 1, "grade": "F", "label": "Contradiction", "tone": "red", "confidence": 0.9},
          "findings": [{"kind": "state", "severity": "high", "title": "State contradiction", "detail": "Affected versus not affected."}],
          "recommendation": "Escalate for reviewer validation.",
          "reasoning_summary": "The free-text rationale points to incompatible conclusions."
        }
        """
    )

    result = asyncio.run(compare_benchmark_with_llm(benchmark, llm))

    assert result["schema_version"] == "agentyzer.benchmark-comparison/v1"
    assert result["comparison_method"] == "agentyzer_probabilistic"
    assert result["rating"]["score"] == 1
    assert result["rating"]["grade"] == "F"
    assert llm.calls[0][1]["system"].startswith("You compare two vulnerability assessment artifacts.")
    assert llm.calls[0][0][0].startswith("Compare this DTVP benchmark artifact.")
    assert result["evaluator"]["probabilistic"] is True
    assert result["findings"][0]["severity"] == "high"


def test_compare_benchmark_grade_is_derived_from_score():
    benchmark = {
        "rating": {"score": 3, "max_score": 5, "grade": "C"},
        "human": {},
        "automated": {},
        "deltas": {},
    }
    llm = FakeLLM(
        """
        {
          "rating": {"score": 4, "grade": "F", "label": "Good match", "tone": "cyan"},
          "findings": [],
          "recommendation": "Review.",
          "reasoning_summary": "Mostly aligned."
        }
        """
    )

    result = asyncio.run(compare_benchmark_with_llm(benchmark, llm))

    assert result["rating"]["score"] == 4
    assert result["rating"]["grade"] == "B"


def test_compare_benchmark_with_llm_falls_back_on_llm_error():
    benchmark = {
        "rating": {"score": 4, "grade": "B"},
        "human": {},
        "automated": {},
        "deltas": {},
    }

    result = asyncio.run(
        compare_benchmark_with_llm(benchmark, FakeLLM(RuntimeError("offline")))
    )

    assert result["comparison_method"] == "deterministic_fallback"
    assert result["evaluator"]["probabilistic"] is False
    assert "offline" in result["evaluator"]["reason"]


def test_deterministic_benchmark_fallback_marks_unavailable():
    result = deterministic_benchmark_fallback({"rating": {"score": 5}}, reason="not configured")

    assert result["schema_version"] == "agentyzer.benchmark-comparison/v1"
    assert result["comparison_method"] == "deterministic_fallback"
    assert result["evaluator"]["available"] is False
