import asyncio

from src.agents import code_scanner


def test_python_ast_detection(tmp_path):
    d = tmp_path / "repo"
    d.mkdir()
    f = d / "app.py"
    f.write_text("""
from example_lib import do_something

def handler():
    do_something()
""")

    hits = code_scanner.search_usage(str(d), "example_lib", ["do_something"])
    assert any("do_something" in h for h in hits)
    reach = code_scanner.classify_reachability(hits)
    assert reach in ("Reachable", "Potentially Reachable")


def test_prompts_use_staged_analysis_workflow():
    assert "Keep analysis private" in code_scanner._SYSTEM_PROMPT
    assert "Use three compact lenses:" in code_scanner._SYSTEM_PROMPT
    assert "require reproducible evidence for every claimed hop" in code_scanner._SYSTEM_PROMPT
    assert "REACHABLE: YES|NO" in code_scanner._REACHABILITY_RESPONSE_CONTRACT
    assert "Do not add markdown, JSON, preamble" in code_scanner._REACHABILITY_RESPONSE_CONTRACT

    assert "Use three compact lenses:" in code_scanner._DEEP_SYSTEM_PROMPT
    assert "use UNCERTAIN instead of overstating exploitability" in code_scanner._DEEP_SYSTEM_PROMPT
    assert "EXPLOITABLE: YES|NO|UNCERTAIN" in code_scanner._DEEP_RESPONSE_CONTRACT

    assert "Use three compact lenses:" in code_scanner._TRANSITIVE_SYSTEM_PROMPT
    assert (
        "return NO only with affirmative exclusion"
        in code_scanner._TRANSITIVE_SYSTEM_PROMPT
    )
    assert "first emit only FETCH_SOURCE" in code_scanner._TRANSITIVE_SYSTEM_PROMPT
    assert "REACHABLE: YES|NO|UNCERTAIN" in code_scanner._TRANSITIVE_RESPONSE_CONTRACT


def test_analyze_with_llm_preserves_backend_error(monkeypatch):
    async def fake_generate_with_research(*args, **kwargs):
        raise RuntimeError("OpenWebUI request failed: Model not found")

    monkeypatch.setattr(code_scanner, "generate_with_research", fake_generate_with_research)

    result = asyncio.run(
        code_scanner.analyze_with_llm(
            ollama=object(),
            vuln_id="GHSA-test",
            advisory_summary="summary",
            snippets=[{"file": "app.py", "line": 1, "snippet": "x()"}],
        )
    )

    assert result["error"] == "OpenWebUI request failed: Model not found"
    assert "Model not found" in result["reasoning"]


def test_deep_analyze_with_llm_preserves_backend_error(monkeypatch):
    async def fake_generate_with_research(*args, **kwargs):
        raise RuntimeError("OpenWebUI request failed: Model not found")

    monkeypatch.setattr(code_scanner, "generate_with_research", fake_generate_with_research)

    result = asyncio.run(
        code_scanner.deep_analyze_with_llm(
            ollama=object(),
            vuln_id="GHSA-test",
            advisory_summary="summary",
            first_pass={"reachable": True},
            path_context=[{"file": "app.py", "content": "print('x')"}],
        )
    )

    assert result["error"] == "OpenWebUI request failed: Model not found"
    assert "Model not found" in result["reasoning"]
