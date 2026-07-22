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


def test_scanner_rejects_symlink_escapes_and_oversized_sources(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("host_secret()\n")
    (repo / "leak.py").symlink_to(outside)
    (repo / "large.py").write_text("oversized_secret()\n" * 20)
    (repo / "safe.py").write_text("safe_component()\n")
    monkeypatch.setattr(code_scanner, "_MAX_SOURCE_FILE_BYTES", 100)

    assert code_scanner.search_usage(str(repo), "host_secret", []) == [
        "No direct usage found"
    ]
    assert code_scanner.search_usage(str(repo), "oversized_secret", []) == [
        "No direct usage found"
    ]
    assert any(
        "safe_component" in hit
        for hit in code_scanner.search_usage(str(repo), "safe_component", [])
    )
    assert code_scanner.collect_structure(str(repo), "host_secret", []) == ""
    assert code_scanner.extract_path_context(
        str(repo), [], [], snippet_files=["leak.py", "large.py"]
    ) == []

    file_index = code_scanner._build_file_index(str(repo))
    assert code_scanner._resolve_file("../outside.py", str(repo), file_index) is None


def test_extract_path_context_resolves_and_prioritizes_risk_file(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "pkg").mkdir()
    (repo / "src" / "app.py").write_text("from pkg import client\n\ndef handler():\n    client.parse()\n")
    (repo / "pkg" / "client.py").write_text("def parse():\n    return True\n")

    context = code_scanner.extract_path_context(
        str(repo),
        ["[PRODUCTION] src/app.py::handler → pkg.client::parse"],
        ["pkg/client.py:1"],
    )

    assert [item["file"] for item in context] == ["pkg/client.py", "src/app.py"]
    assert "def parse" in context[0]["content"]


def test_parse_llm_response_handles_multiline_contract():
    parsed = code_scanner._parse_llm_response(
        """REACHABLE: YES
RISK_AREAS: src/app.py:12, src/client.py:4
INVOCATION_PATHS: [PRODUCTION] src/app.py::main -> src/client.py::call
src/worker.py::run → package.parse
REASONING: User input reaches the parser.
The call is not guarded."""
    )

    assert parsed["reachable"] is True
    assert parsed["risk_areas"] == ["src/app.py:12", "src/client.py:4"]
    assert len(parsed["invocation_paths"]) == 2
    assert parsed["reasoning"] == "User input reaches the parser. The call is not guarded."


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
