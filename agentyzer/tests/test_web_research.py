import asyncio

from src.agents import web_research


class FakeSearchResponse:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code


class FakeSearchClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.urls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return None

    async def get(self, url, **kwargs):
        self.urls.append(url)
        return self.responses.pop(0)


def fake_async_client_with(responses):
    client = FakeSearchClient(responses)

    def factory(**kwargs):
        return client

    return factory, client


def test_parse_fetch_directives_supports_search():
    directives = web_research.parse_fetch_directives(
        """
FETCH_SEARCH: CVE-2026-1234 vulnerable-package advisory
FETCH_SOURCE: intermediary-lib
FETCH_URL: https://example.com/advisory
"""
    )

    assert directives == [
        {
            "type": "url",
            "target": "https://example.com/advisory",
        },
        {
            "type": "search",
            "target": "CVE-2026-1234 vulnerable-package advisory",
        },
        {
            "type": "source",
            "target": "intermediary-lib",
        },
    ]


def test_search_web_extracts_duckduckgo_lite_results(monkeypatch):
    html = """
<html><body>
<a rel="nofollow" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fgithub.com%2Fkeycloak%2Fkeycloak%2Fissues%2F49094" class="result-link">Keycloak Netty issue</a>
<td class="result-snippet">Keycloak depends on Quarkus, which pulls in Netty.</td>
</body></html>
"""
    factory, client = fake_async_client_with([FakeSearchResponse(html)])
    monkeypatch.setattr(web_research, "async_client", factory)

    result = asyncio.run(web_research.search_web("Keycloak Netty dependency version"))

    assert result["ok"] is True
    assert "Search provider: DuckDuckGo Lite" in result["text"]
    assert "Keycloak Netty issue" in result["text"]
    assert "https://github.com/keycloak/keycloak/issues/49094" in result["text"]
    assert "pulls in Netty" in result["text"]
    assert client.urls[0].startswith("https://lite.duckduckgo.com/lite/?q=")


def test_search_web_falls_back_to_bing_after_search_provider_challenge(monkeypatch):
    challenged = """
<html><body><form action="//duckduckgo.com/anomaly.js">challenge</form></body></html>
"""
    empty = "<html><body>No parseable results here</body></html>"
    bing = """
<html><body>
<li class="b_algo">
  <h2><a href="https://www.keycloak.org/server/containers">Keycloak containers</a></h2>
  <p>Keycloak runtime packaging and dependency information.</p>
</li>
</body></html>
"""
    factory, client = fake_async_client_with(
        [
            FakeSearchResponse(challenged, status_code=202),
            FakeSearchResponse(empty),
            FakeSearchResponse(bing),
        ]
    )
    monkeypatch.setattr(web_research, "async_client", factory)

    result = asyncio.run(web_research.search_web("Keycloak Netty dependency version"))

    assert result["ok"] is True
    assert "Search provider: Bing" in result["text"]
    assert "Keycloak containers" in result["text"]
    assert "https://www.keycloak.org/server/containers" in result["text"]
    assert len(client.urls) == 3


def test_parse_fetch_directives_supports_inline_validation_request():
    directives = web_research.parse_fetch_directives(
        "VERDICT: Inconclusive\n"
        "CONFIDENCE: Low\n"
        "AFFECTED: false\n"
        "EXPOSURE: unknown\n"
        "REASONING: Desc: Netty DNS resolver issue. Validate: FETCH_SEARCH "
        "Keycloak dependency tree Netty CVE-2026-47691"
    )

    assert directives == [
        {
            "type": "search",
            "target": "Keycloak dependency tree Netty CVE-2026-47691",
        }
    ]


def test_fulfill_directives_runs_search(monkeypatch):
    async def fake_search_web(query: str):
        return {
            "query": query,
            "ok": True,
            "text": "1. Vendor advisory\n   URL: https://vendor.example/advisory",
            "error": None,
        }

    monkeypatch.setattr(web_research, "search_web", fake_search_web)

    result = asyncio.run(
        web_research.fulfill_directives(
            [{"type": "search", "target": "CVE-2026-1234 vendor advisory"}]
        )
    )

    assert "Search results for: CVE-2026-1234 vendor advisory" in result
    assert "Vendor advisory" in result


def test_strip_fetch_lines_removes_search_directives():
    stripped = web_research._strip_fetch_lines(
        "FETCH_SEARCH: CVE-2026-1234\nREACHABLE: UNCERTAIN"
    )

    assert "FETCH_SEARCH" not in stripped
    assert stripped == "REACHABLE: UNCERTAIN"


def test_strip_fetch_lines_removes_inline_validation_request():
    stripped = web_research._strip_fetch_lines(
        "REASONING: Desc: uncertain upstream dependency. Validate: "
        "FETCH_SEARCH Keycloak dependency tree Netty CVE-2026-47691"
    )

    assert stripped == "REASONING: Desc: uncertain upstream dependency."


def test_generate_with_research_fulfills_inline_validation_request(monkeypatch):
    class FakeOllama:
        def __init__(self):
            self.prompts = []

        async def generate(self, prompt, **kwargs):
            self.prompts.append(prompt)
            if len(self.prompts) == 1:
                return (
                    "VERDICT: Inconclusive\n"
                    "CONFIDENCE: Low\n"
                    "AFFECTED: false\n"
                    "EXPOSURE: unknown\n"
                    "REASONING: Desc: Netty DNS resolver issue. Validate: "
                    "FETCH_SEARCH Keycloak dependency tree Netty CVE-2026-47691"
                )
            return (
                "VERDICT: Inconclusive\n"
                "CONFIDENCE: Low\n"
                "AFFECTED: false\n"
                "EXPOSURE: unknown\n"
                "REASONING: Desc: Netty DNS resolver issue. Evidence: search "
                "results were checked. Validate: review dependency tree."
            )

    async def fake_fulfill(directives, vulnerable_component=""):
        assert directives == [
            {
                "type": "search",
                "target": "Keycloak dependency tree Netty CVE-2026-47691",
            }
        ]
        return "--- Search results for: Keycloak dependency tree Netty CVE-2026-47691 ---"

    monkeypatch.setattr(web_research, "fulfill_directives", fake_fulfill)

    raw, research_log = asyncio.run(
        web_research.generate_with_research(FakeOllama(), "prompt")
    )

    assert "FETCH_SEARCH" not in raw
    assert research_log[0]["directives"] == [
        {
            "type": "search",
            "target": "Keycloak dependency tree Netty CVE-2026-47691",
        }
    ]


def test_generate_with_research_fulfills_native_tool_calls(monkeypatch):
    class FakeToolLlm:
        supports_tool_calls = True

        def __init__(self):
            self.messages = []
            self.tools = []

        async def chat_completion(self, messages, **kwargs):
            self.messages.append(messages)
            self.tools.append(kwargs.get("tools"))
            if len(self.messages) == 1:
                return {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "search_web",
                                "arguments": (
                                    '{"query":"Keycloak Netty CVE-2026-47691"}'
                                ),
                            },
                        }
                    ],
                }
            assert any(message.get("role") == "tool" for message in messages)
            return {
                "role": "assistant",
                "content": (
                    "VERDICT: Inconclusive\n"
                    "CONFIDENCE: Low\n"
                    "AFFECTED: false\n"
                    "EXPOSURE: unknown\n"
                    "REASONING: Evidence: search result checked."
                ),
            }

        async def generate(self, *args, **kwargs):
            raise AssertionError("native tool path should not call generate")

    async def fake_search_web(query: str):
        return {
            "query": query,
            "ok": True,
            "text": "1. Keycloak issue\n   URL: https://github.com/keycloak/keycloak/issues/49094",
            "error": None,
        }

    monkeypatch.setattr(web_research, "search_web", fake_search_web)

    llm = FakeToolLlm()
    raw, research_log = asyncio.run(
        web_research.generate_with_research(llm, "prompt", system="system")
    )

    assert "Evidence: search result checked" in raw
    assert research_log[0]["tool_protocol"] == "native"
    assert research_log[0]["directives"] == [
        {"type": "search", "target": "Keycloak Netty CVE-2026-47691"}
    ]
    assert research_log[0]["tool_calls"][0]["name"] == "search_web"
    assert llm.tools[0]
    assert llm.messages[1][-1]["role"] == "tool"
    assert "Search results for: Keycloak Netty CVE-2026-47691" in llm.messages[1][
        -1
    ]["content"]
