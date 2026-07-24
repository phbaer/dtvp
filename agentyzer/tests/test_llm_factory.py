from src import llm


def test_openwebui_api_key_can_be_loaded_from_secret_file(tmp_path, monkeypatch):
    secret_path = tmp_path / "openwebui-api-key"
    secret_path.write_text("secret-from-file\n", encoding="utf-8")
    captured = {}

    class FakeOpenWebUIClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(llm, "OpenWebUIClient", FakeOpenWebUIClient)
    monkeypatch.setenv("AGENTYZER_LLM_BACKEND", "openwebui")
    monkeypatch.delenv("AGENTYZER_OPENWEBUI_API_KEY", raising=False)
    monkeypatch.setenv("AGENTYZER_OPENWEBUI_API_KEY_FILE", str(secret_path))

    client = llm.create_llm_client()

    assert isinstance(client, FakeOpenWebUIClient)
    assert captured["api_key"] == "secret-from-file"


def test_prefixed_llm_settings_take_precedence_over_legacy_aliases(monkeypatch):
    captured = {}

    class FakeOllamaClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(llm, "OllamaClient", FakeOllamaClient)
    monkeypatch.setenv("AGENTYZER_LLM_BACKEND", "ollama")
    monkeypatch.setenv("LLM_BACKEND", "openwebui")
    monkeypatch.setenv("AGENTYZER_OLLAMA_HOST", "http://prefixed:11434")
    monkeypatch.setenv("OLLAMA_HOST", "http://legacy:11434")
    monkeypatch.setenv("AGENTYZER_OLLAMA_MODEL", "prefixed-model")
    monkeypatch.setenv("OLLAMA_MODEL", "legacy-model")

    client = llm.create_llm_client()

    assert isinstance(client, FakeOllamaClient)
    assert captured == {
        "host": "http://prefixed:11434",
        "model": "prefixed-model",
    }


def test_legacy_llm_settings_remain_supported(monkeypatch):
    captured = {}

    class FakeOllamaClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(llm, "OllamaClient", FakeOllamaClient)
    monkeypatch.delenv("AGENTYZER_LLM_BACKEND", raising=False)
    monkeypatch.delenv("AGENTYZER_OLLAMA_HOST", raising=False)
    monkeypatch.delenv("AGENTYZER_OLLAMA_MODEL", raising=False)
    monkeypatch.setenv("LLM_BACKEND", "ollama")
    monkeypatch.setenv("OLLAMA_HOST", "http://legacy:11434")
    monkeypatch.setenv("OLLAMA_MODEL", "legacy-model")

    client = llm.create_llm_client()

    assert isinstance(client, FakeOllamaClient)
    assert captured == {
        "host": "http://legacy:11434",
        "model": "legacy-model",
    }


def test_prefixed_openwebui_context_settings_take_precedence(monkeypatch):
    monkeypatch.setenv("AGENTYZER_OPENWEBUI_CONTEXT_WINDOW", "8192")
    monkeypatch.setenv("OPENWEBUI_CONTEXT_WINDOW", "4096")
    monkeypatch.setenv("AGENTYZER_OPENWEBUI_CONTEXT_SAFETY_MARGIN", "512")
    monkeypatch.setenv("AGENTYZER_OPENWEBUI_CONTEXT_RETRIES", "4")
    monkeypatch.setenv("AGENTYZER_OPENWEBUI_MIN_COMPLETION_TOKENS", "1024")

    client = llm.OpenWebUIClient()

    assert client.context_window_tokens == 8192
    assert client.context_safety_margin == 512
    assert client.context_retries == 4
    assert client.min_completion_tokens == 1024
