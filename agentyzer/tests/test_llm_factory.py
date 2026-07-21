from src import llm


def test_openwebui_api_key_can_be_loaded_from_secret_file(tmp_path, monkeypatch):
    secret_path = tmp_path / "openwebui-api-key"
    secret_path.write_text("secret-from-file\n", encoding="utf-8")
    captured = {}

    class FakeOpenWebUIClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(llm, "OpenWebUIClient", FakeOpenWebUIClient)
    monkeypatch.setenv("LLM_BACKEND", "openwebui")
    monkeypatch.delenv("OPENWEBUI_API_KEY", raising=False)
    monkeypatch.setenv("OPENWEBUI_API_KEY_FILE", str(secret_path))

    client = llm.create_llm_client()

    assert isinstance(client, FakeOpenWebUIClient)
    assert captured["api_key"] == "secret-from-file"
