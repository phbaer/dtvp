"""LLM backend abstraction.

Public API:
    LLMClient            — abstract base (for type annotations)
    create_llm_client()  — factory that picks the right backend from env vars
"""

from __future__ import annotations

import os
from pathlib import Path

from src.llm.base import LLMClient
from src.llm.ollama_client import OllamaClient
from src.llm.openwebui_client import OpenWebUIClient

__all__ = ["LLMClient", "OllamaClient", "OpenWebUIClient", "create_llm_client"]


def _read_api_key() -> str:
    direct = os.environ.get("OPENWEBUI_API_KEY", "").strip()
    if direct:
        return direct
    secret_path = os.environ.get("OPENWEBUI_API_KEY_FILE", "").strip()
    if not secret_path:
        return ""
    return Path(secret_path).read_text(encoding="utf-8").strip()


def create_llm_client() -> LLMClient:
    """Instantiate the LLM backend selected by ``LLM_BACKEND`` env var.

    Supported values (case-insensitive):
        ``ollama``    — default; uses ``OLLAMA_HOST`` / ``OLLAMA_MODEL``.
        ``openwebui`` — uses ``OPENWEBUI_HOST`` / ``OPENWEBUI_MODEL`` /
                        ``OPENWEBUI_API_KEY`` / ``OPENWEBUI_TOOL_CALLS``.
    """
    backend = os.environ.get("LLM_BACKEND", "ollama").lower()

    if backend == "openwebui":
        return OpenWebUIClient(
            host=os.environ.get("OPENWEBUI_HOST", "http://localhost:3000"),
            model=os.environ.get("OPENWEBUI_MODEL", "mistral"),
            api_key=_read_api_key(),
            tool_call_mode=os.environ.get("OPENWEBUI_TOOL_CALLS", "auto"),
        )

    # Default: Ollama
    return OllamaClient(
        host=os.environ.get("OLLAMA_HOST", "http://localhost:11434"),
        model=os.environ.get("OLLAMA_MODEL", "mistral"),
    )
