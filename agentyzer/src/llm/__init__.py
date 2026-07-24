"""LLM backend abstraction.

Public API:
    LLMClient            — abstract base (for type annotations)
    create_llm_client()  — factory that picks the right backend from env vars
"""

from __future__ import annotations

import os
from pathlib import Path

from src.configuration import environment_text
from src.llm.base import LLMClient
from src.llm.ollama_client import OllamaClient
from src.llm.openwebui_client import OpenWebUIClient

__all__ = ["LLMClient", "OllamaClient", "OpenWebUIClient", "create_llm_client"]


def _setting(name: str, legacy_name: str, default: str = "") -> str:
    return environment_text(
        os.environ,
        name,
        default,
        legacy_name=legacy_name,
    )


def _read_api_key() -> str:
    direct = _setting(
        "AGENTYZER_OPENWEBUI_API_KEY",
        "OPENWEBUI_API_KEY",
    )
    if direct:
        return direct
    secret_path = _setting(
        "AGENTYZER_OPENWEBUI_API_KEY_FILE",
        "OPENWEBUI_API_KEY_FILE",
    )
    if not secret_path:
        return ""
    return Path(secret_path).read_text(encoding="utf-8").strip()


def create_llm_client() -> LLMClient:
    """Instantiate the LLM backend selected by Agentyzer configuration.

    Supported values (case-insensitive):
        ``ollama``    — default; uses ``AGENTYZER_OLLAMA_*`` settings.
        ``openwebui`` — uses ``AGENTYZER_OPENWEBUI_*`` settings.

    The historical unprefixed names remain compatibility aliases.
    """
    backend = _setting(
        "AGENTYZER_LLM_BACKEND",
        "LLM_BACKEND",
        "ollama",
    ).lower()

    if backend == "openwebui":
        return OpenWebUIClient(
            host=_setting(
                "AGENTYZER_OPENWEBUI_HOST",
                "OPENWEBUI_HOST",
                "http://localhost:3000",
            ),
            model=_setting(
                "AGENTYZER_OPENWEBUI_MODEL",
                "OPENWEBUI_MODEL",
                "mistral",
            ),
            api_key=_read_api_key(),
            tool_call_mode=_setting(
                "AGENTYZER_OPENWEBUI_TOOL_CALLS",
                "OPENWEBUI_TOOL_CALLS",
                "auto",
            ),
        )

    # Default: Ollama
    return OllamaClient(
        host=_setting(
            "AGENTYZER_OLLAMA_HOST",
            "OLLAMA_HOST",
            "http://localhost:11434",
        ),
        model=_setting(
            "AGENTYZER_OLLAMA_MODEL",
            "OLLAMA_MODEL",
            "mistral",
        ),
    )
