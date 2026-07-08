"""Abstract base for LLM backends.

Every backend must implement ``generate()`` and ``health_check()``.
Pipeline code and agent modules depend only on this protocol so that
swapping backends (Ollama, OpenWebUI, …) requires zero changes outside
``src/llm/``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class LLMClient(ABC):
    """Minimal interface that all LLM backends must satisfy."""

    supports_tool_calls = False

    @abstractmethod
    async def generate(
        self,
        prompt: str,
        *,
        system: str | None = None,
        temperature: float = 0.0,
        timeout: int = 300,
        num_predict: int = 4096,
    ) -> str:
        """Generate a completion and return the full text."""

    @abstractmethod
    async def health_check(self, timeout: int = 5) -> bool:
        """Return ``True`` when the backend is reachable."""

    async def chat_completion(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict[str, Any] | None = None,
        temperature: float = 0.0,
        timeout: int = 300,
        num_predict: int = 4096,
    ) -> dict[str, Any]:
        """Generate a chat response, optionally with native tool calls.

        Backends that do not support OpenAI-style tool calls leave this as the
        default so callers can fall back to plain ``generate()``.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support native chat tool calls"
        )
