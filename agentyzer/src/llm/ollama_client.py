import json
import logging
from datetime import UTC, datetime

import httpx

from src.http import async_client
from src.llm.base import LLMClient

logger = logging.getLogger(__name__)


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


class OllamaClient(LLMClient):
    def __init__(self, host: str = "http://localhost:11434", model: str = "mistral"):
        self.host = host.rstrip("/")
        self.model = model
        self.last_error = ""
        self.conversation_trace: list[dict] = []

    async def generate(
        self,
        prompt: str,
        *,
        system: str | None = None,
        temperature: float = 0.0,
        timeout: int = 300,
        num_predict: int = 4096,
    ) -> str:
        """Send a generation request to Ollama and return the full text.

        Ollama streams newline-delimited JSON objects.  We concatenate the
        ``response`` field of every chunk until ``done`` is ``true``.

        Args:
            prompt: The user prompt.
            system: Optional system prompt that sets the model's behaviour.
            temperature: Sampling temperature.  0.0 = deterministic.
            timeout: Total HTTP timeout in seconds (connect + full stream).
            num_predict: Maximum number of tokens to generate.  Set high
                enough to avoid truncated responses.
        """
        url = f"{self.host}/api/generate"
        payload: dict = {
            "model": self.model,
            "prompt": prompt,
            "stream": True,
            "options": {
                "temperature": temperature,
                "num_predict": num_predict,
            },
        }
        if system:
            payload["system"] = system
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        trace_entry: dict = {
            "schema_version": "agentyzer.llm-conversation-turn/v1",
            "started_at": _utc_now_iso(),
            "provider": "ollama",
            "backend": type(self).__name__,
            "host": self.host,
            "model": self.model,
            "request": {
                "url": url,
                "temperature": temperature,
                "num_predict": num_predict,
                "stream": True,
            },
            "messages": messages,
            "response": None,
            "usage": None,
            "status": "running",
        }
        logger.debug(
            "Ollama request: model=%s, prompt length=%d, temperature=%.1f",
            self.model,
            len(prompt),
            temperature,
        )

        parts: list[str] = []
        # Use a generous read timeout — the model streams tokens slowly and
        # we must not abort mid-generation.  The *connect* timeout stays
        # short so we fail fast if Ollama is unreachable.
        http_timeout = httpx.Timeout(
            connect=10.0,
            read=float(timeout),
            write=30.0,
            pool=10.0,
        )
        async with async_client(timeout=http_timeout) as client:
            try:
                async with client.stream("POST", url, json=payload) as resp:
                    resp.raise_for_status()
                    async for line in resp.aiter_lines():
                        if not line:
                            continue
                        chunk = json.loads(line)
                        token = chunk.get("response", "")
                        if token:
                            parts.append(token)
                        if chunk.get("done"):
                            break
            except Exception as e:
                self.last_error = str(e)
                trace_entry["finished_at"] = _utc_now_iso()
                trace_entry["status"] = "failed"
                trace_entry["error"] = f"Ollama request failed: {e}"
                self.conversation_trace.append(trace_entry)
                raise RuntimeError(f"Ollama request failed: {e}") from e

        result = "".join(parts)
        self.last_error = ""
        trace_entry["finished_at"] = _utc_now_iso()
        trace_entry["status"] = "completed"
        trace_entry["response"] = {"role": "assistant", "content": result}
        self.conversation_trace.append(trace_entry)
        logger.debug("Ollama response length: %d chars", len(result))
        return result

    async def health_check(self, timeout: int = 5) -> bool:
        """Simple health check — Ollama exposes ``GET /`` returning 200."""
        try:
            async with async_client(timeout=timeout) as client:
                r = await client.get(self.host)
                if r.status_code == 200:
                    self.last_error = ""
                    return True
                self.last_error = (
                    f"GET {self.host} returned {r.status_code}: {r.text.strip()}"
                )
                logger.warning("Ollama health check failed: %s", self.last_error)
                return False
        except Exception as exc:
            self.last_error = str(exc)
            logger.warning(
                "Ollama health check raised for host=%s model=%s: %s",
                self.host,
                self.model,
                exc,
            )
            return False
