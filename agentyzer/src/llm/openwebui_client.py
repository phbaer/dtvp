"""OpenWebUI LLM backend.

OpenWebUI exposes an OpenAI-compatible ``/api/chat/completions`` endpoint.
This client streams the response using SSE (Server-Sent Events) and
concatenates the delta tokens, matching the ``LLMClient`` interface used
by the rest of the pipeline.

Required environment variables (see ``main.py``):
    OPENWEBUI_HOST   — base URL, e.g. ``http://localhost:3000``
    OPENWEBUI_MODEL  — model identifier served by OpenWebUI
    OPENWEBUI_API_KEY — Bearer token for authentication
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import UTC, datetime
from typing import Any

import httpx

from src.http import async_client
from src.llm.base import LLMClient

logger = logging.getLogger(__name__)

_MAX_LOG_CHARS = 800
_USAGE_FIELDS = ("prompt_tokens", "completion_tokens", "total_tokens")
_TOOL_CALL_MODES = {"auto", "off"}
_TOKEN_ESTIMATE_CHARS = 3
_CONTEXT_SAFETY_MARGIN = 256
_CONTEXT_RETRIES = 2
_MIN_COMPLETION_TOKENS = 256
_TRUNCATION_MARKER = (
    "\n\n...[truncated by Agentyzer to fit OpenWebUI context budget]...\n\n"
)
_CONTEXT_ERROR_RE = re.compile(
    r"maximum context length is\s+(?P<max>\d+)\s+tokens.*?"
    r"requested\s+(?P<requested>\d+)\s+output tokens.*?"
    r"prompt contains at least\s+(?P<input>\d+)\s+input tokens",
    re.IGNORECASE | re.DOTALL,
)


class OpenWebUIContextLengthError(RuntimeError):
    """OpenWebUI rejected a request because prompt + output exceeded context."""

    def __init__(
        self,
        message: str,
        *,
        max_context_tokens: int | None = None,
        requested_output_tokens: int | None = None,
        input_tokens: int | None = None,
    ):
        super().__init__(message)
        self.max_context_tokens = max_context_tokens
        self.requested_output_tokens = requested_output_tokens
        self.input_tokens = input_tokens


def _truncate_for_log(value: str, limit: int = _MAX_LOG_CHARS) -> str:
    text = (value or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 16].rstrip() + " ...[truncated]"


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_tool_call_mode(value: str | None) -> str:
    normalized = (value or "auto").strip().lower()
    if normalized in {"0", "false", "no", "disabled", "none"}:
        return "off"
    if normalized in _TOOL_CALL_MODES:
        return normalized
    logger.warning(
        "Unknown OPENWEBUI_TOOL_CALLS=%r; falling back to auto", value
    )
    return "auto"


def _positive_int(value: Any, *, default: int | None = None) -> int | None:
    if value in (None, ""):
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _nonnegative_int(value: Any, *, default: int | None = None) -> int | None:
    if value in (None, ""):
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed >= 0 else default


def _int_env(name: str, *, default: int | None = None) -> int | None:
    return _positive_int(os.environ.get(name), default=default)


def _nonnegative_int_env(name: str, *, default: int | None = None) -> int | None:
    return _nonnegative_int(os.environ.get(name), default=default)


def _estimate_text_tokens(value: Any) -> int:
    text = "" if value is None else str(value)
    if not text:
        return 0
    return max(1, (len(text) + _TOKEN_ESTIMATE_CHARS - 1) // _TOKEN_ESTIMATE_CHARS)


def _estimate_payload_input_tokens(payload: dict) -> int:
    tokens = 8
    for message in payload.get("messages") or []:
        if not isinstance(message, dict):
            continue
        tokens += 4
        tokens += _estimate_text_tokens(message.get("role", ""))
        tokens += _estimate_text_tokens(message.get("content", ""))
        tool_calls = message.get("tool_calls")
        if tool_calls:
            tokens += _estimate_text_tokens(json.dumps(tool_calls, ensure_ascii=True))
    tools = payload.get("tools")
    if tools:
        tokens += _estimate_text_tokens(json.dumps(tools, ensure_ascii=True))
    return tokens


def _truncate_middle(text: str, target_chars: int) -> str:
    if len(text) <= target_chars:
        return text
    if target_chars <= len(_TRUNCATION_MARKER) + 80:
        return text[: max(0, target_chars - len(_TRUNCATION_MARKER))].rstrip() + _TRUNCATION_MARKER

    available = target_chars - len(_TRUNCATION_MARKER)
    head_chars = max(40, int(available * 0.6))
    tail_chars = max(40, available - head_chars)
    return (
        text[:head_chars].rstrip()
        + _TRUNCATION_MARKER
        + text[-tail_chars:].lstrip()
    )


def _select_truncation_candidate(messages: list[dict[str, Any]]) -> int | None:
    priority = {"user": 0, "tool": 0, "assistant": 1, "system": 2}
    candidates: list[tuple[int, int, int]] = []
    for index, message in enumerate(messages):
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if not isinstance(content, str) or len(content) <= len(_TRUNCATION_MARKER) + 200:
            continue
        role = str(message.get("role") or "")
        candidates.append((priority.get(role, 1), -len(content), index))
    if not candidates:
        return None
    return sorted(candidates)[0][2]


def _fit_payload_messages_to_input_budget(
    payload: dict,
    max_input_tokens: int,
    *,
    exact_input_tokens: int | None = None,
) -> list[str]:
    messages = payload.get("messages")
    if not isinstance(messages, list) or max_input_tokens <= 0:
        return []

    notes: list[str] = []
    current_tokens = exact_input_tokens or _estimate_payload_input_tokens(payload)
    for _ in range(8):
        if current_tokens <= max_input_tokens:
            break

        index = _select_truncation_candidate(messages)
        if index is None:
            notes.append("context budget exceeded but no truncatable message was found")
            break

        message = dict(messages[index])
        content = str(message.get("content") or "")
        overage_tokens = max(1, current_tokens - max_input_tokens)
        remove_chars = max(
            overage_tokens * _TOKEN_ESTIMATE_CHARS + 2048,
            len(content) // 10,
        )
        target_chars = max(400, len(content) - remove_chars)
        truncated = _truncate_middle(content, target_chars)
        if len(truncated) >= len(content):
            notes.append(
                f"context budget exceeded but message {index} could not be shortened"
            )
            break

        message["content"] = truncated
        messages[index] = message
        notes.append(
            "truncated "
            f"{message.get('role', 'message')} message {index} "
            f"from {len(content)} to {len(truncated)} chars"
        )
        current_tokens = _estimate_payload_input_tokens(payload)

    return notes


def _apply_preflight_context_budget(
    payload: dict,
    *,
    context_window_tokens: int | None,
    min_completion_tokens: int,
    safety_margin_tokens: int,
) -> list[str]:
    if not context_window_tokens:
        return []

    notes: list[str] = []
    desired_completion = int(payload.get("max_tokens") or min_completion_tokens)
    target_input_tokens = (
        context_window_tokens
        - max(min_completion_tokens, 1)
        - max(safety_margin_tokens, 0)
    )
    notes.extend(
        _fit_payload_messages_to_input_budget(payload, target_input_tokens)
    )

    estimated_input = _estimate_payload_input_tokens(payload)
    allowed_completion = (
        context_window_tokens
        - estimated_input
        - max(safety_margin_tokens, 0)
    )
    if allowed_completion < desired_completion:
        new_completion = max(1, allowed_completion)
        payload["max_tokens"] = new_completion
        notes.append(
            f"reduced max_tokens from {desired_completion} to {new_completion} "
            "for configured context window"
        )
    return notes


def _parse_context_length_error(reason: str) -> dict[str, int] | None:
    match = _CONTEXT_ERROR_RE.search(reason or "")
    if not match:
        return None
    try:
        return {
            "max_context_tokens": int(match.group("max")),
            "requested_output_tokens": int(match.group("requested")),
            "input_tokens": int(match.group("input")),
        }
    except (TypeError, ValueError):
        return None


def _adapt_payload_after_context_error(
    payload: dict,
    error: OpenWebUIContextLengthError,
    *,
    min_completion_tokens: int,
    safety_margin_tokens: int,
) -> list[str]:
    max_context = error.max_context_tokens
    input_tokens = error.input_tokens
    if not max_context or not input_tokens:
        return []

    current_completion = int(payload.get("max_tokens") or min_completion_tokens)
    safety = max(0, safety_margin_tokens)
    min_completion = max(1, min_completion_tokens)
    allowed_completion = max_context - input_tokens - safety
    if allowed_completion >= min_completion:
        new_completion = min(current_completion, allowed_completion)
        if new_completion < current_completion:
            payload["max_tokens"] = new_completion
            return [
                f"reduced max_tokens from {current_completion} to {new_completion} "
                "after OpenWebUI context-length rejection"
            ]

    target_input_tokens = max_context - min_completion - safety
    notes = _fit_payload_messages_to_input_budget(
        payload,
        target_input_tokens,
        exact_input_tokens=input_tokens,
    )
    if notes:
        new_completion = min(current_completion, min_completion)
        payload["max_tokens"] = new_completion
        notes.append(
            f"reduced max_tokens from {current_completion} to {new_completion} "
            "after truncating prompt context"
        )
    return notes


def _format_http_error(error: httpx.HTTPError) -> str:
    response = getattr(error, "response", None)
    if response is None:
        return str(error)

    detail = ""
    try:
        data = response.json()
    except Exception:
        try:
            detail = response.text.strip()
        except Exception:
            detail = ""
    else:
        if isinstance(data, dict):
            raw_detail = data.get("detail") or data.get("error") or data
        else:
            raw_detail = data
        detail = json.dumps(raw_detail, ensure_ascii=True)

    if detail:
        return f"{error}; response={detail}"
    return str(error)


def _extract_openai_error(error_block: dict) -> str:
    message = error_block.get("message")
    param = error_block.get("param")
    code = error_block.get("code")
    parts = [str(message).strip()] if message else []
    if param:
        parts.append(f"param={param}")
    if code:
        parts.append(f"code={code}")
    return "; ".join(parts)


def _extract_detail(detail: object) -> str:
    if isinstance(detail, (dict, list)):
        return json.dumps(detail, ensure_ascii=True)
    return str(detail).strip()


def _extract_error_reason(payload: object) -> str:
    if isinstance(payload, list):
        return json.dumps(payload, ensure_ascii=True)

    if not isinstance(payload, dict):
        return str(payload).strip()

    error_block = payload.get("error")
    if isinstance(error_block, dict):
        error_reason = _extract_openai_error(error_block)
        if error_reason:
            return error_reason

    detail = payload.get("detail")
    if detail:
        return _extract_detail(detail)

    message = payload.get("message")
    if message:
        return str(message).strip()

    return json.dumps(payload, ensure_ascii=True)


def _decode_error_body(body: bytes) -> str:
    if not body:
        return ""

    text = body.decode("utf-8", errors="replace").strip()
    if not text:
        return ""

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return _truncate_for_log(text)

    return _truncate_for_log(_extract_error_reason(payload))


def _known_error_hint(reason: str, payload: dict) -> str:
    normalized = (reason or "").lower()
    if "max_tokens" in normalized and "max_completion_tokens" in normalized:
        return (
            "Upstream rejected the deprecated max_tokens field; this model expects "
            "max_completion_tokens instead."
        )

    if (
        "nonetype" in normalized
        and "startswith" in normalized
        and "parent_id" not in payload
    ):
        return (
            "OpenWebUI has a known /api/chat/completions bug where external callers "
            "must send parent_id=null for new chats."
        )

    return ""


async def _raise_openwebui_error(
    resp: httpx.Response,
    payload: dict,
    request_debug: dict,
) -> None:
    response_body = b""
    if hasattr(resp, "aread"):
        response_body = await resp.aread()
    elif getattr(resp, "text", ""):
        response_body = resp.text.encode("utf-8")
    else:
        json_data = getattr(resp, "_json_data", None)
        if json_data is not None:
            response_body = json.dumps(json_data).encode("utf-8")

    error_reason = _decode_error_body(response_body)
    hint = _known_error_hint(error_reason, payload)
    logger.warning(
        "OpenWebUI request rejected: status=%s reason=%s%s; context=%s",
        resp.status_code,
        error_reason or "<empty response body>",
        f" hint={hint}" if hint else "",
        json.dumps(request_debug, ensure_ascii=True),
    )
    message = (
        "OpenWebUI request failed: "
        f"HTTP {resp.status_code}; "
        f"reason={error_reason or '<empty response body>'}"
        + (f"; hint={hint}" if hint else "")
    )
    context_error = _parse_context_length_error(error_reason)
    if context_error:
        raise OpenWebUIContextLengthError(message, **context_error)
    raise RuntimeError(message)


def _extract_usage(usage_payload: object) -> dict[str, int] | None:
    if not isinstance(usage_payload, dict):
        return None

    usage: dict[str, int] = {}
    for field in _USAGE_FIELDS:
        value = usage_payload.get(field)
        if isinstance(value, int):
            usage[field] = value

    return usage or None


async def _collect_streamed_chat_response(
    resp: httpx.Response,
) -> tuple[list[str], list[dict[str, Any]], dict[str, int] | None]:
    parts: list[str] = []
    tool_call_parts: dict[int, dict[str, Any]] = {}
    usage: dict[str, int] | None = None
    async for line in resp.aiter_lines():
        data = _extract_sse_data(line)
        if not data:
            continue

        if data.strip() == "[DONE]":
            break

        try:
            chunk = json.loads(data)
        except json.JSONDecodeError:
            continue

        chunk_usage = _extract_usage(chunk.get("usage"))
        if chunk_usage:
            usage = chunk_usage

        delta = _extract_delta_content(chunk)
        if delta:
            parts.append(delta)
        _accumulate_delta_tool_calls(chunk, tool_call_parts)
    tool_calls = [
        call for _, call in sorted(tool_call_parts.items(), key=lambda item: item[0])
    ]
    return parts, tool_calls, usage


def _extract_sse_data(line: str) -> str:
    if not line:
        return ""
    if line.startswith("data: "):
        return line[len("data: ") :]
    return line


def _extract_delta_content(chunk: dict) -> str:
    choices = chunk.get("choices") or []
    if not choices:
        return ""
    return choices[0].get("delta", {}).get("content", "")


def _accumulate_delta_tool_calls(
    chunk: dict,
    tool_call_parts: dict[int, dict[str, Any]],
) -> None:
    choices = chunk.get("choices") or []
    if not choices:
        return
    delta_tool_calls = choices[0].get("delta", {}).get("tool_calls") or []
    if not isinstance(delta_tool_calls, list):
        return

    for item in delta_tool_calls:
        if not isinstance(item, dict):
            continue
        index = item.get("index")
        if not isinstance(index, int):
            index = len(tool_call_parts)
        entry = tool_call_parts.setdefault(
            index,
            {
                "id": "",
                "type": "function",
                "function": {"name": "", "arguments": ""},
            },
        )
        if item.get("id"):
            entry["id"] = item["id"]
        if item.get("type"):
            entry["type"] = item["type"]
        function = item.get("function") or {}
        if not isinstance(function, dict):
            continue
        entry_function = entry.setdefault(
            "function", {"name": "", "arguments": ""}
        )
        if function.get("name"):
            entry_function["name"] += function["name"]
        if function.get("arguments"):
            entry_function["arguments"] += function["arguments"]


def _build_request_debug_context(
    url: str,
    payload: dict,
    *,
    has_api_key: bool,
) -> dict:
    messages = payload.get("messages") or []
    return {
        "url": url,
        "model": payload.get("model"),
        "stream": payload.get("stream"),
        "temperature": payload.get("temperature"),
        "max_tokens": payload.get("max_tokens"),
        "tool_choice": payload.get("tool_choice"),
        "tool_names": [
            tool.get("function", {}).get("name")
            for tool in payload.get("tools") or []
            if isinstance(tool, dict)
        ],
        "message_count": len(messages),
        "message_roles": [msg.get("role") for msg in messages],
        "message_lengths": [len(msg.get("content") or "") for msg in messages],
        "system_preview": _truncate_for_log(messages[0].get("content", ""))
        if messages and messages[0].get("role") == "system"
        else "",
        "user_preview": _truncate_for_log(messages[-1].get("content", ""))
        if messages
        else "",
        "has_api_key": has_api_key,
    }


class OpenWebUIClient(LLMClient):
    def __init__(
        self,
        host: str = "http://localhost:3000",
        model: str = "mistral",
        api_key: str = "",
        tool_call_mode: str = "auto",
        context_window_tokens: int | None = None,
        context_safety_margin: int | None = None,
        context_retries: int | None = None,
        min_completion_tokens: int | None = None,
    ):
        self.host = host.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.tool_call_mode = _normalize_tool_call_mode(tool_call_mode)
        self.context_window_tokens = (
            _positive_int(context_window_tokens)
            or _int_env("OPENWEBUI_CONTEXT_WINDOW")
        )
        parsed_context_safety_margin = (
            _nonnegative_int(context_safety_margin)
            if context_safety_margin is not None
            else _nonnegative_int_env(
                "OPENWEBUI_CONTEXT_SAFETY_MARGIN",
                default=_CONTEXT_SAFETY_MARGIN,
            )
        )
        self.context_safety_margin = (
            parsed_context_safety_margin
            if parsed_context_safety_margin is not None
            else _CONTEXT_SAFETY_MARGIN
        )
        parsed_context_retries = (
            _nonnegative_int(context_retries)
            if context_retries is not None
            else _nonnegative_int_env(
                "OPENWEBUI_CONTEXT_RETRIES", default=_CONTEXT_RETRIES
            )
        )
        self.context_retries = (
            parsed_context_retries
            if parsed_context_retries is not None
            else _CONTEXT_RETRIES
        )
        self.min_completion_tokens = (
            _positive_int(min_completion_tokens)
            or _int_env(
                "OPENWEBUI_MIN_COMPLETION_TOKENS",
                default=_MIN_COMPLETION_TOKENS,
            )
            or _MIN_COMPLETION_TOKENS
        )
        self.last_error = ""
        self.last_usage: dict[str, int] | None = None
        self.conversation_trace: list[dict] = []

    @property
    def supports_tool_calls(self) -> bool:
        return self.tool_call_mode != "off"

    async def generate(
        self,
        prompt: str,
        *,
        system: str | None = None,
        temperature: float = 0.0,
        timeout: int = 300,
        num_predict: int = 4096,
    ) -> str:
        messages: list[dict[str, Any]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        response = await self.chat_completion(
            messages,
            temperature=temperature,
            timeout=timeout,
            num_predict=num_predict,
        )
        return str(response.get("content") or "")

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
        if tools and not self.supports_tool_calls:
            raise NotImplementedError("OpenWebUI native tool calls are disabled")

        url = f"{self.host}/api/chat/completions"
        request_messages = [dict(message) for message in messages]

        payload: dict = {
            "model": self.model,
            "messages": request_messages,
            "parent_id": None,
            "stream": True,
            "stream_options": {"include_usage": True},
            "temperature": temperature,
            "max_tokens": num_predict,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice or "auto"
        headers: dict[str, str] = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        context_adaptations = _apply_preflight_context_budget(
            payload,
            context_window_tokens=self.context_window_tokens,
            min_completion_tokens=self.min_completion_tokens,
            safety_margin_tokens=self.context_safety_margin,
        )

        self.last_error = ""
        self.last_usage = None
        trace_entry: dict = {
            "schema_version": "agentyzer.llm-conversation-turn/v1",
            "started_at": _utc_now_iso(),
            "provider": "openwebui",
            "backend": type(self).__name__,
            "host": self.host,
            "model": self.model,
            "request": {
                "url": url,
                "temperature": temperature,
                "max_tokens": payload["max_tokens"],
                "stream": True,
                "context_window_tokens": self.context_window_tokens,
                "estimated_input_tokens": _estimate_payload_input_tokens(payload),
            },
            "messages": payload["messages"],
            "response": None,
            "usage": None,
            "status": "running",
        }
        if context_adaptations:
            trace_entry["request"]["context_adaptations"] = context_adaptations
        if tools:
            trace_entry["request"]["tool_choice"] = payload["tool_choice"]
            trace_entry["request"]["tools"] = [
                tool.get("function", {}).get("name")
                for tool in tools
                if isinstance(tool, dict)
            ]

        request_debug = _build_request_debug_context(
            url,
            payload,
            has_api_key=bool(self.api_key),
        )

        logger.debug(
            "OpenWebUI request context: %s",
            json.dumps(request_debug, ensure_ascii=True),
        )

        http_timeout = httpx.Timeout(
            connect=10.0,
            read=float(timeout),
            write=30.0,
            pool=10.0,
        )
        max_attempts = 2
        max_context_retries = max(0, self.context_retries)
        attempts = 0
        context_retry_count = 0
        try:
            for attempt in range(1, max_attempts + max_context_retries + 1):
                attempts = attempt
                parts: list[str] = []
                tool_calls: list[dict[str, Any]] = []
                async with async_client(timeout=http_timeout) as client:
                    try:
                        async with client.stream(
                            "POST",
                            url,
                            json=payload,
                            headers=headers,
                        ) as resp:
                            if resp.status_code >= 400:
                                await _raise_openwebui_error(
                                    resp, payload, request_debug
                                )

                            parts, tool_calls, usage = (
                                await _collect_streamed_chat_response(resp)
                            )
                            self.last_usage = usage
                            self.last_error = ""
                            break
                    except OpenWebUIContextLengthError as e:
                        self.last_error = str(e)
                        if context_retry_count < max_context_retries:
                            adaptations = _adapt_payload_after_context_error(
                                payload,
                                e,
                                min_completion_tokens=self.min_completion_tokens,
                                safety_margin_tokens=self.context_safety_margin,
                            )
                            if adaptations:
                                context_retry_count += 1
                                context_adaptations.extend(adaptations)
                                trace_entry["messages"] = payload["messages"]
                                trace_entry["request"]["max_tokens"] = payload[
                                    "max_tokens"
                                ]
                                trace_entry["request"][
                                    "estimated_input_tokens"
                                ] = _estimate_payload_input_tokens(payload)
                                trace_entry["request"][
                                    "context_adaptations"
                                ] = context_adaptations
                                request_debug = _build_request_debug_context(
                                    url,
                                    payload,
                                    has_api_key=bool(self.api_key),
                                )
                                logger.warning(
                                    "OpenWebUI context limit reached; retrying "
                                    "with compacted request: %s",
                                    json.dumps(request_debug, ensure_ascii=True),
                                )
                                continue
                        raise
                    except httpx.RemoteProtocolError as e:
                        self.last_error = _format_http_error(e)
                        if attempt < max_attempts:
                            logger.warning(
                                "OpenWebUI stream disconnected before response; "
                                "retrying once; context=%s",
                                json.dumps(request_debug, ensure_ascii=True),
                            )
                            continue
                        logger.warning(
                            "OpenWebUI stream disconnected after retry; context=%s",
                            json.dumps(request_debug, ensure_ascii=True),
                        )
                        raise RuntimeError(
                            f"OpenWebUI request failed: {self.last_error}"
                        ) from e
                    except httpx.HTTPError as e:
                        self.last_error = _format_http_error(e)
                        logger.warning(
                            "OpenWebUI request failed; context=%s",
                            json.dumps(request_debug, ensure_ascii=True),
                        )
                        raise RuntimeError(
                            f"OpenWebUI request failed: {self.last_error}"
                        ) from e

            result = "".join(parts)
        except Exception as exc:
            trace_entry["finished_at"] = _utc_now_iso()
            trace_entry["status"] = "failed"
            trace_entry["error"] = str(exc)
            trace_entry["request"]["attempts"] = attempts
            self.conversation_trace.append(trace_entry)
            raise

        trace_entry["finished_at"] = _utc_now_iso()
        trace_entry["status"] = "completed"
        response_message: dict[str, Any] = {"role": "assistant", "content": result}
        if tool_calls:
            response_message["tool_calls"] = tool_calls
        trace_entry["response"] = response_message
        trace_entry["usage"] = self.last_usage
        trace_entry["request"]["attempts"] = attempts
        self.conversation_trace.append(trace_entry)
        if self.last_usage:
            logger.debug(
                "OpenWebUI usage: %s", json.dumps(self.last_usage, ensure_ascii=True)
            )
        logger.debug("OpenWebUI response length: %d chars", len(result))
        return response_message

    async def health_check(self, timeout: int = 5) -> bool:
        try:
            headers: dict[str, str] = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            async with async_client(timeout=timeout) as client:
                r = await client.get(
                    f"{self.host}/api/models",
                    headers=headers,
                )
                if r.status_code == 200:
                    self.last_error = ""
                    return True
                response_text = _truncate_for_log(r.text)
                self.last_error = f"GET {self.host}/api/models returned {r.status_code}: {response_text}"
                logger.warning(
                    "OpenWebUI health check failed for host=%s model=%s has_api_key=%s: %s",
                    self.host,
                    self.model,
                    bool(self.api_key),
                    self.last_error,
                )
                return False
        except Exception as exc:
            self.last_error = str(exc)
            logger.warning(
                "OpenWebUI health check raised for host=%s model=%s has_api_key=%s: %s",
                self.host,
                self.model,
                bool(self.api_key),
                exc,
            )
            return False
