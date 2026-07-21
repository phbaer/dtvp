"""Web research tool for LLM-driven information retrieval.

When the LLM determines it needs additional context to make a confident
assessment — e.g. what API surface an intermediary library exposes, or
whether a specific function delegates to a vulnerable dependency — it can
emit ``FETCH:`` directives in its response.  This module fulfils those
requests and returns the results for a follow-up prompt.

Supported directives (emitted by the LLM as lines in its response):
    FETCH_URL: <url>          — fetch a web page and extract text content
    FETCH_SEARCH: <query>     — search the public web for authoritative sources
    FETCH_PACKAGE: <name>     — look up a package on npm / PyPI / crates.io
    FETCH_SOURCE: <name>      — fetch source snippets for an intermediary package

Security: URLs are validated to prevent SSRF.  Only HTTPS is allowed, and
private/internal IP ranges are rejected.
"""

from __future__ import annotations

from copy import deepcopy
import ipaddress
import json
import logging
import re
import socket
from html.parser import HTMLParser
from typing import Any, Dict, List
from urllib.parse import parse_qs, quote, quote_plus, urljoin, urlparse

from src.http import async_client
from src.llm.prompt_registry import get_prompt_value

logger = logging.getLogger(__name__)

_RESEARCH_CONTINUATION_INSTRUCTION = get_prompt_value(
    "common", "research_continuation_instruction"
)

# Maximum bytes to read from a fetched page.
_MAX_RESPONSE_BYTES = 64_000
# Maximum chars of extracted text to return per fetch.
_MAX_TEXT_CHARS = 12_000
# Maximum number of fetches per LLM turn.
MAX_FETCHES_PER_TURN = 3
# Maximum total fetch rounds (LLM → fetch → LLM → fetch → …).
MAX_RESEARCH_ROUNDS = 2
_MAX_REDIRECTS = 3

_RESEARCH_TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "search_web",
            "description": "Search the public web for authoritative advisory, dependency, or source evidence.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Focused search query including project/package and vulnerability identifiers.",
                    }
                },
                "required": ["query"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_url",
            "description": "Download and extract text from a specific authoritative HTTPS URL.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "HTTPS URL to fetch. Internal/private hosts are blocked.",
                    }
                },
                "required": ["url"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_package",
            "description": "Look up package registry metadata for npm, PyPI, crates.io, Maven, or similar package names.",
            "parameters": {
                "type": "object",
                "properties": {
                    "package": {
                        "type": "string",
                        "description": "Package identifier, optionally including ecosystem notation.",
                    }
                },
                "required": ["package"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_source",
            "description": "Fetch source/package snippets for an intermediary dependency.",
            "parameters": {
                "type": "object",
                "properties": {
                    "package": {
                        "type": "string",
                        "description": "Package or repository name to inspect for dependency/use evidence.",
                    }
                },
                "required": ["package"],
                "additionalProperties": False,
            },
        },
    },
]

_TOOL_TO_DIRECTIVE_TYPE = {
    "fetch_url": "url",
    "search_web": "search",
    "fetch_package": "package",
    "fetch_source": "source",
}


def research_tool_schemas() -> list[dict[str, Any]]:
    """Return OpenAI-compatible tool schemas for bounded research fetches."""
    return deepcopy(_RESEARCH_TOOL_SCHEMAS)

# ------------------------------------------------------------------ #
# URL safety
# ------------------------------------------------------------------ #
_BLOCKED_HOSTS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "metadata.google.internal",
}


def _is_safe_url(url: str) -> tuple[bool, str]:
    """Validate that *url* is safe to fetch (no SSRF)."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "invalid URL"

    if parsed.scheme != "https":
        return False, f"scheme '{parsed.scheme}' not allowed (use https)"

    if parsed.username is not None or parsed.password is not None:
        return False, "URL credentials are not allowed"

    try:
        if parsed.port not in {None, 443}:
            return False, "only the default HTTPS port is allowed"
    except ValueError:
        return False, "invalid port"

    host = (parsed.hostname or "").casefold().rstrip(".")
    if not host:
        return False, "no hostname"

    if host in _BLOCKED_HOSTS:
        return False, f"blocked host: {host}"

    try:
        literal_ip = ipaddress.ip_address(host)
    except ValueError:
        literal_ip = None
    if literal_ip is not None and not literal_ip.is_global:
        return False, f"non-public IP address: {literal_ip}"

    # Resolve every address family and reject the host if any answer is not
    # globally routable. This also blocks mixed public/private DNS responses.
    try:
        resolved_any = False
        for info in socket.getaddrinfo(
            host, None, socket.AF_UNSPEC, socket.SOCK_STREAM
        ):
            resolved_any = True
            addr = info[4][0]
            ip = ipaddress.ip_address(addr)
            if not ip.is_global:
                return False, f"resolved to non-public IP: {addr}"
        if not resolved_any:
            return False, "hostname did not resolve"
    except (socket.gaierror, OSError, ValueError):
        return False, "hostname did not resolve to a public address"

    return True, "ok"


# ------------------------------------------------------------------ #
# HTML → plain text
# ------------------------------------------------------------------ #
class _TextExtractor(HTMLParser):
    """Minimal HTML-to-text converter."""

    _SKIP_TAGS = {"script", "style", "noscript", "svg", "head"}

    def __init__(self) -> None:
        super().__init__()
        self._parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in self._SKIP_TAGS:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in self._SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip_depth == 0:
            text = data.strip()
            if text:
                self._parts.append(text)

    def get_text(self) -> str:
        return "\n".join(self._parts)


def _html_to_text(html: str) -> str:
    extractor = _TextExtractor()
    try:
        extractor.feed(html)
    except Exception:
        pass
    return extractor.get_text()


# ------------------------------------------------------------------ #
# Fetch operations
# ------------------------------------------------------------------ #
async def fetch_url(url: str) -> Dict[str, Any]:
    """Fetch a URL and return extracted text content.

    Returns ``{"url": str, "ok": bool, "text": str, "error": str | None}``.
    """
    logger.info("[web_research] Fetching %s", url)
    try:
        async with async_client(timeout=15) as client:
            current_url = url
            for redirect_count in range(_MAX_REDIRECTS + 1):
                safe, reason = _is_safe_url(current_url)
                if not safe:
                    logger.warning(
                        "[web_research] Blocked unsafe URL %s: %s",
                        current_url,
                        reason,
                    )
                    return {
                        "url": url,
                        "ok": False,
                        "text": "",
                        "error": f"Blocked: {reason}",
                    }

                async with client.stream(
                    "GET",
                    current_url,
                    follow_redirects=False,
                    headers={
                        "User-Agent": "agentyzer/1.0 (vulnerability-analysis-bot)",
                        "Accept": "text/html, application/json, text/plain",
                    },
                ) as response:
                    if response.is_redirect:
                        location = response.headers.get("location")
                        if not location:
                            return {
                                "url": url,
                                "ok": False,
                                "text": "",
                                "error": "Redirect response omitted Location",
                            }
                        if redirect_count >= _MAX_REDIRECTS:
                            return {
                                "url": url,
                                "ok": False,
                                "text": "",
                                "error": "Too many redirects",
                            }
                        current_url = urljoin(current_url, location)
                        continue

                    if response.status_code >= 400:
                        return {
                            "url": url,
                            "ok": False,
                            "text": "",
                            "error": f"HTTP {response.status_code}",
                        }

                    content_type = response.headers.get("content-type", "").lower()
                    if not any(
                        allowed in content_type
                        for allowed in ("text/", "json", "xml")
                    ):
                        return {
                            "url": url,
                            "ok": False,
                            "text": "",
                            "error": f"Unsupported content type: {content_type or 'unknown'}",
                        }

                    body = bytearray()
                    async for chunk in response.aiter_bytes(chunk_size=8192):
                        remaining = _MAX_RESPONSE_BYTES - len(body)
                        if remaining <= 0:
                            break
                        body.extend(chunk[:remaining])
                    decoded = bytes(body).decode(
                        response.encoding or "utf-8",
                        errors="replace",
                    )

                    if "html" in content_type:
                        text = _html_to_text(decoded)[:_MAX_TEXT_CHARS]
                    else:
                        text = decoded[:_MAX_TEXT_CHARS]

                    logger.info(
                        "[web_research] Fetched %s: %d chars extracted",
                        current_url,
                        len(text),
                    )
                    return {
                        "url": url,
                        "final_url": current_url,
                        "ok": True,
                        "text": text,
                        "error": None,
                    }
    except Exception as e:
        logger.warning("[web_research] Fetch failed for %s: %s", url, e)
        return {"url": url, "ok": False, "text": "", "error": str(e)}


async def fetch_package_info(package_name: str) -> Dict[str, Any]:
    """Look up a package on npm and PyPI (best-effort).

    Returns ``{"package": str, "ok": bool, "text": str, "error": str | None}``.
    """
    package_name = _squash_text(package_name)[:200]
    encoded_package = quote(package_name, safe="@")
    logger.info("[web_research] Looking up package '%s'", package_name)
    registries = [
        (
            "npm",
            f"https://registry.npmjs.org/{encoded_package}",
            _extract_npm_info,
        ),
        (
            "pypi",
            f"https://pypi.org/pypi/{encoded_package}/json",
            _extract_pypi_info,
        ),
    ]

    for registry_name, url, extractor in registries:
        try:
            async with async_client(timeout=10) as client:
                r = await client.get(url, follow_redirects=False)
                if r.status_code == 200:
                    data = r.json()
                    text = extractor(data, package_name)
                    if text:
                        logger.info(
                            "[web_research] Found '%s' on %s: %d chars",
                            package_name,
                            registry_name,
                            len(text),
                        )
                        return {
                            "package": package_name,
                            "ok": True,
                            "text": text,
                            "error": None,
                        }
        except Exception:
            continue

    return {
        "package": package_name,
        "ok": False,
        "text": "",
        "error": "Package not found on npm or PyPI",
    }


def _extract_npm_info(data: dict, name: str) -> str:
    """Extract useful info from an npm registry response."""
    parts = [f"Package: {name} (npm)"]
    desc = data.get("description", "")
    if desc:
        parts.append(f"Description: {desc}")

    latest = data.get("dist-tags", {}).get("latest", "")
    if latest:
        parts.append(f"Latest version: {latest}")

    # Get the latest version's metadata
    versions = data.get("versions", {})
    if latest and latest in versions:
        ver_data = versions[latest]
        deps = ver_data.get("dependencies", {})
        if deps:
            parts.append(f"Dependencies: {', '.join(sorted(deps.keys()))}")

        readme = data.get("readme", "")
        if readme:
            # Truncate README to useful portion
            parts.append(f"\nREADME (excerpt):\n{readme[: _MAX_TEXT_CHARS // 2]}")

    return "\n".join(parts)


def _extract_pypi_info(data: dict, name: str) -> str:
    """Extract useful info from a PyPI JSON response."""
    info = data.get("info", {})
    parts = [f"Package: {name} (PyPI)"]
    desc = info.get("summary", "")
    if desc:
        parts.append(f"Description: {desc}")
    ver = info.get("version", "")
    if ver:
        parts.append(f"Latest version: {ver}")
    requires = info.get("requires_dist") or []
    if requires:
        parts.append(f"Dependencies: {', '.join(requires[:30])}")
    long_desc = info.get("description", "")
    if long_desc:
        parts.append(f"\nDescription (excerpt):\n{long_desc[: _MAX_TEXT_CHARS // 2]}")
    return "\n".join(parts)


class _DuckDuckGoSearchResultExtractor(HTMLParser):
    """Extract DuckDuckGo Lite/HTML search results without a parser dependency."""

    def __init__(self) -> None:
        super().__init__()
        self.results: list[dict[str, str]] = []
        self._capture_title = False
        self._capture_snippet = False
        self._pending_result: dict[str, str] | None = None
        self._text_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {key: value or "" for key, value in attrs}
        class_name = attrs_dict.get("class", "")

        if tag.lower() == "a" and (
            "result__a" in class_name or "result-link" in class_name
        ):
            url = _normalize_search_href(attrs_dict.get("href", ""))
            if url:
                self._pending_result = {"title": "", "url": url, "snippet": ""}
                self._text_parts = []
                self._capture_title = True
            return

        if self.results and (
            "result__snippet" in class_name or "result-snippet" in class_name
        ):
            self._text_parts = []
            self._capture_snippet = True

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.lower()
        if self._capture_title and lowered == "a" and self._pending_result:
            self._pending_result["title"] = _squash_text(" ".join(self._text_parts))
            if self._pending_result["title"]:
                self.results.append(self._pending_result)
            self._pending_result = None
            self._text_parts = []
            self._capture_title = False
            return

        if self._capture_snippet and lowered in {"a", "div", "td"}:
            snippet = _squash_text(" ".join(self._text_parts))
            if snippet and self.results and not self.results[-1].get("snippet"):
                self.results[-1]["snippet"] = snippet
            self._text_parts = []
            self._capture_snippet = False

    def handle_data(self, data: str) -> None:
        if self._capture_title or self._capture_snippet:
            text = data.strip()
            if text:
                self._text_parts.append(text)


class _BingSearchResultExtractor(HTMLParser):
    """Extract Bing result titles/links/snippets without a parser dependency."""

    def __init__(self) -> None:
        super().__init__()
        self.results: list[dict[str, str]] = []
        self._in_result = False
        self._result_depth = 0
        self._capture_title = False
        self._capture_snippet = False
        self._captured_title_for_result = False
        self._pending_result: dict[str, str] | None = None
        self._text_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lowered = tag.lower()
        attrs_dict = {key: value or "" for key, value in attrs}
        class_name = attrs_dict.get("class", "")

        if not self._in_result and lowered == "li" and "b_algo" in class_name:
            self._in_result = True
            self._result_depth = 1
            self._pending_result = None
            self._captured_title_for_result = False
            self._text_parts = []
            return

        if not self._in_result:
            return

        self._result_depth += 1

        if (
            lowered == "a"
            and self._pending_result is None
            and not self._captured_title_for_result
        ):
            url = _normalize_search_href(attrs_dict.get("href", ""))
            if url:
                self._pending_result = {"title": "", "url": url, "snippet": ""}
                self._text_parts = []
                self._capture_title = True
            return

        if lowered == "p" and self.results:
            self._text_parts = []
            self._capture_snippet = True

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.lower()
        if self._capture_title and lowered == "a" and self._pending_result:
            self._pending_result["title"] = _squash_text(" ".join(self._text_parts))
            if self._pending_result["title"]:
                self.results.append(self._pending_result)
                self._captured_title_for_result = True
            self._pending_result = None
            self._text_parts = []
            self._capture_title = False

        if self._capture_snippet and lowered == "p":
            snippet = _squash_text(" ".join(self._text_parts))
            if snippet and self.results and not self.results[-1].get("snippet"):
                self.results[-1]["snippet"] = snippet
            self._text_parts = []
            self._capture_snippet = False

        if self._in_result:
            self._result_depth -= 1
            if self._result_depth <= 0:
                self._in_result = False
                self._result_depth = 0
                self._pending_result = None
                self._capture_title = False
                self._capture_snippet = False
                self._captured_title_for_result = False
                self._text_parts = []

    def handle_data(self, data: str) -> None:
        if self._capture_title or self._capture_snippet:
            text = data.strip()
            if text:
                self._text_parts.append(text)


def _squash_text(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def _normalize_search_href(href: str) -> str:
    if not href:
        return ""
    if href.startswith("//"):
        href = "https:" + href
    parsed = urlparse(href)
    query = parse_qs(parsed.query)
    uddg = query.get("uddg")
    if uddg:
        candidate = uddg[0]
        return candidate if candidate.startswith(("https://", "http://")) else ""
    return href if href.startswith(("https://", "http://")) else ""


def _looks_like_search_challenge(text: str) -> bool:
    lowered = (text or "").lower()
    return any(
        marker in lowered
        for marker in (
            "anomaly.js",
            "captcha",
            "challenge",
            "verify you are human",
            "unusual traffic",
        )
    )


_SEARCH_ENDPOINTS = (
    (
        "DuckDuckGo Lite",
        "https://lite.duckduckgo.com/lite/?q={query}",
        _DuckDuckGoSearchResultExtractor,
    ),
    (
        "DuckDuckGo HTML",
        "https://html.duckduckgo.com/html/?q={query}",
        _DuckDuckGoSearchResultExtractor,
    ),
    (
        "Bing",
        "https://www.bing.com/search?q={query}",
        _BingSearchResultExtractor,
    ),
)


async def search_web(query: str) -> Dict[str, Any]:
    """Search the public web for authoritative sources related to *query*.

    This best-effort helper intentionally returns only compact result metadata.
    The LLM can follow up with ``FETCH_URL`` for a specific authoritative page.
    """
    clean_query = _squash_text(query)[:300]
    if not clean_query:
        return {
            "query": query,
            "ok": False,
            "text": "",
            "error": "empty search query",
        }

    logger.info("[web_research] Searching web for '%s'", clean_query)
    errors: list[str] = []
    results: list[dict[str, str]] = []
    provider = ""

    async with async_client(timeout=15) as client:
        for provider_name, url_template, parser_cls in _SEARCH_ENDPOINTS:
            search_url = url_template.format(query=quote_plus(clean_query))
            provider = provider_name
            try:
                r = await client.get(
                    search_url,
                    follow_redirects=False,
                    headers={
                        "User-Agent": (
                            "Mozilla/5.0 (compatible; agentyzer/1.0; "
                            "+https://example.invalid)"
                        ),
                        "Accept": "text/html",
                    },
                )
            except Exception as e:
                logger.warning(
                    "[web_research] Search failed for '%s' via %s: %s",
                    clean_query,
                    provider_name,
                    e,
                )
                errors.append(f"{provider_name}: {e}")
                continue

            if r.status_code >= 400:
                errors.append(f"{provider_name}: HTTP {r.status_code}")
                continue

            html = r.text[:_MAX_RESPONSE_BYTES]
            if _looks_like_search_challenge(html):
                errors.append(f"{provider_name}: provider challenge page")
                continue

            parser = parser_cls()
            parser.feed(html)
            results = parser.results[:5]
            if results:
                break
            errors.append(f"{provider_name}: no search results extracted")

    if not results:
        return {
            "query": clean_query,
            "ok": False,
            "text": "",
            "error": "; ".join(errors) or "no search results extracted",
        }

    lines = [
        f"Search query: {clean_query}",
        f"Search provider: {provider}",
        "Search results:",
    ]
    for idx, result in enumerate(results, start=1):
        title = result.get("title") or "(untitled)"
        url = result.get("url") or ""
        snippet = result.get("snippet") or ""
        lines.append(f"{idx}. {title}")
        lines.append(f"   URL: {url}")
        if snippet:
            lines.append(f"   Snippet: {snippet[:500]}")

    return {
        "query": clean_query,
        "ok": True,
        "text": "\n".join(lines)[:_MAX_TEXT_CHARS],
        "error": None,
    }


# ------------------------------------------------------------------ #
# Component source fetching
# ------------------------------------------------------------------ #


async def fetch_component_source(
    package_name: str,
    vulnerable_component: str = "",
) -> Dict[str, Any]:
    """Fetch source details of a package to understand how it uses a dependency.

    Looks up the package on PyPI and npm to find its source repository,
    then fetches the repository tree from GitHub to find files that
    reference *vulnerable_component*.  Returns extracted source snippets
    showing how the intermediary uses the vulnerable dependency.

    Returns ``{"package": str, "ok": bool, "text": str, "error": str | None}``.
    """
    logger.info(
        "[web_research] Fetching source details for '%s' (looking for usage of '%s')",
        package_name,
        vulnerable_component,
    )

    # Step 1: Find the source repository URL via PyPI or npm
    repo_url = await _find_source_repo(package_name)
    if not repo_url:
        return {
            "package": package_name,
            "ok": False,
            "text": "",
            "error": "Could not find source repository for package",
        }

    # Step 2: Normalise to a GitHub API-friendly URL
    github_match = re.match(
        r"https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$", repo_url
    )
    if not github_match:
        # Fall back to fetching the repo URL page itself
        result = await fetch_url(repo_url)
        if result["ok"]:
            return {
                "package": package_name,
                "ok": True,
                "text": f"Source repository: {repo_url}\n\n{result['text']}",
                "error": None,
            }
        return {
            "package": package_name,
            "ok": False,
            "text": "",
            "error": f"Source repo found ({repo_url}) but could not fetch contents",
        }

    owner, repo = github_match.group(1), github_match.group(2)

    # Step 3: Search for files referencing the vulnerable component via GitHub API
    search_results = await _github_code_search(owner, repo, vulnerable_component)
    if search_results:
        return {
            "package": package_name,
            "ok": True,
            "text": search_results,
            "error": None,
        }

    # Step 4: Fallback — fetch the repo tree and look at likely source files
    tree_results = await _github_tree_scan(owner, repo, vulnerable_component)
    if tree_results:
        return {
            "package": package_name,
            "ok": True,
            "text": tree_results,
            "error": None,
        }

    return {
        "package": package_name,
        "ok": True,
        "text": (
            f"Source repository: {repo_url}\n"
            f"No direct references to '{vulnerable_component}' found in source files."
        ),
        "error": None,
    }


async def _find_source_repo(package_name: str) -> str | None:
    """Look up a package on PyPI and npm to find its source repository URL."""
    encoded_package = quote(_squash_text(package_name)[:200], safe="@")
    # Try PyPI first
    try:
        async with async_client(timeout=10) as client:
            r = await client.get(
                f"https://pypi.org/pypi/{encoded_package}/json",
                follow_redirects=False,
            )
            if r.status_code == 200:
                data = r.json()
                info = data.get("info", {})
                urls = info.get("project_urls") or {}
                for key in (
                    "Source",
                    "Repository",
                    "Source Code",
                    "GitHub",
                    "Homepage",
                ):
                    url = urls.get(key, "")
                    if url and ("github.com" in url or "gitlab.com" in url):
                        return url
                # Fallback: check home_page
                home = info.get("home_page", "")
                if home and ("github.com" in home or "gitlab.com" in home):
                    return home
    except Exception:
        pass

    # Try npm
    try:
        async with async_client(timeout=10) as client:
            r = await client.get(
                f"https://registry.npmjs.org/{encoded_package}",
                follow_redirects=False,
            )
            if r.status_code == 200:
                data = r.json()
                npm_repo = data.get("repository", {})
                if isinstance(npm_repo, dict):
                    url = npm_repo.get("url", "")
                elif isinstance(npm_repo, str):
                    url = npm_repo
                else:
                    url = ""
                # Normalise git+https://... or git://...
                url = re.sub(r"^git\+", "", url)
                url = re.sub(r"^git://", "https://", url)
                url = re.sub(r"\.git$", "", url)
                if url and ("github.com" in url or "gitlab.com" in url):
                    return url
    except Exception:
        pass

    return None


async def _github_code_search(owner: str, repo: str, component: str) -> str | None:
    """Search a GitHub repo for files referencing *component* via the search API."""
    if not component:
        return None

    search_url = (
        f"https://api.github.com/search/code"
        f"?q={component}+repo:{owner}/{repo}"
        f"&per_page=5"
    )
    try:
        async with async_client(timeout=15) as client:
            r = await client.get(
                search_url,
                follow_redirects=False,
                headers={
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "agentyzer/1.0",
                },
            )
            if r.status_code != 200:
                return None
            data = r.json()
            items = data.get("items", [])
            if not items:
                return None

            parts = [
                f"Source repository: https://github.com/{owner}/{repo}",
                f"Files referencing '{component}' ({len(items)} found):",
            ]
            for item in items[:5]:
                path = item.get("path", "")
                raw_url = (
                    f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{path}"
                )
                file_result = await _fetch_raw_file(client, raw_url)
                if file_result:
                    relevant = _extract_relevant_lines(file_result, component)
                    parts.append(f"\n--- {path} ---")
                    parts.append(relevant)

            text = "\n".join(parts)
            return text[:_MAX_TEXT_CHARS]
    except Exception as e:
        logger.warning("[web_research] GitHub code search failed: %s", e)
        return None


async def _github_tree_scan(owner: str, repo: str, component: str) -> str | None:
    """Fetch the default branch tree and look for source files referencing *component*."""
    tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/HEAD?recursive=1"
    try:
        async with async_client(timeout=15) as client:
            r = await client.get(
                tree_url,
                follow_redirects=False,
                headers={
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "agentyzer/1.0",
                },
            )
            if r.status_code != 200:
                return None
            data = r.json()
            tree = data.get("tree", [])

            # Find candidate source files (manifests + source files)
            candidates: list[str] = []
            for entry in tree:
                if entry.get("type") != "blob":
                    continue
                path = entry.get("path", "")
                lower = path.lower()
                if any(
                    lower.endswith(ext)
                    for ext in (
                        "requirements.txt",
                        "pyproject.toml",
                        "setup.py",
                        "setup.cfg",
                        "package.json",
                        "go.mod",
                        "cargo.toml",
                        "pom.xml",
                    )
                ):
                    candidates.insert(0, path)  # manifests first
                elif any(
                    lower.endswith(ext)
                    for ext in (".py", ".js", ".ts", ".go", ".rs", ".java")
                ):
                    candidates.append(path)

            if not candidates:
                return None

            parts = [f"Source repository: https://github.com/{owner}/{repo}"]
            files_checked = 0
            files_with_hits = 0

            for path in candidates[:30]:
                raw_url = (
                    f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{path}"
                )
                content = await _fetch_raw_file(client, raw_url)
                files_checked += 1
                if not content:
                    continue
                if component and component.lower() not in content.lower():
                    continue
                files_with_hits += 1
                relevant = _extract_relevant_lines(content, component)
                parts.append(f"\n--- {path} ---")
                parts.append(relevant)
                if files_with_hits >= 5:
                    break

            if files_with_hits == 0:
                return None

            parts.insert(
                1,
                f"Scanned {files_checked} files, {files_with_hits} reference '{component}':",
            )
            text = "\n".join(parts)
            return text[:_MAX_TEXT_CHARS]
    except Exception as e:
        logger.warning("[web_research] GitHub tree scan failed: %s", e)
        return None


async def _fetch_raw_file(client: Any, url: str) -> str | None:
    """Fetch a raw file from GitHub, returning its text or None."""
    try:
        r = await client.get(
            url,
            follow_redirects=False,
            headers={"User-Agent": "agentyzer/1.0"},
        )
        if r.status_code == 200:
            return r.text[:_MAX_RESPONSE_BYTES]
    except Exception:
        pass
    return None


def _extract_relevant_lines(content: str, component: str, context: int = 3) -> str:
    """Extract lines mentioning *component* with surrounding context."""
    lines = content.splitlines()
    relevant_indices: set[int] = set()

    for i, line in enumerate(lines):
        if component.lower() in line.lower():
            for j in range(max(0, i - context), min(len(lines), i + context + 1)):
                relevant_indices.add(j)

    if not relevant_indices:
        return "(no matching lines)"

    result_lines: list[str] = []
    sorted_indices = sorted(relevant_indices)
    prev = -2
    for idx in sorted_indices:
        if idx > prev + 1:
            if result_lines:
                result_lines.append("  ...")
        result_lines.append(f"  {idx + 1:4d}: {lines[idx]}")
        prev = idx

    return "\n".join(result_lines)


# ------------------------------------------------------------------ #
# Directive parsing
# ------------------------------------------------------------------ #
_FETCH_URL_RE = re.compile(r"^FETCH_URL:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
_FETCH_SEARCH_RE = re.compile(
    r"^FETCH_SEARCH:\s*(.+)$", re.MULTILINE | re.IGNORECASE
)
_FETCH_PKG_RE = re.compile(r"^FETCH_PACKAGE:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
_FETCH_SRC_RE = re.compile(r"^FETCH_SOURCE:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
_INLINE_FETCH_RE = re.compile(
    r"\bFETCH_(URL|SEARCH|PACKAGE|SOURCE)\b\s*:?\s*(.+)$", re.IGNORECASE
)
_INLINE_FETCH_FRAGMENT_RE = re.compile(
    r"(?:\b(?:Validate|Fix|Evidence|Surface|Desc)\s*:\s*)?"
    r"\bFETCH_(?:URL|SEARCH|PACKAGE|SOURCE)\b\s*:?\s*.*$",
    re.IGNORECASE,
)
_DIRECTIVE_TYPES = {
    "URL": "url",
    "SEARCH": "search",
    "PACKAGE": "package",
    "SOURCE": "source",
}


def _clean_fetch_target(kind: str, raw_target: str) -> str:
    target = " ".join(raw_target.strip().split())
    if not target:
        return ""
    if target[0] in ",;|/":
        return ""
    target = target.strip("`'\"<> ")
    if kind == "URL":
        match = re.search(r"https?://[^\s)>\]]+", target, re.IGNORECASE)
        if not match:
            return ""
        return match.group(0).rstrip(".,;")
    target = target.strip(" .;")
    if not re.search(r"[A-Za-z0-9]", target):
        return ""
    if target.upper().startswith(("FETCH_", "OR FETCH_")):
        return ""
    return target


def _append_directive(
    directives: List[Dict[str, str]],
    seen: set[tuple[str, str]],
    kind: str,
    target: str,
) -> None:
    directive_type = _DIRECTIVE_TYPES[kind.upper()]
    cleaned = _clean_fetch_target(kind.upper(), target)
    if not cleaned:
        return
    key = (directive_type, cleaned)
    if key in seen:
        return
    seen.add(key)
    directives.append({"type": directive_type, "target": cleaned})


def parse_fetch_directives(llm_response: str) -> List[Dict[str, str]]:
    """Extract FETCH_* directives from an LLM response.

    Returns a list of
    ``{"type": "url"|"search"|"package"|"source", "target": str}`` dicts,
    capped at ``MAX_FETCHES_PER_TURN``.
    """
    directives: List[Dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for m in _FETCH_URL_RE.finditer(llm_response):
        _append_directive(directives, seen, "URL", m.group(1))

    for m in _FETCH_SEARCH_RE.finditer(llm_response):
        _append_directive(directives, seen, "SEARCH", m.group(1))

    for m in _FETCH_PKG_RE.finditer(llm_response):
        _append_directive(directives, seen, "PACKAGE", m.group(1))

    for m in _FETCH_SRC_RE.finditer(llm_response):
        _append_directive(directives, seen, "SOURCE", m.group(1))

    for line in llm_response.splitlines():
        match = _INLINE_FETCH_RE.search(line)
        if not match:
            continue
        _append_directive(directives, seen, match.group(1), match.group(2))

    return directives[:MAX_FETCHES_PER_TURN]


def has_fetch_directives(llm_response: str) -> bool:
    """Check if the LLM response contains any FETCH directives."""
    return bool(
        _FETCH_URL_RE.search(llm_response)
        or _FETCH_SEARCH_RE.search(llm_response)
        or _FETCH_PKG_RE.search(llm_response)
        or _FETCH_SRC_RE.search(llm_response)
    )


async def fulfill_directives(
    directives: List[Dict[str, str]],
    vulnerable_component: str = "",
) -> str:
    """Execute fetch directives and format results as text for the LLM.

    *vulnerable_component* is passed to ``FETCH_SOURCE`` requests so the
    source scanner knows which dependency to search for in the target
    package's source code.

    Returns a formatted string with all fetch results.
    """
    if not directives:
        return ""

    parts: List[str] = []
    for d in directives:
        parts.append(await _fulfill_single_directive(d, vulnerable_component))

    return "\n".join(parts)


async def _fulfill_single_directive(
    directive: Dict[str, str],
    vulnerable_component: str = "",
) -> str:
    directive_type = directive.get("type")
    target = directive.get("target", "")
    if directive_type == "url":
        result = await fetch_url(target)
        if result["ok"]:
            return f"--- Fetched: {result['url']} ---\n{result['text']}\n"
        return f"--- Fetch failed: {result['url']} ({result['error']}) ---\n"
    if directive_type == "search":
        result = await search_web(target)
        if result["ok"]:
            return (
                f"--- Search results for: {result['query']} ---\n"
                f"{result['text']}\n"
            )
        return f"--- Search failed: {result['query']} ({result['error']}) ---\n"
    if directive_type == "package":
        result = await fetch_package_info(target)
        if result["ok"]:
            return f"--- Package info: {result['package']} ---\n{result['text']}\n"
        return (
            f"--- Package lookup failed: {result['package']} "
            f"({result['error']}) ---\n"
        )
    if directive_type == "source":
        result = await fetch_component_source(
            target, vulnerable_component=vulnerable_component
        )
        if result["ok"]:
            return f"--- Source of {result['package']} ---\n{result['text']}\n"
        return (
            f"--- Source fetch failed: {result['package']} "
            f"({result['error']}) ---\n"
        )
    return f"--- Fetch failed: {target or 'unknown'} (unsupported directive) ---\n"


def _tool_call_id(tool_call: dict[str, Any], index: int) -> str:
    value = str(tool_call.get("id") or "").strip()
    return value or f"call_{index + 1}"


def _tool_call_name(tool_call: dict[str, Any]) -> str:
    function = tool_call.get("function") or {}
    if not isinstance(function, dict):
        return ""
    return str(function.get("name") or "").strip()


def _tool_call_arguments(tool_call: dict[str, Any]) -> dict[str, Any]:
    function = tool_call.get("function") or {}
    if not isinstance(function, dict):
        return {}
    raw = function.get("arguments") or "{}"
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _tool_call_to_directive(tool_call: dict[str, Any]) -> Dict[str, str] | None:
    name = _tool_call_name(tool_call)
    directive_type = _TOOL_TO_DIRECTIVE_TYPE.get(name)
    if not directive_type:
        return None
    args = _tool_call_arguments(tool_call)
    if name == "search_web":
        target = str(args.get("query") or "").strip()
    elif name == "fetch_url":
        target = str(args.get("url") or "").strip()
    else:
        target = str(args.get("package") or args.get("name") or "").strip()
    if not target:
        return None
    return {"type": directive_type, "target": target}


async def fulfill_tool_calls(
    tool_calls: list[dict[str, Any]],
    vulnerable_component: str = "",
) -> list[dict[str, Any]]:
    """Execute native LLM tool calls through the allowlisted research tools."""
    results: list[dict[str, Any]] = []
    for index, tool_call in enumerate(tool_calls[:MAX_FETCHES_PER_TURN]):
        call_id = _tool_call_id(tool_call, index)
        name = _tool_call_name(tool_call)
        directive = _tool_call_to_directive(tool_call)
        if directive is None:
            content = (
                f"--- Tool call failed: {name or 'unknown'} "
                "(unsupported tool or missing required argument) ---\n"
            )
            results.append(
                {
                    "tool_call_id": call_id,
                    "name": name or "unknown",
                    "target": "",
                    "directive": None,
                    "content": content,
                    "ok": False,
                }
            )
            continue

        content = await _fulfill_single_directive(directive, vulnerable_component)
        results.append(
            {
                "tool_call_id": call_id,
                "name": name,
                "target": directive["target"],
                "directive": directive,
                "content": content,
                "ok": " failed:" not in content.lower()
                and "tool call failed" not in content.lower(),
            }
        )
    return results


# ------------------------------------------------------------------ #
# LLM-with-research loop
# ------------------------------------------------------------------ #
async def generate_with_research(
    ollama: Any,
    prompt: str,
    *,
    system: str | None = None,
    temperature: float = 0.0,
    timeout: int = 300,
    num_predict: int = 4096,
    max_rounds: int = MAX_RESEARCH_ROUNDS,
    vulnerable_component: str = "",
) -> tuple[str, List[Dict[str, Any]]]:
    """Call the LLM, fulfilling any FETCH directives it emits.

    If the LLM's response contains ``FETCH_URL:``, ``FETCH_SEARCH:``,
    ``FETCH_PACKAGE:``, or ``FETCH_SOURCE:`` directives, this function fetches
    the requested resources and re-prompts the LLM with the results appended.
    This loop repeats up to *max_rounds* times.

    *vulnerable_component* is forwarded to ``FETCH_SOURCE`` requests so
    the source scanner knows which dependency to look for.

    Returns ``(final_response, research_log)`` where *research_log* is a
    list of ``{"round": int, "directives": [...], "results_summary": str}``
    entries documenting what was fetched.
    """
    if getattr(ollama, "supports_tool_calls", False):
        try:
            return await _generate_with_native_research(
                ollama,
                prompt,
                system=system,
                temperature=temperature,
                timeout=timeout,
                num_predict=num_predict,
                max_rounds=max_rounds,
                vulnerable_component=vulnerable_component,
            )
        except (NotImplementedError, RuntimeError) as exc:
            logger.warning(
                "[web_research] Native tool-call path failed; falling back to "
                "FETCH_* directives: %s",
                exc,
            )

    return await _generate_with_text_research(
        ollama,
        prompt,
        system=system,
        temperature=temperature,
        timeout=timeout,
        num_predict=num_predict,
        max_rounds=max_rounds,
        vulnerable_component=vulnerable_component,
    )


async def _generate_with_text_research(
    ollama: Any,
    prompt: str,
    *,
    system: str | None = None,
    temperature: float = 0.0,
    timeout: int = 300,
    num_predict: int = 4096,
    max_rounds: int = MAX_RESEARCH_ROUNDS,
    vulnerable_component: str = "",
) -> tuple[str, List[Dict[str, Any]]]:
    research_log: List[Dict[str, Any]] = []
    current_prompt = prompt

    for round_num in range(1, max_rounds + 1):
        raw = await ollama.generate(
            current_prompt,
            system=system,
            temperature=temperature,
            timeout=timeout,
            num_predict=num_predict,
        )

        directives = parse_fetch_directives(raw)
        if not directives:
            # No fetch requests — return the response as-is
            return raw, research_log

        logger.info(
            "[web_research] Round %d: LLM requested %d fetches: %s",
            round_num,
            len(directives),
            [d["target"] for d in directives],
        )

        # Fulfill the directives
        fetched_text = await fulfill_directives(
            directives, vulnerable_component=vulnerable_component
        )

        research_log.append(
            {
                "round": round_num,
                "directives": directives,
                "results_summary": fetched_text[:500],
            }
        )

        # Strip the FETCH directives from the LLM's partial response
        # and build a continuation prompt
        partial = _strip_fetch_lines(raw)

        current_prompt = f"""{prompt}

--- YOUR PREVIOUS PARTIAL RESPONSE ---
{partial}

--- RESEARCH RESULTS (round {round_num}) ---
{fetched_text}

{_RESEARCH_CONTINUATION_INSTRUCTION}"""

    # Final call after all research rounds
    raw = await ollama.generate(
        current_prompt,
        system=system,
        temperature=temperature,
        timeout=timeout,
        num_predict=num_predict,
    )
    return raw, research_log


async def _generate_with_native_research(
    ollama: Any,
    prompt: str,
    *,
    system: str | None = None,
    temperature: float = 0.0,
    timeout: int = 300,
    num_predict: int = 4096,
    max_rounds: int = MAX_RESEARCH_ROUNDS,
    vulnerable_component: str = "",
) -> tuple[str, List[Dict[str, Any]]]:
    research_log: List[Dict[str, Any]] = []
    messages: list[dict[str, Any]] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    for round_num in range(1, max_rounds + 1):
        response = await ollama.chat_completion(
            messages,
            tools=research_tool_schemas(),
            tool_choice="auto",
            temperature=temperature,
            timeout=timeout,
            num_predict=num_predict,
        )
        raw = str(response.get("content") or "")
        tool_calls = response.get("tool_calls") or []
        if tool_calls:
            logger.info(
                "[web_research] Round %d: LLM requested %d native tool calls",
                round_num,
                len(tool_calls),
            )
            tool_results = await fulfill_tool_calls(
                tool_calls, vulnerable_component=vulnerable_component
            )
            fetched_text = "\n".join(result["content"] for result in tool_results)
            directives = [
                result["directive"]
                for result in tool_results
                if result.get("directive") is not None
            ]
            research_log.append(
                {
                    "round": round_num,
                    "tool_protocol": "native",
                    "tool_calls": [
                        {
                            "id": result["tool_call_id"],
                            "name": result["name"],
                            "target": result["target"],
                            "ok": result["ok"],
                        }
                        for result in tool_results
                    ],
                    "directives": directives,
                    "results_summary": fetched_text[:500],
                }
            )
            assistant_message: dict[str, Any] = {
                "role": "assistant",
                "content": raw,
                "tool_calls": tool_calls,
            }
            messages.append(assistant_message)
            for result in tool_results:
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": result["tool_call_id"],
                        "name": result["name"],
                        "content": result["content"],
                    }
                )
            continue

        directives = parse_fetch_directives(raw)
        if not directives:
            return raw, research_log

        logger.info(
            "[web_research] Round %d: LLM requested %d text fetches: %s",
            round_num,
            len(directives),
            [d["target"] for d in directives],
        )
        fetched_text = await fulfill_directives(
            directives, vulnerable_component=vulnerable_component
        )
        research_log.append(
            {
                "round": round_num,
                "tool_protocol": "text",
                "directives": directives,
                "results_summary": fetched_text[:500],
            }
        )
        messages.append({"role": "assistant", "content": _strip_fetch_lines(raw)})
        messages.append(
            {
                "role": "user",
                "content": (
                    f"--- RESEARCH RESULTS (round {round_num}) ---\n"
                    f"{fetched_text}\n\n{_RESEARCH_CONTINUATION_INSTRUCTION}"
                ),
            }
        )

    messages.append(
        {
            "role": "user",
            "content": (
                "Research/tool round limit reached. Do not request more tools; "
                "produce the final structured response from the evidence already "
                "provided."
            ),
        }
    )
    response = await ollama.chat_completion(
        messages,
        temperature=temperature,
        timeout=timeout,
        num_predict=num_predict,
    )
    return str(response.get("content") or ""), research_log


def _strip_fetch_lines(text: str) -> str:
    """Remove FETCH_* directive lines from LLM output."""
    lines = []
    for line in text.splitlines():
        stripped = line.strip().upper()
        if (
            stripped.startswith("FETCH_URL:")
            or stripped.startswith("FETCH_SEARCH:")
            or stripped.startswith("FETCH_PACKAGE:")
            or stripped.startswith("FETCH_SOURCE:")
        ):
            continue
        if _INLINE_FETCH_RE.search(line):
            cleaned = _INLINE_FETCH_FRAGMENT_RE.sub("", line).rstrip(" -;:,")
            if cleaned:
                lines.append(cleaned)
            continue
        lines.append(line)
    return "\n".join(lines)
