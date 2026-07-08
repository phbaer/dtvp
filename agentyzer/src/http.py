"""Shared httpx helpers — ensures every HTTP client trusts local CA certs."""

import ssl

import httpx


def _make_ssl_context() -> ssl.SSLContext:
    """Build an SSL context that loads the **OS / system** CA certificates.

    ``ssl.create_default_context()`` reads the platform trust store
    (``/etc/ssl/certs`` on Debian/Alpine, ``SSL_CERT_FILE`` /
    ``SSL_CERT_DIR`` env-vars when set, or the Windows/macOS keychain).
    This ensures corporate / internally-signed CAs are trusted without
    having to bundle them via certifi.
    """
    return ssl.create_default_context()


# Pre-built context — reusable and thread-safe (read-only after creation).
ssl_context = _make_ssl_context()


def async_client(**kwargs: object) -> httpx.AsyncClient:
    """Create an ``httpx.AsyncClient`` that trusts the system CA store.

    All keyword arguments are forwarded to ``httpx.AsyncClient``.
    Callers that already pass ``verify=`` keep their override.
    """
    kwargs.setdefault("verify", ssl_context)  # type: ignore[arg-type]
    return httpx.AsyncClient(**kwargs)  # type: ignore[arg-type]
