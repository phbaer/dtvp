"""Run a callback as soon as the process is asked to stop.

Uvicorn runs the application's lifespan shutdown only after every open HTTP
connection has finished. A live-update stream (``GET /api/events``) never
finishes on its own before ``max_stream_seconds``, so work that ends such
streams must run when the signal arrives, before uvicorn waits for the
connections to drain. ``chain_shutdown_signals`` wraps the handlers installed
for SIGINT and SIGTERM (uvicorn's, when it serves the app): the callback runs
first, then the previous handler.
"""

from __future__ import annotations

import logging
import signal
import threading
from typing import Any, Callable, Iterable

logger = logging.getLogger(__name__)

SHUTDOWN_SIGNALS: tuple[int, ...] = (signal.SIGINT, signal.SIGTERM)


def chain_shutdown_signals(
    callback: Callable[[], None],
    signals: Iterable[int] = SHUTDOWN_SIGNALS,
) -> Callable[[], None]:
    """Call ``callback`` on each of ``signals``, then the previous handler.

    Returns a function that puts the previous handlers back. Signal handlers
    can only be set in the main thread; anywhere else this does nothing and
    the returned function is a no-op."""
    if threading.current_thread() is not threading.main_thread():
        return lambda: None

    previous: dict[int, Any] = {}

    def handler(sig: int, frame: Any) -> None:
        try:
            callback()
        except Exception:
            logger.exception("Shutdown callback failed")
        prior = previous.get(sig)
        if callable(prior):
            prior(sig, frame)
        elif prior == signal.SIG_DFL:
            signal.signal(sig, signal.SIG_DFL)
            signal.raise_signal(sig)

    for sig in signals:
        try:
            previous[sig] = signal.signal(sig, handler)
        except (ValueError, OSError):
            logger.debug("Cannot chain handler for signal %s", sig)

    def restore() -> None:
        for sig, prior in previous.items():
            try:
                if signal.getsignal(sig) is handler:
                    signal.signal(sig, prior if prior is not None else signal.SIG_DFL)
            except (ValueError, OSError):
                pass

    return restore
