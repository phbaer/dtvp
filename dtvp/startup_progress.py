"""What a long-running start is doing right now.

Database and data migrations can take a while on an existing installation.
They report here; the message is printed to the console and shown on the
start page until River is ready.
"""

from __future__ import annotations

import threading

_lock = threading.Lock()
_message: str | None = None


def report_startup_progress(message: str, *, done: bool = False) -> None:
    """Print ``message`` and make it the start page's current message.

    ``done`` marks the end of the work: the message is printed, and the start
    page goes back to its own messages.
    """
    global _message
    with _lock:
        _message = None if done else message
    print(f"[startup] {message}", flush=True)


def current_startup_progress() -> str | None:
    with _lock:
        return _message


def clear_startup_progress() -> None:
    global _message
    with _lock:
        _message = None
