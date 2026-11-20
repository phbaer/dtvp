import os
import signal
import socket
import subprocess
import sys
import textwrap
import time

import httpx

from dtvp.shutdown_signals import chain_shutdown_signals


def test_chained_handler_runs_the_callback_then_the_previous_handler():
    calls = []
    original = signal.signal(signal.SIGUSR1, lambda sig, frame: calls.append("previous"))
    try:
        restore = chain_shutdown_signals(lambda: calls.append("callback"), (signal.SIGUSR1,))
        signal.raise_signal(signal.SIGUSR1)
        assert calls == ["callback", "previous"]

        restore()
        signal.raise_signal(signal.SIGUSR1)
        assert calls == ["callback", "previous", "previous"]
    finally:
        signal.signal(signal.SIGUSR1, original)


def test_a_failing_callback_still_reaches_the_previous_handler():
    calls = []
    original = signal.signal(signal.SIGUSR1, lambda sig, frame: calls.append("previous"))
    try:

        def boom():
            raise RuntimeError("boom")

        restore = chain_shutdown_signals(boom, (signal.SIGUSR1,))
        signal.raise_signal(signal.SIGUSR1)
        restore()
        assert calls == ["previous"]
    finally:
        signal.signal(signal.SIGUSR1, original)


APP = textwrap.dedent(
    """
    from contextlib import asynccontextmanager

    from fastapi import FastAPI, Request

    from dtvp.event_hub import EventHub
    from dtvp.event_routes import EventRouteDeps, create_event_router
    from dtvp.shutdown_signals import chain_shutdown_signals

    hub = EventHub(boot_id="boot")


    async def authenticate(request: Request) -> str:
        return "rita"


    @asynccontextmanager
    async def lifespan(app):
        # The same order as dtvp.main.lifespan.
        restore = chain_shutdown_signals(hub.close)
        try:
            yield
        finally:
            restore()
            hub.close()


    app = FastAPI(lifespan=lifespan)
    app.include_router(
        create_event_router(
            EventRouteDeps(
                hub=hub,
                authenticate=authenticate,
                get_user_role=lambda user: "REVIEWER",
                build="test",
                source_state=lambda: {},
                heartbeat_seconds=1.0,
                max_stream_seconds=600.0,
            )
        ),
        prefix="/api",
    )
    """
)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_sigterm_ends_open_streams_before_uvicorn_waits_for_them(tmp_path):
    (tmp_path / "stream_app.py").write_text(APP)
    port = _free_port()
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(tmp_path), os.getcwd(), env.get("PYTHONPATH", "")]
    )
    server = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "stream_app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.monotonic() + 20
        while True:
            try:
                httpx.get(f"http://127.0.0.1:{port}/docs", timeout=0.5)
                break
            except httpx.HTTPError:
                if time.monotonic() > deadline or server.poll() is not None:
                    raise AssertionError("uvicorn did not start")
                time.sleep(0.1)

        with httpx.stream(
            "GET", f"http://127.0.0.1:{port}/api/events", timeout=10
        ) as response:
            lines = response.iter_lines()
            assert next(lines).startswith("id: boot:0")
            server.send_signal(signal.SIGTERM)
            sent = time.monotonic()
            # The server ends the stream; the client sees the body close.
            for _line in lines:
                if time.monotonic() - sent > 8:
                    break
        server.wait(timeout=10)
        assert time.monotonic() - sent < 5
    finally:
        if server.poll() is None:
            server.kill()
            server.wait()
