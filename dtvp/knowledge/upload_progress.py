"""Measured file transfer and elapsed server wait; stderr keeps stdout machine-readable."""

import os
import sys
import threading
import time


class UploadProgress:
    def __init__(self, source, name):
        self.source = source
        self.name = name
        self.total = os.fstat(source.fileno()).st_size
        self.started = time.monotonic()
        self.sent = False
        self.last_percent = -10
        self.stop = threading.Event()
        self.output = sys.stderr
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._heartbeat, daemon=True)

    def _write(self, message):
        with self.lock:
            print(message, file=self.output, flush=True)

    def __enter__(self):
        self._write(f"Uploading {self.name!r} ({self.total:,} bytes)…")
        self.thread.start()
        return self

    def __getattr__(self, name):
        return getattr(self.source, name)

    def read(self, size=-1):
        data = self.source.read(size)
        position = min(self.total, self.source.tell())
        percent = position * 100 // self.total if self.total else 100
        if percent >= self.last_percent + 10 or (percent == 100 and not self.sent):
            self.last_percent = percent
            self._write(f"Uploaded {position:,}/{self.total:,} bytes ({percent}%).")
        if position == self.total and not self.sent:
            self.sent = True
            self._write("Upload sent. Waiting for server validation and commit confirmation…")
        return data

    def _heartbeat(self):
        while not self.stop.wait(5):
            elapsed = int(time.monotonic() - self.started)
            phase = "Waiting for server confirmation" if self.sent else "Uploading"
            self._write(f"{phase}… {elapsed}s elapsed.")

    def _stop(self):
        self.stop.set()
        self.thread.join()

    def finish(self, result):
        self._stop()
        elapsed = int(time.monotonic() - self.started)
        if result.get("committed") is True:
            suffix = " Projection pending." if result.get("projection") == "pending" else ""
            self._write(f"Import committed ({elapsed}s).{suffix}")
        else:
            self._write(f"Import outcome not confirmed ({elapsed}s); retain exact retry metadata.")

    def __exit__(self, kind, value, traceback):
        self._stop()
        if kind is not None:
            self._write(
                "Import not confirmed. Retain the captured metadata and file for an exact retry."
            )
