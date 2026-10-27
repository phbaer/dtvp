"""Content-addressed storage for immutable DTVP source and state artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ArtifactStore:
    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(
            root
            or os.getenv("DTVP_ARTIFACT_STORE_PATH", "data/dtvp_artifacts")
        ).expanduser()

    @staticmethod
    def encode_json(value: Any) -> bytes:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def put_bytes(self, content: bytes) -> str:
        digest = hashlib.sha256(content).hexdigest()
        target = self._path_for(digest)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                raise IOError("Existing DTVP artifact failed its SHA-256 check")
            return digest

        file_descriptor, temporary_path = tempfile.mkstemp(
            prefix=".artifact-", dir=target.parent
        )
        try:
            with os.fdopen(file_descriptor, "wb") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary_path, target)
            directory_descriptor = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        finally:
            if os.path.exists(temporary_path):
                os.unlink(temporary_path)
        return digest

    def put_json(self, value: Any) -> str:
        return self.put_bytes(self.encode_json(value))

    def get_bytes(self, digest: str) -> bytes:
        path = self._path_for(digest)
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != digest:
            raise IOError(f"DTVP artifact {digest} failed its SHA-256 check")
        return content

    def get_json(self, digest: str) -> Any:
        return json.loads(self.get_bytes(digest).decode("utf-8"))

    def _path_for(self, digest: str) -> Path:
        if not _SHA256_RE.fullmatch(digest):
            raise ValueError("Artifact key must be a lowercase SHA-256 digest")
        return self.root / digest[:2] / f"{digest[2:]}.json"
