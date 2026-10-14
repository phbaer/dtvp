"""Content-addressed immutable local artifacts. Database owns all metadata."""

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class Artifacts:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def path(self, sha: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise ValueError("Invalid artifact digest")
        return self.root / sha[:2] / sha[2:]

    def put(self, raw: bytes) -> str:
        sha = digest(raw)
        target = self.path(sha)
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(dir=target.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(name, target)
            except FileExistsError:
                self.read(sha)
            directory = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            os.unlink(name)
        return sha

    def read(self, sha: str) -> bytes:
        raw = self.path(sha).read_bytes()
        if digest(raw) != sha:
            raise ValueError("Artifact integrity check failed")
        return raw
