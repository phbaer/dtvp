"""Refusals and warnings of the instance dump. Every one carries the code of
its rule in docs/backup-and-restore.md (C1, F3, R2, W5, E1, T4, P2, ...)."""

from dataclasses import dataclass


class DumpError(Exception):
    """A dump, an export or a restore is refused."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class Finding:
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"
