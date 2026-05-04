import json
from typing import Any


def read_text(path: str, encoding: str = "utf-8") -> str:
    with open(path, "r", encoding=encoding) as file_handle:
        return file_handle.read()


def write_bytes(path: str, content: bytes) -> None:
    with open(path, "wb") as file_handle:
        file_handle.write(content)


def write_json(path: str, payload: Any) -> None:
    with open(path, "w") as file_handle:
        json.dump(payload, file_handle, indent=2)


def validate_json_bytes(content: bytes) -> None:
    json.loads(content)


def write_and_validate_json_bytes(path: str, content: bytes) -> None:
    write_bytes(path, content)
    with open(path, "r") as file_handle:
        json.load(file_handle)
