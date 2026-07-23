#!/usr/bin/env python3
"""Generate or verify the checked-in Agentyzer OpenAPI contract."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
AGENTYZER_ROOT = ROOT / "agentyzer"
OUTPUT_PATH = ROOT / "openapi" / "code-analysis-openapi.json"


def _load_openapi() -> dict[str, Any]:
    sys.path.insert(0, str(AGENTYZER_ROOT))
    os.environ.setdefault("AGENTYZER_ENVIRONMENT", "test")
    os.environ.setdefault(
        "AGENTYZER_SERVICE_TOKEN",
        "openapi-generation-service-token-1234567890",
    )
    os.environ.setdefault(
        "AGENTYZER_ADMIN_TOKEN",
        "openapi-generation-admin-token-123456789012",
    )

    from src.main import app

    return app.openapi()


def _serialized(schema: dict[str, Any]) -> str:
    return json.dumps(schema, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail when the checked-in contract differs from the live schema",
    )
    args = parser.parse_args()

    schema = _load_openapi()
    if args.check:
        try:
            checked_in = json.loads(OUTPUT_PATH.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            print(f"{OUTPUT_PATH.relative_to(ROOT)} is unreadable: {exc}", file=sys.stderr)
            return 1
        if checked_in != schema:
            print(
                "Agentyzer OpenAPI contract is stale; run "
                "`cd agentyzer && uv run python ../scripts/"
                "generate-agentyzer-openapi.py`.",
                file=sys.stderr,
            )
            return 1
        print("Agentyzer OpenAPI contract is current.")
        return 0

    OUTPUT_PATH.write_text(_serialized(schema), encoding="utf-8")
    print(f"Wrote {OUTPUT_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
