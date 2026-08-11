#!/usr/bin/env python3
"""Check Agentyzer readiness from inside the Arcane-managed container."""

import os
from http.client import HTTPConnection
from pathlib import Path


def main() -> int:
    token = Path(os.environ["AGENTYZER_SERVICE_TOKEN_FILE"]).read_text(
        encoding="utf-8"
    ).strip()
    if not token:
        return 1

    connection = HTTPConnection("127.0.0.1", 8000, timeout=5)
    try:
        connection.request(
            "GET",
            "/readyz",
            headers={
                "Authorization": "Bearer " + token,
                "X-Agentyzer-Owner": "healthcheck",
            },
        )
        response = connection.getresponse()
        response.read()
        return 0 if response.status == 200 else 1
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
