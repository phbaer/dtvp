#!/usr/bin/env python3
"""Check DTVP readiness from inside the Arcane-managed container."""

import os
from http.client import HTTPConnection
from urllib.parse import urlsplit


def main() -> int:
    context = "/" + os.environ.get("DTVP_CONTEXT_PATH", "/").strip("/")
    context = "" if context == "/" else context
    frontend = urlsplit(os.environ["DTVP_FRONTEND_URL"])
    connection = HTTPConnection("127.0.0.1", 8000, timeout=5)
    try:
        connection.request(
            "GET",
            context + "/readyz",
            headers={"Host": frontend.netloc},
        )
        response = connection.getresponse()
        response.read()
        return 0 if response.status == 200 else 1
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
