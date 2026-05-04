import os
from datetime import datetime
from typing import Any, Optional


def get_env_int_with_floor(
    env_name: str,
    *,
    default: int,
    minimum: int,
    logger: Any,
) -> int:
    raw_value = os.getenv(env_name, str(default))
    try:
        return max(minimum, int(raw_value))
    except TypeError, ValueError:
        logger.warning(
            "Invalid %s=%r, falling back to %s",
            env_name,
            raw_value,
            default,
        )
        return default


def parse_iso_timestamp(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).timestamp()
    except TypeError, ValueError:
        return None
