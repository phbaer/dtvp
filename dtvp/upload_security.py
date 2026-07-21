import os

from fastapi import HTTPException, UploadFile


DEFAULT_SETTINGS_UPLOAD_MAX_BYTES = 1 * 1024 * 1024
DEFAULT_TMRESCORE_UPLOAD_MAX_BYTES = 20 * 1024 * 1024
DEFAULT_PROJECT_ARCHIVE_UPLOAD_MAX_BYTES = 100 * 1024 * 1024


def upload_limit(setting: str, default: int) -> int:
    raw_value = os.getenv(setting, str(default))
    try:
        return max(1024, int(raw_value))
    except (TypeError, ValueError):
        return default


async def read_upload_limited(
    upload: UploadFile,
    *,
    setting: str,
    default: int,
    label: str,
) -> bytes:
    limit = upload_limit(setting, default)
    content = await upload.read(limit + 1)
    if len(content) > limit:
        raise HTTPException(
            status_code=413,
            detail=f"{label} exceeds the configured {limit}-byte upload limit",
        )
    return content
