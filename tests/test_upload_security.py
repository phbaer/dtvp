from io import BytesIO

import pytest
from fastapi import HTTPException, UploadFile

from dtvp.upload_security import read_upload_limited, upload_limit


def test_upload_limit_falls_back_for_invalid_values(monkeypatch):
    monkeypatch.setenv("DTVP_TEST_UPLOAD_LIMIT", "invalid")

    assert upload_limit("DTVP_TEST_UPLOAD_LIMIT", 4096) == 4096


@pytest.mark.asyncio
async def test_read_upload_limited_rejects_oversized_file(monkeypatch):
    monkeypatch.setenv("DTVP_TEST_UPLOAD_LIMIT", "1024")
    upload = UploadFile(filename="large.bin", file=BytesIO(b"x" * 1025))

    with pytest.raises(HTTPException) as exc_info:
        await read_upload_limited(
            upload,
            setting="DTVP_TEST_UPLOAD_LIMIT",
            default=4096,
            label="Test upload",
        )

    assert exc_info.value.status_code == 413
    assert "1024-byte" in exc_info.value.detail


@pytest.mark.asyncio
async def test_read_upload_limited_accepts_file_at_limit(monkeypatch):
    monkeypatch.setenv("DTVP_TEST_UPLOAD_LIMIT", "1024")
    upload = UploadFile(filename="valid.bin", file=BytesIO(b"x" * 1024))

    content = await read_upload_limited(
        upload,
        setting="DTVP_TEST_UPLOAD_LIMIT",
        default=4096,
        label="Test upload",
    )

    assert len(content) == 1024
