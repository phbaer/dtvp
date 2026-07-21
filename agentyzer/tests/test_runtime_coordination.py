import os
import stat

import pytest

from src.runtime_coordination import ProcessLease


def test_process_lease_rejects_a_second_runtime_and_is_owner_only(tmp_path):
    path = tmp_path / "runtime.lock"
    first = ProcessLease(str(path), "Agentyzer")
    second = ProcessLease(str(path), "Agentyzer")

    first.acquire()
    try:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert f"pid={os.getpid()}" in path.read_text(encoding="utf-8")
        with pytest.raises(RuntimeError, match="Multiple API workers"):
            second.acquire()
    finally:
        first.release()

    second.acquire()
    second.release()


def test_process_lease_refuses_a_symlink(tmp_path):
    target = tmp_path / "target"
    target.write_text("do not overwrite", encoding="utf-8")
    link = tmp_path / "runtime.lock"
    link.symlink_to(target)

    with pytest.raises(OSError):
        ProcessLease(str(link), "Agentyzer").acquire()
    assert target.read_text(encoding="utf-8") == "do not overwrite"


def test_process_lease_refuses_a_non_regular_file():
    with pytest.raises(RuntimeError, match="regular file"):
        ProcessLease("/dev/null", "Agentyzer").acquire()
