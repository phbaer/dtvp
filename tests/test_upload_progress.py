"""Upload completion must not be presented as publication confirmation."""

import pytest

from dtvp.knowledge.upload_progress import UploadProgress


@pytest.mark.parametrize("projection", ["current", "pending"])
def test_measured_bytes_wait_for_receipt_and_stop_heartbeat(tmp_path, capsys, projection):
    file = tmp_path / "bom.json"
    file.write_bytes(b"x" * 100)
    with file.open("rb") as source, UploadProgress(source, file.name) as upload:
        assert upload.read(25) == b"x" * 25
        before = capsys.readouterr()
        assert "25/100 bytes (25%)" in before.err
        assert before.out == ""
        assert upload.read() == b"x" * 75
        waiting = capsys.readouterr().err
        assert "100/100 bytes (100%)" in waiting
        assert "Waiting for server" in waiting
        assert "Import committed" not in waiting
        upload.finish({"committed": True, "projection": projection})
    result = capsys.readouterr()
    assert "Import committed" in result.err
    assert ("Projection pending" in result.err) == (projection == "pending")
    assert result.out == ""
    assert not upload.thread.is_alive()


def test_connection_failure_retains_uncertain_outcome_and_stops_heartbeat(tmp_path, capsys):
    file = tmp_path / "bom.json"
    file.write_bytes(b"x")
    with pytest.raises(OSError):
        with file.open("rb") as source, UploadProgress(source, file.name) as upload:
            upload.read()
            raise OSError("Connection lost")
    output = capsys.readouterr().err
    assert "Import not confirmed" in output
    assert "exact retry" in output
    assert "Import committed" not in output
    assert not upload.thread.is_alive()


def test_unconfirmed_receipt_does_not_report_success(tmp_path, capsys):
    file = tmp_path / "bom.json"
    file.write_bytes(b"x")
    with file.open("rb") as source, UploadProgress(source, file.name) as upload:
        upload.read()
        upload.finish({"committed": None})
    output = capsys.readouterr().err
    assert "outcome not confirmed" in output
    assert "Import committed" not in output


def test_waiting_heartbeat_continues_after_upload_without_claiming_commit(tmp_path, monkeypatch):
    import io
    import threading

    waiting = threading.Event()

    class Output(io.StringIO):
        def write(self, value):
            result = super().write(value)
            if "Waiting for server confirmation" in value and "elapsed" in value:
                waiting.set()
            return result

    output = Output()
    monkeypatch.setattr("sys.stderr", output)
    file = tmp_path / "bom.json"
    file.write_bytes(b"x")
    with file.open("rb") as source:
        progress = UploadProgress(source, file.name)
        original_wait = progress.stop.wait
        monkeypatch.setattr(progress.stop, "wait", lambda interval: original_wait(0.01))
        with progress as upload:
            upload.read()
            assert waiting.wait(2), "Server wait must keep reporting elapsed progress"
            assert "Import committed" not in output.getvalue()
            upload.finish({"committed": True})
    assert not progress.thread.is_alive()
