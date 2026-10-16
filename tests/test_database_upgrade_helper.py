"""No-network candidate orchestration and failure containment, never production acceptance."""

import hashlib
import json
import subprocess
from types import SimpleNamespace

import pytest

from scripts import database_upgrade as upgrade


@pytest.fixture
def harness(monkeypatch, tmp_path):
    calls, flags = [], {}
    args = [
        "--source-container",
        "source",
        "--target-name",
        "candidate",
        "--backup-dir",
        str(tmp_path),
        "--writers-stopped",
    ]
    monkeypatch.setenv("DTVP_UPGRADE_TARGET_PASSWORD", "synthetic-password-123")
    monkeypatch.setattr(upgrade.time, "sleep", lambda _: None)

    def docker(*items, **kwargs):
        calls.append(items)
        if items[:2] == ("container", "ls"):
            return SimpleNamespace(stdout="candidate" if flags.get("container") else "")
        if items[:2] == ("volume", "ls"):
            return SimpleNamespace(stdout="candidate" if flags.get("volume") else "")
        if items[:2] == ("image", "inspect"):
            if flags.get("missing_image"):
                raise subprocess.CalledProcessError(1, ["docker", *items])
            return SimpleNamespace(stdout="sha256:" + "a" * 64)
        if "SHOW server_version_num" in items:
            major = (
                flags.get("source_major", 17)
                if items[1] == "source"
                else flags.get("target_major", 18)
            )
            return SimpleNamespace(stdout=str(major * 10000 + 1))
        if "pg_dump" in items:
            kwargs["stdout"].write(b"PGDMP-synthetic")
            if flags.get("manifest_race"):
                (tmp_path / "candidate.manifest.json").write_text("retained race winner")
            if flags.get("dump_failure"):
                raise subprocess.CalledProcessError(1, ["docker", *items])
        if items[:2] == ("volume", "create"):
            flags["owner"] = next(
                item.split("=", 1)[1] for item in items if item.startswith("dtvp.upgrade=")
            )
        if items[:2] == ("volume", "inspect"):
            return SimpleNamespace(
                stdout="other-owner" if flags.get("owner_mismatch") else flags["owner"]
            )
        if items[0] == "run":
            if flags.get("run_failure"):
                raise subprocess.CalledProcessError(1, ["docker", *items])
            assert kwargs["env"]["POSTGRES_PASSWORD"] == "synthetic-password-123"
            if flags.get("tamper"):
                (tmp_path / "candidate.dump").write_bytes(b"changed")
        if "pg_restore" in items:
            assert kwargs["stdin"].read() == b"PGDMP-synthetic"
            if flags.get("restore_failure"):
                raise subprocess.CalledProcessError(1, ["docker", *items])
        return SimpleNamespace(stdout="")

    def run(items, **kwargs):
        assert items[:2] == ["docker", "exec"] and "pg_isready" in items
        assert items[items.index("-h") + 1] == "127.0.0.1"
        if flags.get("readiness_timeout"):
            raise subprocess.TimeoutExpired(items, 5)
        return SimpleNamespace(returncode=1 if flags.get("not_ready") else 0)

    monkeypatch.setattr(upgrade, "docker", docker)
    monkeypatch.setattr(upgrade.subprocess, "run", run)
    return args, calls, flags, tmp_path


def test_new_candidate_uses_private_owned_volume_pinned_local_image_and_sealed_backup(harness):
    args, calls, _, directory = harness
    upgrade.main(args)
    manifest = json.loads((directory / "candidate.manifest.json").read_text())
    assert manifest["source_major"] == 17 and manifest["target_major"] == 18
    assert manifest["sha256"] == hashlib.sha256(b"PGDMP-synthetic").hexdigest()
    assert (
        manifest["target_volume"].startswith("candidate-") and len(manifest["target_volume"]) == 42
    )
    for name in ("candidate.dump", "candidate.manifest.json"):
        assert (directory / name).stat().st_mode & 0o777 == 0o600
    command = next(call for call in calls if call[0] == "run")
    assert "--pull=never" in command and command[-1] == "sha256:" + "a" * 64
    assert (
        command[command.index("--mount") + 1]
        == f"type=volume,source={manifest['target_volume']},target=/var/lib/postgresql"
    )
    assert all("synthetic-password-123" not in item for call in calls for item in call)
    restore = next(call for call in calls if "pg_restore" in call)
    assert "--exit-on-error" in restore and "--single-transaction" in restore
    assert not any(call[0] in {"stop", "rm", "remove"} for call in calls)


@pytest.mark.parametrize("collision", ["container", "volume", "missing_image", "source_major"])
def test_readonly_preflight_failure_creates_no_backup_or_candidate(harness, collision):
    args, calls, flags, directory = harness
    flags[collision] = 18 if collision == "source_major" else True
    with pytest.raises((SystemExit, subprocess.CalledProcessError)):
        upgrade.main(args)
    assert not list(directory.iterdir())
    assert not any(
        "pg_dump" in call or call[0] == "run" or call[:2] == ("volume", "create") for call in calls
    )


@pytest.mark.parametrize("existing", ["candidate.dump", "candidate.manifest.json"])
def test_backup_and_manifest_are_never_overwritten(harness, existing):
    args, calls, _, directory = harness
    (directory / existing).write_bytes(b"retained")
    with pytest.raises(SystemExit):
        upgrade.main(args)
    assert (directory / existing).read_bytes() == b"retained"
    assert not any("pg_dump" in call for call in calls)


@pytest.mark.parametrize(
    "failure",
    [
        "owner_mismatch",
        "tamper",
        "not_ready",
        "readiness_timeout",
        "run_failure",
        "target_major",
        "restore_failure",
    ],
)
def test_candidate_failure_retains_source_and_backup_without_false_success(
    harness, failure, capsys
):
    args, calls, flags, directory = harness
    flags[failure] = 17 if failure == "target_major" else True
    with pytest.raises((RuntimeError, subprocess.CalledProcessError)):
        upgrade.main(args)
    assert (directory / "candidate.dump").exists()
    assert (directory / "candidate.manifest.json").exists()
    if failure != "restore_failure":
        assert not any("pg_restore" in call for call in calls)
    assert not any(call[0] in {"stop", "rm", "remove"} for call in calls)
    assert "Candidate restored" not in capsys.readouterr().out


def test_failed_dump_keeps_partial_backup_and_does_not_start_target(harness):
    args, calls, flags, directory = harness
    flags["dump_failure"] = True
    with pytest.raises(subprocess.CalledProcessError):
        upgrade.main(args)
    assert (directory / "candidate.dump").read_bytes() == b"PGDMP-synthetic"
    assert not (directory / "candidate.manifest.json").exists()
    assert not any(call[0] == "run" or call[:2] == ("volume", "create") for call in calls)


def test_invalid_port_is_rejected_before_docker(harness):
    args, calls, _, _ = harness
    with pytest.raises(SystemExit):
        upgrade.main([*args, "--port", "0"])
    assert not calls


def test_manifest_create_race_never_overwrites_winner_or_starts_candidate(harness):
    args, calls, flags, directory = harness
    flags["manifest_race"] = True
    with pytest.raises(FileExistsError):
        upgrade.main(args)
    assert (directory / "candidate.manifest.json").read_text() == "retained race winner"
    assert not any(call[0] == "run" or call[:2] == ("volume", "create") for call in calls)
