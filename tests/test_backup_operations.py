import os
from pathlib import Path
import subprocess
import tarfile


ROOT = Path(__file__).resolve().parents[1]


def test_compose_backup_captures_only_dtvp_durable_state():
    compose = (ROOT / "compose.yml").read_text(encoding="utf-8")

    assert "dtvp-state-backup:" in compose
    assert "profiles:\n      - maintenance" in compose
    assert "./data:/state/dtvp:ro" in compose
    assert "network_mode: none" in compose
    assert "persistent-files.tar.gz" in compose
    assert "dependency-track" not in compose
    assert "postgres" not in compose
    backup_section = compose[
        compose.index("  dtvp-state-backup:") : compose.index(
            "  dtvp-archive-git-push:"
        )
    ]
    assert "agentyzer" not in backup_section


def test_backup_script_pauses_only_dtvp_and_verifies_archive():
    script_path = ROOT / "scripts" / "backup-compose-state.sh"
    script = script_path.read_text(encoding="utf-8")

    assert script_path.stat().st_mode & 0o100
    assert "for service in dtvp" in script
    assert "trap resume_writers EXIT HUP INT TERM" in script
    assert 'gzip -t "$snapshot_dir/persistent-files.tar.gz"' in script
    assert "sha256sum persistent-files.tar.gz" in script
    assert "backup_status.json" in script
    assert "Backup root must not be inside the DTVP data directory" in script
    assert "dependency-track" not in script
    assert "postgres" not in script
    assert "agentyzer" not in script
    assert "rm -rf" not in script


def test_compose_backup_scheduler_is_explicit_and_hardened():
    compose = (ROOT / "compose.yml").read_text(encoding="utf-8")
    dockerfile = (ROOT / "Dockerfile.backup").read_text(encoding="utf-8")

    assert "dtvp-backup-scheduler:" in compose
    assert "profiles:\n      - backup" in compose
    assert "Dockerfile.backup" in compose
    assert "DTVP_BACKUP_INTERVAL_SECONDS: ${DTVP_BACKUP_INTERVAL_SECONDS:-86400}" in compose
    assert "DTVP_DOCKER_SOCKET_PATH:-/var/run/docker.sock" in compose
    assert "./data:/app/data" in compose
    assert "stop_grace_period: 1m" in compose
    assert "read_only: true" in compose
    assert "cap_drop:" in compose
    assert "docker-cli" in dockerfile
    assert "ALPINE_IMAGE=alpine:" in dockerfile
    assert "POSTGRES_IMAGE" not in dockerfile


def test_container_backup_pauses_only_dtvp_and_updates_marker(tmp_path):
    backup_root = tmp_path / "backups"
    state_root = tmp_path / "state"
    data_root = tmp_path / "data"
    fake_bin = tmp_path / "bin"
    docker_log = tmp_path / "docker.log"
    lock_dir = tmp_path / "backup.lock"
    for directory in (
        backup_root,
        data_root,
        fake_bin,
        state_root / "dtvp",
        state_root / "agentyzer" / "cloned-repository" / ".git",
    ):
        directory.mkdir(parents=True, exist_ok=True)
    (state_root / "dtvp" / "settings.json").write_text("{}", encoding="utf-8")
    (state_root / "agentyzer" / "cloned-repository" / ".git" / "config").write_text(
        "throwaway clone metadata",
        encoding="utf-8",
    )
    fake_docker = fake_bin / "docker"
    fake_docker.write_text(
        """#!/bin/sh
printf '%s\\n' "$*" >> "$FAKE_DOCKER_LOG"
case "$1" in
  inspect)
    case "$*" in
      *com.docker.compose.project*) echo test-project ;;
      *State.Paused*) echo false ;;
    esac
    ;;
  ps)
    case "$*" in
      *service=dtvp*) echo dtvp-id ;;
    esac
    ;;
esac
""",
        encoding="utf-8",
    )
    fake_docker.chmod(0o755)

    script = ROOT / "scripts" / "backup-compose-state-container.sh"
    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{fake_bin}:{environment['PATH']}",
            "HOSTNAME": "scheduler-id",
            "FAKE_DOCKER_LOG": str(docker_log),
            "DTVP_BACKUP_ROOT": str(backup_root),
            "DTVP_BACKUP_STATE_ROOT": str(state_root),
            "DTVP_BACKUP_DTVP_DATA_ROOT": str(data_root),
            "DTVP_BACKUP_STATUS_PATH": str(data_root / "backup_status.json"),
            "DTVP_BACKUP_LOCK_DIR": str(lock_dir),
        }
    )

    result = subprocess.run(
        [str(script)],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    snapshots = list(backup_root.glob("dtvp-state-*"))
    assert len(snapshots) == 1
    assert (snapshots[0] / "persistent-files.tar.gz").is_file()
    assert (snapshots[0] / "SHA256SUMS").is_file()
    with tarfile.open(snapshots[0] / "persistent-files.tar.gz", "r:gz") as archive:
        members = archive.getnames()
    assert members
    assert all(name == "dtvp" or name.startswith("dtvp/") for name in members)
    assert (data_root / "backup_status.json").is_file()
    docker_calls = docker_log.read_text(encoding="utf-8")
    for container_id in ("dtvp-id",):
        assert f"pause {container_id}" in docker_calls
        assert f"unpause {container_id}" in docker_calls
    assert "agentyzer" not in docker_calls


def test_backup_scheduler_supports_a_single_immediate_run(tmp_path):
    invocation = tmp_path / "invoked"
    backup_command = tmp_path / "backup"
    backup_command.write_text(
        f"#!/bin/sh\nprintf complete > '{invocation}'\n",
        encoding="utf-8",
    )
    backup_command.chmod(0o755)

    result = subprocess.run(
        [str(ROOT / "scripts" / "run-backup-scheduler.sh")],
        cwd=ROOT,
        env={
            **os.environ,
            "DTVP_BACKUP_COMMAND": str(backup_command),
            "DTVP_BACKUP_INITIAL_DELAY_SECONDS": "0",
            "DTVP_BACKUP_INTERVAL_SECONDS": "300",
            "DTVP_BACKUP_RETRY_SECONDS": "60",
            "DTVP_BACKUP_SCHEDULER_ONCE": "true",
        },
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert invocation.read_text(encoding="utf-8") == "complete"
