from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_compose_backup_captures_every_persistent_application_volume():
    compose = (ROOT / "compose.yml").read_text(encoding="utf-8")

    assert "dtvp-state-backup:" in compose
    assert "profiles:\n      - maintenance" in compose
    assert "./data:/state/dtvp:ro" in compose
    assert "agentyzer-repos:/state/agentyzer:ro" in compose
    assert "dependency-track-data:/state/dependency-track:ro" in compose
    assert "network_mode: none" in compose
    assert "persistent-files.tar.gz" in compose


def test_backup_script_pauses_writers_and_verifies_both_artifacts():
    script_path = ROOT / "scripts" / "backup-compose-state.sh"
    script = script_path.read_text(encoding="utf-8")

    assert script_path.stat().st_mode & 0o100
    assert "for service in dtvp agentyzer dtrack-apiserver" in script
    assert "trap resume_writers EXIT HUP INT TERM" in script
    assert "pg_dump --username=dtrack --dbname=dtrack --format=custom" in script
    assert "pg_restore --list" in script
    assert 'gzip -t "$snapshot_dir/persistent-files.tar.gz"' in script
    assert "sha256sum dependency-track.pgdump persistent-files.tar.gz" in script
    assert "backup_status.json" in script
    assert "Backup root must not be inside the DTVP data directory" in script
    assert "rm -rf" not in script
