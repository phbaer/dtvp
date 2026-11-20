"""Settings files are validated first and written atomically."""

import json
import os
import stat

import pytest

from dtvp import file_io_services, tmrescore_cache_services
from dtvp.settings_files import (
    SETTINGS_FILE_NAMES,
    SETTINGS_FILES,
    SettingsValidationError,
    validate_settings_document,
    write_settings_file,
)

VALID_RESCORE_RULES = {
    "metric_rules": {
        "3.1": {
            "undefined_values": ["X"],
            "base_metrics": ["AV"],
            "metric_order": ["AV", "MAV"],
            "relationships": [{"base": "AV", "modified": "MAV"}],
        }
    },
    "transitions": [],
}


@pytest.fixture
def settings_paths(tmp_path, monkeypatch):
    directory = tmp_path / "settings"
    directory.mkdir()
    paths = {
        "team_mapping": ("TEAM_MAPPING_PATH", directory / "team_mapping.json"),
        "team_groups": ("TEAM_GROUPS_PATH", directory / "team_groups.json"),
        "user_roles": ("USER_ROLES_PATH", directory / "user_roles.json"),
        "rescore_rules": ("RESCORE_RULES_PATH", directory / "rescore_rules.json"),
        "auto_analysis_guidance": (
            "DTVP_AUTO_ANALYSIS_GUIDANCE_PATH",
            directory / "auto_analysis_guidance.json",
        ),
    }
    for variable, path in paths.values():
        monkeypatch.setenv(variable, str(path))
    return {name: path for name, (_variable, path) in paths.items()}


def test_registry_lists_every_settings_file_in_order(settings_paths):
    assert SETTINGS_FILE_NAMES == (
        "team_mapping",
        "team_groups",
        "user_roles",
        "rescore_rules",
        "auto_analysis_guidance",
    )
    for item in SETTINGS_FILES:
        assert item.path() == str(settings_paths[item.name])


@pytest.mark.parametrize(
    "name, valid, invalid, message",
    [
        ("team_mapping", {"lib": "Core"}, ["lib"], "Team mapping must be a JSON object"),
        (
            "team_groups",
            {"Core": {"teams": ["Core"], "groups": []}},
            {"Core": {"teams": ["Unknown"], "groups": []}},
            "unknown configured team Unknown",
        ),
        ("user_roles", {"alice": "REVIEWER"}, {"alice": ["REVIEWER"]}, "must be a string"),
        ("rescore_rules", VALID_RESCORE_RULES, {"transitions": []}, "metric_rules"),
        (
            "auto_analysis_guidance",
            {"components": {}},
            "text",
            "Auto-analysis guidance JSON must be an object",
        ),
    ],
)
def test_each_validator(settings_paths, name, valid, invalid, message):
    context = {"team_mapping": {"core": "Core"}}
    assert validate_settings_document(name, valid, context) == []
    errors = validate_settings_document(name, invalid, context)
    assert any(message in error for error in errors), errors

    target = settings_paths[name]
    target.write_bytes(b'{"previous": "x"}')
    with pytest.raises(SettingsValidationError) as raised:
        write_settings_file(name, payload=invalid, context=context)
    assert message in str(raised.value)
    assert target.read_bytes() == b'{"previous": "x"}'

    assert write_settings_file(name, payload=valid, context=context) == str(target)
    assert target.read_bytes() == json.dumps(valid, indent=2).encode()


def test_content_is_kept_byte_for_byte(settings_paths):
    content = b'{\n    "alice":   "REVIEWER"\n}\n'
    write_settings_file("user_roles", content=content)
    assert settings_paths["user_roles"].read_bytes() == content


def test_invalid_json_is_rejected_before_any_write(settings_paths):
    target = settings_paths["team_mapping"]
    target.write_bytes(b"{}")
    with pytest.raises(SettingsValidationError, match="Invalid JSON"):
        write_settings_file("team_mapping", content=b"{nope")
    assert target.read_bytes() == b"{}"


def test_failed_write_leaves_old_file_and_no_temp_file(settings_paths, monkeypatch):
    target = settings_paths["user_roles"]
    target.write_bytes(b'{"alice": "REVIEWER"}')
    before = target.read_bytes()

    def broken_replace(*_args, **_kwargs):
        raise OSError("disk gone")

    monkeypatch.setattr(os, "replace", broken_replace)
    with pytest.raises(OSError, match="disk gone"):
        write_settings_file("user_roles", payload={"bob": "ANALYST"})
    assert target.read_bytes() == before
    assert sorted(path.name for path in target.parent.iterdir()) == ["user_roles.json"]


def test_atomic_write_keeps_mode_of_existing_file_and_sets_given_mode(tmp_path):
    target = tmp_path / "file.json"
    target.write_bytes(b"old")
    os.chmod(target, 0o640)
    file_io_services.atomic_write_bytes(str(target), b"new")
    assert target.read_bytes() == b"new"
    assert stat.S_IMODE(target.stat().st_mode) == 0o640

    file_io_services.atomic_write_bytes(str(target), b"newer", mode=0o600)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600

    fresh = tmp_path / "sub" / "fresh.json"
    file_io_services.atomic_write_bytes(str(fresh), b"x")
    assert stat.S_IMODE(fresh.stat().st_mode) == file_io_services.DEFAULT_FILE_MODE


def test_write_and_validate_json_bytes_validates_first(tmp_path):
    target = tmp_path / "file.json"
    with pytest.raises(ValueError):
        file_io_services.write_and_validate_json_bytes(str(target), b"{nope")
    assert not target.exists()
    file_io_services.write_and_validate_json_bytes(str(target), b'{"a": 1}')
    assert target.read_bytes() == b'{"a": 1}'


def test_write_json_format_is_unchanged(tmp_path):
    target = tmp_path / "file.json"
    file_io_services.write_json(str(target), {"b": 1, "a": "ü"})
    assert target.read_text() == json.dumps({"b": 1, "a": "ü"}, indent=2)


def test_tmrescore_cache_is_written_atomically(tmp_path, monkeypatch):
    target = tmp_path / "proposals" / "tmrescore_proposals.json"
    monkeypatch.setenv("DTVP_TMRESCORE_CACHE_PATH", str(target))
    cache = {"b": {"x": 1}, "a": {"y": [1, 2]}}
    tmrescore_cache_services.save_tmrescore_project_cache(cache)
    assert target.read_bytes() == json.dumps(cache, indent=2, sort_keys=True).encode()
    assert tmrescore_cache_services.serialize_tmrescore_cache(cache) == target.read_bytes()

    monkeypatch.setattr(
        os, "replace", lambda *_a, **_k: (_ for _ in ()).throw(OSError("full"))
    )
    with pytest.raises(OSError):
        tmrescore_cache_services.save_tmrescore_project_cache({"c": {}})
    assert json.loads(target.read_bytes()) == cache
    assert [path.name for path in target.parent.iterdir()] == [target.name]
