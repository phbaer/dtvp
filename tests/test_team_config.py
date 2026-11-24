"""The team mapping organised by team (dtvp.team_config, ADR 0012): the
shared cases, conversion of the older selector format, loading, saving
through the settings API, team groups, and the backup round trip."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from dtvp import logic
from dtvp.team_config import (
    FORMAT_SELECTORS,
    FORMAT_TEAMS,
    is_team_format,
    selector_mapping,
    team_config_errors,
    team_config_from_document,
)
from dtvp.team_group_services import configured_team_names, validate_team_group_config

CASES = json.loads(
    (Path(__file__).parent / "fixtures" / "team_config_cases.json").read_text()
)["cases"]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_shared_cases(case):
    assert team_config_errors(case["document"]) == case["errors"]
    if "mapping" in case:
        assert selector_mapping(case["document"]) == case["mapping"]


def test_the_format_is_told_by_object_values_or_the_owner_of_star():
    assert is_team_format({"Unknown": "*"})
    assert is_team_format({"Core": {"components": ["x"]}})
    assert is_team_format({"Unknown": ["a", "*"]})
    assert not is_team_format({"*": "Unknown", "core": "Core"})
    assert not is_team_format({})
    # Selector files load as they are.
    old = {"core": ["Core", "DE-Core"], "*": "Unknown"}
    assert selector_mapping(old) is old


def test_converting_the_selector_format():
    old = {
        "vp-stats-app": "Core",
        "core-lib": ["Core", "DE-Core"],
        "VPStatsApp": "Phoenix",
        "project::eventserver": "Events",
        "libtiff": ["3P", "3rd Party"],
        "ffmpeg": ["3P", "Third"],
        "shared": ["Phoenix", "Platform"],
        "other": ["Events", "Platform", "Core"],
        "*": "Unknown",
    }
    config = team_config_from_document(old)
    assert config.source_format == FORMAT_SELECTORS
    assert config.document() == {
        "Core": {"aliases": ["DE-Core"], "components": ["vp-stats-app", "core-lib"]},
        "Phoenix": {"aliases": ["Platform"], "components": ["VPStatsApp", "shared"]},
        "Events": {"projects": ["eventserver"], "components": ["other"]},
        "3P": {"aliases": ["3rd Party", "Third"], "components": ["libtiff", "ffmpeg"]},
        "Unknown": {"components": ["*"]},
    }
    assert config.warnings == [
        "Alias 'Platform' is listed for teams 'Phoenix' and 'Events'; kept for 'Phoenix'",
        "Alias 'Core' of team 'Events' is the name of team 'Core'; dropped from 'Events'",
    ]
    # The converted document is valid and resolves as before.
    assert team_config_errors(config.document()) == []
    converted = selector_mapping(config.document())
    for key in ("vp-stats-app", "VPStatsApp", "libtiff", "*"):
        assert converted[key][0] if isinstance(converted[key], list) else converted[key]
    assert converted["project::eventserver"] == "Events"


def test_a_team_document_is_read_as_it_is():
    config = team_config_from_document({"Core": ["a"], "Unknown": "*"})
    assert config.source_format == FORMAT_TEAMS
    assert config.warnings == []


def test_load_team_mapping_flattens_a_team_file(tmp_path):
    path = tmp_path / "team_mapping.json"
    path.write_text(json.dumps({"Core": {"aliases": ["DE"], "projects": ["P"], "components": ["x"]}, "Unknown": "*"}))
    assert logic.load_team_mapping(str(path)) == {
        "x": ["Core", "DE"],
        "project::P": ["Core", "DE"],
        "*": "Unknown",
    }
    assert logic.load_team_mapping_document(str(path))["Unknown"] == "*"


def test_team_groups_know_teams_of_a_team_file_even_without_selectors():
    document = {"Core": {"aliases": ["DE-Core"], "components": ["x"]}, "Ops": {}, "Unknown": "*"}
    assert configured_team_names(document) == ["Core", "Ops", "Unknown"]
    assert validate_team_group_config(
        {"All": {"teams": ["DE-Core", "Ops"], "groups": []}}, document
    ) == []


# -- the settings API ------------------------------------------------------


@pytest.fixture
def reviewer(tmp_path):
    from dtvp import main

    target = tmp_path / "team_mapping.json"
    main.app.dependency_overrides[main.get_current_user] = lambda: "reviewer"
    with patch("dtvp.main.get_team_mapping_path", return_value=str(target)), patch(
        "dtvp.logic.get_team_mapping_path", return_value=str(target)
    ), patch("dtvp.main.get_user_role", return_value="REVIEWER"):
        yield target
    main.app.dependency_overrides = {}


def test_saving_the_selector_format_writes_the_team_format(client, reviewer):
    response = client.put(
        "/api/settings/mapping",
        json={"vp-stats-app": "Core", "core-lib": ["Core", "DE-Core"], "*": "Unknown"},
    )
    assert response.json()["status"] == "success"
    assert json.loads(reviewer.read_text()) == {
        "Core": {"aliases": ["DE-Core"], "components": ["vp-stats-app", "core-lib"]},
        "Unknown": {"components": ["*"]},
    }
    # Readers of the selector mapping see the same ownership.
    assert client.get("/api/settings/mapping").json() == {
        "vp-stats-app": ["Core", "DE-Core"],
        "core-lib": ["Core", "DE-Core"],
        "*": "Unknown",
    }
    teams = client.get("/api/settings/mapping/teams").json()
    assert teams["format"] == "teams"
    assert teams["teams"]["Unknown"] == {"components": ["*"]}


def test_the_teams_view_converts_a_selector_file(client, reviewer):
    reviewer.write_text(json.dumps({"a": ["Core", "X"], "b": ["Ops", "X"]}))
    teams = client.get("/api/settings/mapping/teams").json()
    assert teams["format"] == "selectors"
    assert teams["teams"] == {
        "Core": {"aliases": ["X"], "components": ["a"]},
        "Ops": {"components": ["b"]},
    }
    assert teams["warnings"] == ["Alias 'X' is listed for teams 'Core' and 'Ops'; kept for 'Core'"]


def test_saving_a_team_document_with_errors_is_refused(client, reviewer):
    response = client.put(
        "/api/settings/mapping",
        json={"A": {"components": ["lib", "*"]}, "B": {"components": ["lib"], "aliases": ["A"]}},
    )
    body = response.json()
    assert body["status"] == "error"
    assert "Selector 'lib' is listed under teams 'A' and 'B'" in body["message"]
    assert "Alias 'A' of team 'B' is the name of team 'A'" in body["message"]
    assert not reviewer.exists()


def test_uploading_a_mapping_converts_it(client, reviewer):
    files = {"file": ("m.json", json.dumps({"x": "Core"}).encode(), "application/json")}
    assert client.post("/api/settings/mapping", files=files).json()["status"] == "success"
    assert json.loads(reviewer.read_text()) == {"Core": {"components": ["x"]}}
    bad = {"file": ("m.json", b"{nope", "application/json")}
    assert client.post("/api/settings/mapping", files=bad).json() == {
        "status": "error",
        "message": "Invalid JSON",
    }


# -- backup ----------------------------------------------------------------


def test_backup_round_trip_keeps_the_team_file_and_old_dumps_convert(tmp_path, monkeypatch):
    from dtvp.backup.export import export_dump
    from dtvp.backup.restore import restore_dump
    from dtvp.instance_stores import resolve_instance_stores, write_instance_registry
    from tests.backup_instance import configure_instance, populate

    team_file = json.dumps(
        {"Core": {"aliases": ["DE-Core"], "projects": ["P"], "components": ["lib-1"]}, "Unknown": "*"},
        indent=2,
    ).encode()
    source = configure_instance(monkeypatch, tmp_path / "source")
    populate(source)
    (source.root / "data" / "team_mapping.json").write_bytes(team_file)
    dump = export_dump().path

    target = configure_instance(monkeypatch, tmp_path / "target")
    write_instance_registry(resolve_instance_stores())
    restore_dump(dump)
    assert (target.root / "data" / "team_mapping.json").read_bytes() == team_file
    assert logic.load_team_mapping()["project::P"] == ["Core", "DE-Core"]

    # A dump of the selector format (populate writes one) restores as it
    # was and is read the same way.
    old_source = configure_instance(monkeypatch, tmp_path / "old")
    populate(old_source)
    old_dump = export_dump().path
    old_target = configure_instance(monkeypatch, tmp_path / "old-target")
    write_instance_registry(resolve_instance_stores())
    restore_dump(old_dump)
    assert (old_target.root / "data" / "team_mapping.json").read_bytes() == b'{"lib-1": "Core"}\n'
    assert logic.load_team_mapping() == {"lib-1": "Core"}
    assert team_config_from_document(logic.load_team_mapping_document()).document() == {
        "Core": {"components": ["lib-1"]}
    }


def test_statistics_resolve_team_groups_and_aliases_from_the_team_document():
    """A team group naming a team without any entry (only aliases, or
    nothing yet) resolves, and its aliases count: the team list comes from
    the team document, not from the selector mapping."""
    import logging
    from types import SimpleNamespace

    from dtvp.general_api_routes import _task_group_query_context

    document = {
        "Core": {"aliases": ["DE-Core"], "components": ["core"]},
        "Events": {"projects": ["eventserver"]},
        "Newcomers": {"aliases": ["Old-Newcomers"]},
        "Unknown": "*",
    }
    groups = {"Product": {"teams": ["Core", "Events", "Newcomers"], "groups": []}}
    deps = SimpleNamespace(
        logger=logging.getLogger("test"),
        code_analysis_result_store=None,
        load_team_mapping=lambda: selector_mapping(document),
        load_team_groups=lambda: groups,
        load_team_mapping_document=lambda: document,
    )
    _index, context = _task_group_query_context(deps, {"result": []})
    assert context["team_groups"]["Product"] == ["Core", "Events", "Newcomers"]
    assert context["team_aliases"]["old-newcomers"] == "Newcomers"
    assert context["team_aliases"]["de-core"] == "Core"

    # From the selector mapping alone, Newcomers is unknown and the group
    # configuration is ignored.
    without = SimpleNamespace(**{**vars(deps), "load_team_mapping_document": None})
    _index, context = _task_group_query_context(without, {"result": []})
    assert context["team_groups"] == {}
