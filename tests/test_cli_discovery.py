"""Basic discovery and main/advanced command compatibility."""

import json
import sys

import httpx
import pytest
import respx

from dtvp.cli import main


def invoke(monkeypatch, *arguments):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    monkeypatch.setattr(sys, "argv", ["dtvp", "knowledge", "--url", "http://dtvp.test", *arguments])
    main()


@respx.mock
def test_projects_discovery_search_and_pagination(monkeypatch, capsys):
    route = respx.get("http://dtvp.test/api/v1/catalog/projects").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {
                        "id": "project-id",
                        "name": "Medical Product",
                        "workspace": "Platform",
                        "version_count": 4,
                    }
                ],
                "next_cursor": "next-page",
            },
        )
    )
    # Discovery must remain HTTP-only, with no local database configuration.
    monkeypatch.setattr("dtvp.cli.Settings", lambda: pytest.fail("Local settings accessed"))
    invoke(monkeypatch, "projects", "--q", "Medical", "--workspace", "team-id", "--limit", "1")
    assert dict(route.calls[0].request.url.params) == {
        "q": "Medical",
        "workspace_id": "team-id",
        "cursor": "",
        "limit": "1",
    }
    output = capsys.readouterr().out
    assert "project-id  Medical Product  team=Platform  versions=4" in output
    assert "Next cursor: next-page" in output


@respx.mock
def test_versions_preserve_branch_and_release_tag_distinction(monkeypatch, capsys):
    result = {
        "items": [
            {"name": "7.1.2", "kind": "branch", "version": "7.1.2", "state": "a" * 64},
            {"name": "release-7.1.1", "kind": "tag", "version": "7.1.1", "state": "b" * 64},
        ],
        "next_offset": 2,
    }
    route = respx.get("http://dtvp.test/api/v1/projects/project/refs").mock(
        return_value=httpx.Response(200, json=result)
    )
    invoke(monkeypatch, "versions", "--project", "project", "--limit", "2")
    output = capsys.readouterr().out
    assert "7.1.2  branch" in output and "release-7.1.1  tag" in output
    assert "Next offset: 2" in output
    assert route.calls[0].request.url.params["limit"] == "2"
    invoke(monkeypatch, "versions", "--project", "project", "--json")
    assert json.loads(capsys.readouterr().out) == result


@respx.mock
def test_teams_and_empty_discovery(monkeypatch, capsys):
    route = respx.get("http://dtvp.test/api/v1/workspaces").mock(
        return_value=httpx.Response(200, json=[{"id": "team-id", "name": "Platform"}])
    )
    invoke(monkeypatch, "teams")
    assert "team-id  Platform" in capsys.readouterr().out
    route.return_value = httpx.Response(200, json=[])
    invoke(monkeypatch, "teams")
    assert capsys.readouterr().out.strip() == "No results."


@pytest.mark.parametrize("prefix", [[], ["advanced"]])
@respx.mock
def test_advanced_commands_keep_existing_scripts_working(monkeypatch, capsys, prefix):
    respx.get("http://dtvp.test/api/v1/projects").mock(
        return_value=httpx.Response(200, json=[{"id": "project"}])
    )
    invoke(monkeypatch, *prefix, "request", "GET", "/api/v1/projects")
    assert json.loads(capsys.readouterr().out) == [{"id": "project"}]


@pytest.mark.parametrize("prefix", [[], ["advanced"]])
def test_help_separates_main_and_advanced_commands(monkeypatch, capsys, prefix):
    with pytest.raises(SystemExit) as error:
        invoke(monkeypatch, *prefix, "--help")
    assert error.value.code == 0
    output = capsys.readouterr().out
    if prefix:
        assert "advanced commands:" in output and "legacy-archive-preview" in output
        assert "projects " not in output
    else:
        assert "main commands:" in output and "projects " in output
        assert "legacy-archive-preview" not in output
        assert "pipeline-config" not in output
