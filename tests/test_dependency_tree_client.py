"""CLI renders the server's pinned tree; it never rebuilds dependency semantics."""

import json
import sys

import httpx
import respx

from dtvp.cli import main
from dtvp.knowledge.dependency_tree import dependency_tree
from tests.test_dependency_tree import graph


@respx.mock
def test_cli_resolves_version_once_and_renders_bounded_server_rows(monkeypatch, capsys):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    state = "a" * 64
    base = "http://tree.test/api/v1/projects/product"
    inventory = respx.get(base + "/versions/1.0/inventory").mock(
        return_value=httpx.Response(
            200, json={"state": "f" * 64, "reference_state": state, "projection_current": False}
        )
    )
    result = {**dependency_tree(graph(), max_depth=10), "state": state, "version": "1.0"}
    tree = respx.get(base + f"/states/{state}/dependency-tree").mock(
        return_value=httpx.Response(200, json=result)
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dtvp",
            "knowledge",
            "--url",
            "http://tree.test",
            "tree",
            "--project",
            "product",
            "--version",
            "1.0",
            "--depth",
            "10",
        ],
    )
    main()
    assert inventory.call_count == tree.call_count == 1
    assert tree.calls[0].request.url.params["max_depth"] == "10"
    output = capsys.readouterr().out
    assert "└─" in output and "cycle" in output and "shared" in output
    assert "2 vulnerabilities" in output and state in output


@respx.mock
def test_cli_exact_state_json_uses_only_one_tree_read(monkeypatch, capsys):
    monkeypatch.delenv("DTVP_API_TOKEN", raising=False)
    state = "b" * 64
    result = {**dependency_tree(graph(), root_ref="a"), "state": state, "version": "1.0"}
    route = respx.get(
        f"http://tree.test/api/v1/projects/product/states/{state}/dependency-tree"
    ).mock(return_value=httpx.Response(200, json=result))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dtvp",
            "knowledge",
            "--url",
            "http://tree.test",
            "--timeout",
            "300",
            "tree",
            "--project",
            "product",
            "--state",
            state,
            "--root",
            "a",
            "--json",
        ],
    )
    main()
    assert route.call_count == len(respx.calls) == 1
    assert route.calls[0].request.url.params["root_ref"] == "a"
    assert route.calls[0].request.extensions["timeout"]["read"] == 300
    assert json.loads(capsys.readouterr().out) == result
