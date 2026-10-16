"""The local operator playground requires no IdP, provider key or network access."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from dtvp.knowledge.cpe_catalog import Catalog, demo_catalog
from dtvp.knowledge.cpe_sources import dictionary
from dtvp.storage import canonical

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "cpe_catalog.py"


def command(root, *arguments):
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def test_offline_demo_cli_search_export_verify_and_rebuild_are_reproducible(tmp_path):
    root = tmp_path / "catalog"
    demo = command(root, "demo")
    assert demo["synthetic"] and "Synthetic" in demo["source"]
    assert demo["assurance"] == "synthetic_META_consistent_complete_archive"
    page = command(root, "search", "demo")
    assert page["synthetic"] and page["total"] == 2
    output = tmp_path / "candidate-dictionary.json"
    exported = command(root, "export", "demo", "--output", str(output), "--limit", "1")
    assert exported["capture"]["synthetic"]
    records, _ = dictionary(output.read_bytes(), "ignored-default")
    assert records[0]["source"].startswith("synthetic-catalog:")
    assert records[0]["publisher"] == "Synthetic demonstration"
    assert command(root, "verify")["verified"]
    (root / "indexes" / (demo["generation"] + ".sqlite")).unlink()
    assert command(root, "rebuild")["index_rebuilt"]
    assert command(root, "search", "demo", "--include-deprecated")["total"] == 3
    assert not (tmp_path / "knowledge").exists()
    with pytest.raises(ValueError, match="empty catalog"):
        demo_catalog(root)
    assert Catalog(root).current() == demo["generation"]


def test_synthetic_marker_survives_raw_capture_reconstruction(tmp_path):
    catalog = Catalog(tmp_path / "catalog")
    generation = demo_catalog(catalog.root)["generation"]
    assert catalog.verify(generation, rebuild=True)["verified"]
    result = catalog.export("demo", generation=generation)
    assert all(item["publisher"] == "Synthetic demonstration" for item in result["dictionary"])
    assert json.loads(canonical(result["capture"]))["synthetic"]
