"""Optional actual isolated Generator parser, with source-pinned mocked transport."""

import base64
import json
import os
import subprocess
from pathlib import Path

import pytest

from dtvp.knowledge.issued_exports import issue_export
from dtvp.knowledge.journal import Ref, Update
from dtvp.storage import digest
from tests.test_knowledge_vscorer import prepare
from tests.test_knowledge_workspace import workspace as source_workspace

workspace = source_workspace
PROVENANCE = Path(__file__).parent / "fixtures/specialist_contracts/generator-qualified-source.json"

PARSER = r"""
import base64, json, sys
from pathlib import Path
source_root, request_file = sys.argv[1:]
sys.path.insert(0, source_root)
try:
    import src.architecture.knowledge_source as module
except ModuleNotFoundError as error:
    print(json.dumps({"unavailable": True, "dependency": error.name}))
    raise SystemExit(0)
import requests
def no_network(*args, **kwargs):
    raise AssertionError("Consumer contract test forbids live HTTP")
requests.sessions.Session.request = no_network
request = json.loads(Path(request_file).read_bytes())
issued = request["issued"]
files = {name: base64.b64decode(raw) for name, raw in request["files"].items()}
if request["change"] == "bytes":
    files["bundle.json"] += b" "
if request["change"] == "scope":
    issued["project_id"] = "other-product"
root = "/projects/" + request["project"]
reads = []
class Client:
    def __init__(self, url, token):
        assert url == "https://mock-dtvp.invalid" and token == "synthetic-mock-token"
    def post(self, path, *, raw=False, api_version=None):
        assert path == root + "/states/" + request["state"] + "/exports/bundle"
        assert raw and api_version == "v3"
        reads.append(path)
        return json.dumps(issued,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    def get(self, path, *, raw=False, api_version=None):
        prefix = root + "/issued-exports/" + issued["receipt_sha256"] + "/files/"
        assert path.startswith(prefix) and raw and api_version == "v3"
        name = path[len(prefix):]
        assert name in ("receipt.json","bundle.json","manifest.json")
        reads.append(path)
        return files[name]
module.DTVPClient = Client
try:
    inventory = module.KnowledgeSource("https://mock-dtvp.invalid", "synthetic-mock-token", request["project"], request["state"], "Synthetic contract", request["version"]).load()
except ValueError as error:
    print(json.dumps({"accepted":False,"error_type":type(error).__name__}))
else:
    print(json.dumps({"accepted":True,"read_count":len(reads),"inventory_present":bool(inventory.state),"pipeline_context_present":"dtvp_pipeline_context" in inventory.state}))
"""


def test_generator_provenance_distinguishes_default_from_unmerged_native_adapter():
    provenance = json.loads(PROVENANCE.read_bytes())
    assert provenance["format"] == "dtvp.generator-qualified-mock-contract/1"
    assert provenance["default_checkout_at_review"]["native_mode"] == "not_available"
    assert provenance["qualified_adapter"]["branch"] == "feat/dtvp-snapshot-integrity"
    assert provenance["qualified_adapter"]["commit"].startswith("da3cba0")


@pytest.mark.parametrize("change", [None, "bytes", "scope"])
def test_optional_actual_generator_parser_consumes_issued_bytes_only(workspace, tmp_path, change):
    source = os.getenv("DTVP_GENERATOR_CONTRACT_ROOT")
    if not source:
        pytest.skip("Set DTVP_GENERATOR_CONTRACT_ROOT to the qualified isolated native adapter")
    root = Path(source).resolve()
    provenance = json.loads(PROVENANCE.read_bytes())["qualified_adapter"]
    for item in provenance["source_files"]:
        assert digest((root / item["path"]).read_bytes()) == item["sha256"], (
            f"Generator {item['path']} changed; review its contract explicitly"
        )
    python = Path(os.getenv("DTVP_GENERATOR_CONTRACT_PYTHON", str(root / ".venv/bin/python")))
    if not python.is_file():
        pytest.skip(
            "Qualified Generator environment unavailable; no install or sibling write attempted"
        )
    journal, state, _ = prepare(workspace)
    journal.publish(
        request_id="generator-source",
        fingerprint=state,
        updates=[Update(ref=Ref(project_id="product", name="1"), expected=None, target=state)],
    )
    captured = issue_export(
        journal, project_id="product", actor_id="operator", state=state, kind="knowledge-bundle"
    )
    payload = {
        "project": "product",
        "state": state,
        "version": "1",
        "change": change,
        "issued": captured,
        "files": {
            name: base64.b64encode(journal.objects.read(metadata["sha256"])).decode()
            for name, metadata in captured["files"].items()
        },
    }
    request_file = tmp_path / "issued-request.json"
    request_file.write_text(json.dumps(payload))
    before = journal.references()
    result = subprocess.run(
        [str(python), "-B", "-c", PARSER, str(root), str(request_file)],
        cwd=tmp_path,
        env={"PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    if report.get("unavailable"):
        pytest.skip("Qualified Generator dependency environment unavailable; no installation attempted")
    assert report["accepted"] is (change is None), report
    if change is None:
        assert (
            report["read_count"] == 4
            and report["inventory_present"]
            and report["pipeline_context_present"]
        )
    assert journal.references() == before
