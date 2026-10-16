"""Manual fixture producer; run against exact archived old source, never during tests."""

import argparse
import hashlib
import json
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import dtvp
import dtvp.knowledge.issued_exports as issued_module
import dtvp.knowledge.journal as journal_module
import dtvp.knowledge.metadata as metadata_module
from dtvp.knowledge.agentyzer import derive_analysis_input
from dtvp.knowledge.issued_exports import issue_export
from dtvp.knowledge.journal import Journal
from dtvp.knowledge.metadata import MetadataInput, save_metadata
from dtvp.knowledge.service import import_inventory
from dtvp.knowledge.vscorer import derive_context_inputs
from dtvp.knowledge.workspace import load_workspace
from dtvp.storage import canonical, digest

PROJECT = "serializer-compat-product"
VERSION = "7.1.1"
BASE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


class FixedDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 10, 16, 0, 0, 0, tzinfo=UTC)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    root = args.source_root.resolve()
    if Path(dtvp.__file__).resolve().parent != root / "dtvp":
        raise RuntimeError("Fixture producer imported a different checkout")
    if args.work.exists() or args.output.exists():
        raise RuntimeError("Refuse to overwrite a fixture or production journal")
    journal_module.datetime = issued_module.datetime = metadata_module.datetime = FixedDateTime
    journal = Journal(args.work)
    bom = json.loads((root / "playground/fixtures/release.cdx.json").read_bytes())
    state = (
        import_inventory(
            journal,
            project_id=PROJECT,
            version=VERSION,
            actor_id="synthetic-pipeline",
            request_id="compat-import",
            expected=None,
            source="synthetic-source",
            build_number=1,
            occurred_at="2026-10-16T00:00:00Z",
            sbom=bom,
            context={
                "analysis_source": {"repository_name": "synthetic-app", "source_commit": "a" * 40},
                "subject_kind": "build",
                "subject_digest": "sha256:" + "f" * 64,
                "pipeline_run": "synthetic-compat-build",
            },
        )[1]
        .updates[0]
        .target
    )
    state = (
        save_metadata(
            journal,
            project_id=PROJECT,
            version=VERSION,
            actor_id="synthetic-maintainer",
            data=MetadataInput(
                request_id="compat-metadata",
                expected=state,
                expected_revision=None,
                component_ref="http",
                annotations={
                    "support": {
                        "status": "supported",
                        "supplier": "Synthetic maintainer",
                        "support_until": "2028-12-31",
                    }
                },
                provenance={
                    "source": "Synthetic fixture",
                    "reference": "FIXTURE-ONLY",
                    "observed_at": "2026-10-16T00:00:00Z",
                },
                rationale="Synthetic authored support; not supplier verification or human approval",
            ),
        )[1]
        .updates[0]
        .target
    )
    row = next(
        item
        for item in load_workspace(journal, state)["items"]
        if item["context"]["component_ref"] == "http"
        and item["vulnerability_id"] == "CVE-2099-20001"
    )
    agentyzer_selector = {
        "context_id": row["context_id"],
        "vulnerability_id": row["vulnerability_id"],
    }
    vscorer_selector = {
        "context_id": row["context_id"],
        "component_ref": "http",
        "base_selections": {row["vulnerability_id"]: BASE},
    }
    captures = []
    for kind, payload, selector in (
        ("knowledge-bundle", None, {}),
        (
            "vscorer-input",
            derive_context_inputs(
                journal, state, row["context_id"], "http", vscorer_selector["base_selections"]
            ),
            vscorer_selector,
        ),
        (
            "agentyzer-input",
            derive_analysis_input(journal, state, **agentyzer_selector),
            agentyzer_selector,
        ),
    ):
        captures.append(
            issue_export(
                journal,
                project_id=PROJECT,
                actor_id="synthetic-consumer",
                state=state,
                kind=kind,
                payload=payload,
                selector=selector,
            )
        )
    expected = {"project_id": PROJECT, "version": VERSION, "state": state, "captures": captures}
    files = {
        str(path.relative_to(args.work)): path.read_bytes()
        for path in args.work.rglob("*")
        if path.is_file() and not path.name.endswith(".lock")
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, raw in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 10, 16, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, raw)
    args.output.with_suffix(".expected.json").write_bytes(canonical(expected))
    provenance = {
        "synthetic": True,
        "source_commit": args.commit,
        "source_root_package": "dtvp",
        "clock": "2026-10-16T00:00:00+00:00",
        "clock_modules": ["knowledge.journal", "knowledge.issued_exports", "knowledge.metadata"],
        "python_version": sys.version.split()[0],
        "archive_sha256": digest(args.output.read_bytes()),
        "expected_sha256": digest(canonical(expected)),
        "members": {
            name: {"sha256": digest(raw), "bytes": len(raw)} for name, raw in sorted(files.items())
        },
        "producer_sources": {
            name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in (
                "dtvp/knowledge/issued_exports.py",
                "dtvp/knowledge/exports.py",
                "dtvp/knowledge/vscorer.py",
                "dtvp/knowledge/agentyzer.py",
                "uv.lock",
            )
        },
        "limitations": [
            "Synthetic source only; no operational data, credentials or current human approvals.",
            "Generated by exact older source; fixture production freezes clocks only, not serializers.",
            "Reconstructed in the current Python environment, not a historical production capture or complete old-runtime qualification.",
            "Byte compatibility is not renderer, supplier or regulatory acceptance.",
        ],
    }
    args.output.with_suffix(".provenance.json").write_bytes(canonical(provenance))
    print(
        json.dumps(
            {
                "archive": args.output.name,
                "sha256": provenance["archive_sha256"],
                "members": len(files),
                "captures": len(captures),
            }
        )
    )


if __name__ == "__main__":
    main()
