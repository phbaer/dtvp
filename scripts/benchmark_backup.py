#!/usr/bin/env python3
"""Reproducible benchmark of the instance dump with synthetic data.

Builds an instance with the synthetic assessments of
``benchmark_assessment_store.py`` (adopted on import, so their history keeps
the text in the record), then measures the export, the dump size, verify,
and a restore into an empty instance with its phases: staging (records,
compaction, the read into fields), the round-trip proof and the swap.
Everything happens in a temporary directory.
"""

import argparse
import json
import os
import platform
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))
SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from benchmark_assessment_store import remote_batch  # noqa: E402

from dtvp.assessment_outbox_services import AssessmentOutboxStore  # noqa: E402
from dtvp.backup import restore as restore_module  # noqa: E402
from dtvp.backup.export import export_dump  # noqa: E402
from dtvp.backup.restore import RestoreOptions, restore_dump  # noqa: E402
from dtvp.backup.verify import verify_dump  # noqa: E402
from dtvp.instance_stores import resolve_instance_stores, write_instance_registry  # noqa: E402

SCHEMA_VERSION = "dtvp.backup-benchmark/v1"


def configure(root: Path) -> None:
    data = root / "data"
    (data / "dt_cache").mkdir(parents=True, exist_ok=True)
    for name in ("DTVP_DATABASE_PATH", "DTVP_ASSESSMENT_OUTBOX_PATH", "DTVP_ACCESS_TOKENS_PATH"):
        os.environ.pop(name, None)
    os.environ.update(
        {
            "DTVP_DT_CACHE_PATH": str(data / "dt_cache"),
            "DTVP_CODE_ANALYSIS_RESULTS_PATH": str(data / "code_analysis_results.sqlite"),
            "DTVP_TMRESCORE_CACHE_PATH": str(data / "tmrescore_proposals.json"),
            "DTVP_GROUPED_VULN_SUMMARY_INDEX_PATH": str(data / "grouped_vuln_summary_index.sqlite"),
            "DTVP_SSVC_CACHE_PATH": str(data / "dt_cache" / "ssvc_enrichment.sqlite3"),
            "TEAM_MAPPING_PATH": str(data / "team_mapping.json"),
            "TEAM_GROUPS_PATH": str(data / "team_groups.json"),
            "USER_ROLES_PATH": str(data / "user_roles.json"),
            "RESCORE_RULES_PATH": str(data / "rescore_rules.json"),
            "DTVP_AUTO_ANALYSIS_GUIDANCE_PATH": str(data / "auto_analysis_guidance.json"),
            "DTVP_BACKUP_PATH": str(root / "backups"),
            "DTVP_DT_API_URL": "http://localhost:8081",
        }
    )


@contextmanager
def phase_timer(phases: dict[str, float], name: str, owner: Any, attribute: str):
    original = getattr(owner, attribute)

    def timed(*args, **kwargs):
        started = time.perf_counter()
        try:
            return original(*args, **kwargs)
        finally:
            phases[name] = phases.get(name, 0.0) + time.perf_counter() - started

    setattr(owner, attribute, timed)
    try:
        yield
    finally:
        setattr(owner, attribute, original)


def run(count: int, per_project: int, size: int, directory: str) -> dict[str, Any]:
    source = Path(directory) / "source"
    configure(source)
    store = AssessmentOutboxStore(str(source / "data" / "dt_cache" / "dtvp.sqlite3"))
    later = lambda: datetime.now(UTC) + timedelta(seconds=5)  # noqa: E731
    for start in range(0, count, per_project):
        batch = remote_batch(start, min(per_project, count - start), per_project, size)
        store.reconcile_remote(batch, fetched_at=later())
    del store
    database = source / "data" / "dt_cache" / "dtvp.sqlite3"
    database_mib = os.path.getsize(database) / 2**20

    exported = export_dump()
    started = time.perf_counter()
    verified = verify_dump(exported.path)
    verify_seconds = time.perf_counter() - started
    assert verified.ok, verified.errors

    target = Path(directory) / "target"
    configure(target)
    write_instance_registry(resolve_instance_stores())
    phases: dict[str, float] = {}
    with (
        phase_timer(phases, "staging", restore_module, "_stage"),
        phase_timer(phases, "fields", AssessmentOutboxStore, "rebuild_derived_fields"),
        phase_timer(phases, "round_trip_proof", restore_module, "prove_round_trip"),
        phase_timer(phases, "swap", restore_module, "_forward"),
    ):
        started = time.perf_counter()
        result = restore_dump(exported.path, options=RestoreOptions())
        restore_seconds = time.perf_counter() - started
    assert result.ok
    restored_mib = os.path.getsize(target / "data" / "dt_cache" / "dtvp.sqlite3") / 2**20
    return {
        "assessments": count,
        "text_size": size,
        "database_mib": round(database_mib, 1),
        "export_seconds": round(exported.duration_seconds, 2),
        "dump_mib": round(exported.bytes / 2**20, 1),
        "verify_seconds": round(verify_seconds, 2),
        "restore_seconds": round(restore_seconds, 2),
        "restore_phases_seconds": {name: round(value, 2) for name, value in phases.items()},
        "restored_database_mib": round(restored_mib, 1),
        "records": {name: value for name, value in exported.records.items() if value},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assessments", type=int, nargs="+", default=[50_000])
    parser.add_argument("--per-project", type=int, default=1_000)
    parser.add_argument("--text-size", type=int, default=2_000,
                        help="approximate characters per assessment text")
    parser.add_argument("--output", help="write the JSON result to this file")
    args = parser.parse_args()
    results = []
    for count in args.assessments:
        with tempfile.TemporaryDirectory(prefix="dtvp-backup-benchmark-") as directory:
            results.append(run(count, args.per_project, args.text_size, directory))
            print(json.dumps(results[-1]), flush=True)
    document = {
        "schema_version": SCHEMA_VERSION,
        "measured_at": datetime.now(UTC).isoformat(),
        "python": platform.python_version(),
        "cpus": os.cpu_count(),
        "results": results,
    }
    if args.output:
        Path(args.output).write_text(json.dumps(document, indent=2) + "\n")


if __name__ == "__main__":
    main()
