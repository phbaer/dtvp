#!/usr/bin/env python3
"""Reproducible benchmark of the assessment record with synthetic data.

Measures what grows with the number of assessed findings since DTVP keeps a
record of every one (ADR 0003): adopting assessments on import, a start with
an existing database, the one-off read into atomic fields, the comparison of
a later import, memory held by the records, and building a CycloneDX VDR.
"""

import argparse
import gc
import json
import os
import platform
import sqlite3
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from dtvp.assessment_model import parse_assessment  # noqa: E402
from dtvp.assessment_outbox_services import AssessmentOutboxStore  # noqa: E402
from dtvp.cyclonedx_export import build_vdr  # noqa: E402

SCHEMA_VERSION = "dtvp.assessment-store-benchmark/v1"
TEAMS = ("Platform", "Runtime", "Applications", "Security")
STATES = ("NOT_AFFECTED", "NOT_AFFECTED", "NOT_AFFECTED", "IN_TRIAGE", "EXPLOITABLE")
VECTOR = "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N/MAV:L/MAC:H"


def rss_mib() -> float:
    """Resident memory of this process, from /proc where available."""
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) / 1024
    except OSError:
        pass
    return float("nan")


def synthetic_text(index: int, size: int) -> str:
    """An assessment in DTVP's markup of roughly ``size`` characters."""
    state = STATES[index % len(STATES)]
    teams = [TEAMS[(index + offset) % len(TEAMS)] for offset in range(1 + index % 3)]
    filler = (
        f"Finding {index}: the affected function is not reachable from any "
        "request handler in this version; verified in the call graph. "
    )
    per_block = max(1, (size // (len(teams) + 1)) // len(filler))
    blocks = [
        f"--- [Team: General] [State: {state}] [Assessed By: reviewer{index % 7}] "
        f"[Reviewed By: lead{index % 3}] [Justification: CODE_NOT_REACHABLE] ---\n"
        + filler * per_block
    ]
    for team in teams:
        blocks.append(
            f"--- [Team: {team}] [State: {state}] [Assessed By: analyst{index % 11}] "
            f"[Date: {1790000000000 + index}] [Justification: CODE_NOT_REACHABLE] "
            f"[Ticket: EXP-{1000 + index % 500}] ---\n" + filler * per_block
        )
    return f"[Rescored: 2.5] [Rescored Vector: {VECTOR}]\n\n" + "\n\n".join(blocks)


def key(index: int, per_project: int) -> tuple[str, str, str]:
    return (f"project-{index // per_project}", f"component-{index}", f"vuln-{index % 5000}")


def remote_batch(start: int, count: int, per_project: int, size: int) -> dict:
    return {
        key(index, per_project): {
            "state": STATES[index % len(STATES)],
            "details": synthetic_text(index, size),
            "suppressed": index % 17 == 0,
        }
        for index in range(start, start + count)
    }


def timed(function) -> tuple[float, Any]:
    started = time.perf_counter()
    result = function()
    return time.perf_counter() - started, result


def run(count: int, per_project: int, size: int, directory: str) -> dict[str, Any]:
    path = os.path.join(directory, "dtvp.sqlite3")
    later = lambda: datetime.now(UTC) + timedelta(seconds=5)  # noqa: E731
    gc.collect()
    baseline = rss_mib()

    store = AssessmentOutboxStore(path)
    adopt_seconds = 0.0
    for start in range(0, count, per_project):
        batch = remote_batch(start, min(per_project, count - start), per_project, size)
        seconds, outcomes = timed(lambda: store.reconcile_remote(batch, fetched_at=later()))
        adopt_seconds += seconds
        assert len(outcomes["adopted"]) == len(batch)
    gc.collect()
    after_adoption = rss_mib()

    # A later import of one project in which nothing changed, then one in
    # which every assessment was lost in the source.
    unchanged = remote_batch(0, per_project, per_project, size)
    unchanged_seconds, outcomes = timed(
        lambda: store.reconcile_remote(unchanged, fetched_at=later())
    )
    assert not any(outcomes.values())
    lost = {item: {"state": "NOT_SET", "details": "", "suppressed": False} for item in unchanged}
    lost_seconds, outcomes = timed(lambda: store.reconcile_remote(lost, fetched_at=later()))
    assert len(outcomes["requeued"]) == per_project

    lookup_seconds, _ = timed(
        lambda: [store.get_overlay(key(index, per_project)) for index in range(0, count, 97)]
    )
    lookups = len(range(0, count, 97))
    fields_seconds, fields = timed(lambda: store.get_fields(key(count // 2, per_project)))
    assert fields is not None and fields["teams"]

    database_mib = sum(
        os.path.getsize(path + suffix) for suffix in ("", "-wal") if os.path.exists(path + suffix)
    ) / 2**20
    del store
    gc.collect()

    restart_seconds, restarted = timed(lambda: AssessmentOutboxStore(path))
    restart_seconds += timed(restarted.pending_count)[0]
    gc.collect()
    after_restart = rss_mib()

    # The one-off migration: the same database without its fields.
    with sqlite3.connect(path) as connection:
        connection.execute("DELETE FROM assessment_team_fields")
        connection.execute("DELETE FROM assessment_fields")
    del restarted
    gc.collect()
    migration_seconds, migrated = timed(lambda: AssessmentOutboxStore(path).pending_count())

    # A CycloneDX VDR of one large project version.
    findings = [
        {
            "component": {"uuid": f"component-{index}", "name": f"lib-{index}", "version": "1.0"},
            "vulnerability": {
                "uuid": f"vuln-{index}", "vulnId": f"CVE-2026-{index:06d}", "source": "NVD",
                "severity": "HIGH", "cvssV3BaseScore": 7.5,
                "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            },
        }
        for index in range(per_project)
    ]
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "components": [
            {"type": "library", "bom-ref": f"component-{index}", "name": f"lib-{index}",
             "version": "1.0"}
            for index in range(per_project)
        ],
    }
    parse_seconds, assessments = timed(
        lambda: [
            parse_assessment(STATES[index % len(STATES)], synthetic_text(index, size), False)
            for index in range(per_project)
        ]
    )
    vdr_seconds, vdr = timed(lambda: build_vdr(bom, findings, assessments))
    vdr_mib = len(json.dumps(vdr)) / 2**20

    return {
        "assessments": count,
        "per_project": per_project,
        "text_characters": len(synthetic_text(0, size)),
        "adopt_seconds": round(adopt_seconds, 2),
        "adopt_per_second": round(count / adopt_seconds),
        "import_unchanged_project_ms": round(unchanged_seconds * 1000, 1),
        "import_lost_project_ms": round(lost_seconds * 1000, 1),
        "lookup_microseconds": round(lookup_seconds / lookups * 1e6, 1),
        "read_fields_ms": round(fields_seconds * 1000, 2),
        "restart_seconds": round(restart_seconds, 2),
        "field_migration_seconds": round(migration_seconds, 2),
        "database_mib": round(database_mib, 1),
        "memory_after_adoption_mib": round(after_adoption - baseline, 1),
        "memory_after_restart_mib": round(after_restart - baseline, 1),
        "vdr_findings": per_project,
        "vdr_parse_seconds": round(parse_seconds, 2),
        "vdr_build_seconds": round(vdr_seconds, 2),
        "vdr_size_mib": round(vdr_mib, 1),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assessments", type=int, nargs="+", default=[50_000])
    parser.add_argument("--per-project", type=int, default=1_000)
    parser.add_argument("--text-size", type=int, default=2_000,
                        help="approximate characters per assessment text")
    parser.add_argument("--output", help="write the JSON result to this file")
    args = parser.parse_args()

    runs = []
    for count in args.assessments:
        with tempfile.TemporaryDirectory(prefix="dtvp-store-benchmark-") as directory:
            runs.append(run(count, args.per_project, args.text_size, directory))
    result = {
        "schema": SCHEMA_VERSION,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cpus": os.cpu_count(),
        "runs": runs,
    }
    text = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
