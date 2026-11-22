"""Dependency-Track is one replaceable source and sink (dtvp/ports.py).

Its field names belong in its adapter, ``dtvp/dt_client.py``. Generic code
that needs them reads them through a neutral name instead.
"""

from pathlib import Path

DT_ONLY_FIELDS = ("lastBomImport", "lastVulnerabilityAnalysis")

# Usages that predate this check; each is a known leak to be moved behind
# the source adapter. Do not add to this list.
KNOWN_LEAKS: set[tuple[str, str]] = set()


def test_dependency_track_fields_stay_in_its_adapter():
    root = Path(__file__).resolve().parents[1]
    found = set()
    for path in sorted((root / "dtvp").rglob("*.py")):
        relative = path.relative_to(root).as_posix()
        if relative == "dtvp/dt_client.py":
            continue
        text = path.read_text(encoding="utf-8")
        for field in DT_ONLY_FIELDS:
            if field in text:
                found.add((relative, field))

    assert found - KNOWN_LEAKS == set(), (
        "Dependency-Track field names outside dtvp/dt_client.py; read them "
        "through the source adapter instead"
    )


def test_core_names_the_source_change_hints_neutrally():
    """The scheduler's columns and code call them hints, not by the
    Dependency-Track fields they come from (ADR 0004, "Change hints are
    optional")."""
    root = Path(__file__).resolve().parents[1]
    for path in sorted((root / "dtvp").rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        assert "dt_last_bom_import" not in text, path
        assert "dt_last_vuln_analysis" not in text, path
