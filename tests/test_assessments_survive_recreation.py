"""River is the record: an assessment never disappears because Dependency-Track
recreates a component (new UUID, same package), changes its CPE, or drops a
finding for one read before reporting it again on the new component. After
every read, every vulnerability assessed before is assessed with the same
state and teams on the findings that report it."""

import asyncio
import re
from unittest.mock import AsyncMock

import pytest

from dtvp.dt_cache import CacheManager

_TEXT = {
    "v1": "--- [Team: Alpha] [State: NOT_AFFECTED] [Assessed By: alex] ---\nNot reachable.",
    "v2": "--- [Team: Beta] [State: EXPLOITABLE] [Assessed By: bea] [Ticket: VP-1] ---\nReachable.",
}
_STATE = {"v1": "NOT_AFFECTED", "v2": "EXPLOITABLE"}


def _finding(component_uuid, vuln, state="NOT_SET", details=""):
    return {
        "component": {
            "uuid": component_uuid,
            "name": "lib-a",
            "version": "1.0",
            "purl": "pkg:npm/lib-a@1.0",
        },
        "vulnerability": {"uuid": vuln, "vulnId": f"CVE-2026-{vuln[1:]}"},
        "analysis": {"analysisState": state, "analysisDetails": details, "isSuppressed": False},
    }


def _bom(component_uuid, cpe):
    return {
        "components": [{
            "bom-ref": component_uuid, "name": "lib-a", "version": "1.0",
            "purl": "pkg:npm/lib-a@1.0", "cpe": cpe,
        }]
    }


def _teams(details):
    return sorted(set(re.findall(r"\[Team:\s*([^\]]+)\]", details or "")) - {"General"})


def _check(manager, component_uuid):
    """Every vulnerability assessed in the first read: same state and teams
    on the finding that reports it now."""
    for vuln in ("v1", "v2"):
        # The record itself (the overlay hides values adopted unchanged).
        overlay = manager.assessment_outbox.get_overlay(("p1", component_uuid, vuln))
        assert overlay is not None, (component_uuid, vuln)
        # Active: neither inactive nor superseded.
        assert overlay.get("sync_status") not in ("inactive", "superseded"), (component_uuid, vuln)
        assert overlay["analysisState"] == _STATE[vuln], (component_uuid, vuln)
        assert _teams(overlay["analysisDetails"]) == _teams(_TEXT[vuln]), (component_uuid, vuln)


async def test_assessments_survive_recreated_components_and_cpe_changes(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    client = AsyncMock()

    async def analysis(project_uuid, component_uuid, vulnerability_uuid):
        # Only the first generation was assessed in Dependency-Track.
        if component_uuid == "c1":
            return {
                "analysisState": _STATE[vulnerability_uuid],
                "analysisDetails": _TEXT[vulnerability_uuid],
                "isSuppressed": False,
            }
        return None

    client.get_analysis.side_effect = analysis

    async def read(component_uuid, cpe, *, present=True):
        client.get_vulnerabilities.return_value = (
            [_finding(component_uuid, vuln) for vuln in ("v1", "v2")] if present else []
        )
        client.get_bom.return_value = _bom(component_uuid, cpe)
        return await manager.import_findings(client, "p1")

    # Read 1: assessed in Dependency-Track, adopted by River.
    client.get_vulnerabilities.return_value = [
        _finding("c1", vuln, _STATE[vuln], _TEXT[vuln]) for vuln in ("v1", "v2")
    ]
    client.get_bom.return_value = _bom("c1", "cpe:2.3:a:example:lib-a:1.0:*:*:*:*:*:*:*")
    await manager.import_findings(client, "p1")
    _check(manager, "c1")

    # Read 2: recreated overnight (new UUID, same package), CPE changed.
    await read("c2", "cpe:2.3:a:lib-a_project:lib-a:1.0:*:*:*:*:*:*:*")
    _check(manager, "c2")

    # Read 3: recreated again, CPE back.
    await read("c3", "cpe:2.3:a:example:lib-a:1.0:*:*:*:*:*:*:*")
    _check(manager, "c3")

    # Read 4: the source recreated the component but has not analysed it
    # yet: no findings. Nothing is assessed on a finding, nothing is lost.
    await read("c4", "cpe:2.3:a:example:lib-a:1.0:*:*:*:*:*:*:*", present=False)
    # Read 5: the findings are back on the new component.
    await read("c4", "cpe:2.3:a:example:lib-a:1.0:*:*:*:*:*:*:*")
    _check(manager, "c4")

    # Read 6 is cancelled midway (after the findings, before the BOM);
    # read 7 completes on a recreated component.
    client.get_vulnerabilities.return_value = [_finding("c5", vuln) for vuln in ("v1", "v2")]
    client.get_bom.side_effect = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        await manager.import_findings(client, "p1")
    client.get_bom.side_effect = None
    _check(manager, "c4")
    await read("c5", "cpe:2.3:a:example:lib-a:1.0:*:*:*:*:*:*:*")
    _check(manager, "c5")
    await manager.close()
