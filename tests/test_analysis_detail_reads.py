"""A version read takes the analysis details from the record where the
source's list shows the same state and suppression (ADR 0004, "Analysis
details"): an unchanged assessed finding costs no request."""

import pytest

from dtvp.dt_cache import CacheManager

PROJECT = "p1"


def _finding(index: int, state: str, suppressed: bool = False) -> dict:
    return {
        "component": {"uuid": f"c{index}", "name": f"lib{index}", "version": "1"},
        "vulnerability": {"uuid": f"v{index}", "vulnId": f"CVE-2026-{index}", "source": "NVD"},
        # What Dependency-Track's findings list carries: state and suppression.
        "analysis": {"state": state, "isSuppressed": suppressed},
    }


class ListOnlySource:
    """A source that lists analyses without details, like Dependency-Track."""

    def __init__(self, count: int, state: str = "NOT_AFFECTED") -> None:
        self.states = {index: (state, False) for index in range(count)}
        self.details = {index: f"Team A: not reachable ({index})" for index in range(count)}
        self.analysis_reads = 0

    async def get_vulnerabilities(self, project_uuid, cve=None, *, analysis_details=True):
        assert analysis_details is False
        return [
            _finding(index, state, suppressed)
            for index, (state, suppressed) in self.states.items()
        ]

    async def get_analysis(self, project_uuid, component_uuid, vulnerability_uuid):
        self.analysis_reads += 1
        index = int(component_uuid[1:])
        state, suppressed = self.states[index]
        return {
            "analysisState": state,
            "analysisDetails": self.details[index],
            "isSuppressed": suppressed,
        }


async def _read(manager: CacheManager, source: ListOnlySource) -> list:
    return (await manager.import_findings(source, PROJECT)).findings


@pytest.mark.asyncio
async def test_an_unchanged_assessed_version_reads_no_analysis(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    source = ListOnlySource(4000)

    await _read(manager, source)  # first read: every assessment is adopted
    assert source.analysis_reads == 4000
    assert manager.last_analysis_reads[PROJECT] == 4000

    source.analysis_reads = 0
    findings = await _read(manager, source)
    assert source.analysis_reads == 0
    assert manager.last_analysis_reads[PROJECT] == 0
    by_component = {f["component"]["uuid"]: f for f in findings}
    assert by_component["c7"]["analysis"]["analysisDetails"] == "Team A: not reachable (7)"
    # Nothing to export: the record and the source agree.
    assert manager.assessment_outbox.list_pending() == []


@pytest.mark.asyncio
async def test_only_findings_whose_state_changed_in_the_source_are_read(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    source = ListOnlySource(50)
    await _read(manager, source)

    source.analysis_reads = 0
    source.states[3] = ("EXPLOITABLE", False)
    source.details[3] = "Team B: reachable"
    source.states[4] = ("NOT_AFFECTED", True)
    await _read(manager, source)
    assert source.analysis_reads == 2


@pytest.mark.asyncio
async def test_new_assessed_findings_are_read_to_be_adopted(tmp_path):
    manager = CacheManager(base_path=str(tmp_path))
    source = ListOnlySource(10)
    await _read(manager, source)

    source.analysis_reads = 0
    source.states[10] = ("FALSE_POSITIVE", False)
    source.details[10] = "Team C: wrong match"
    source.states[11] = ("NOT_SET", False)
    source.details[11] = ""
    findings = await _read(manager, source)
    assert source.analysis_reads == 1  # the unassessed one needs no read
    adopted = manager.assessment_outbox.get_overlay((PROJECT, "c10", "v10"))
    assert adopted is not None and adopted["analysisDetails"] == "Team C: wrong match"
    assert len(findings) == 12


@pytest.mark.asyncio
async def test_the_safety_re_read_takes_every_assessment_from_the_source(tmp_path):
    from dtvp.source_sync_state import FULL_ANALYSIS_DETAILS

    manager = CacheManager(base_path=str(tmp_path))
    source = ListOnlySource(20)
    await _read(manager, source)

    class FullSource(ListOnlySource):
        async def get_vulnerabilities(self, project_uuid, cve=None, *, analysis_details=True):
            assert analysis_details is True
            findings = []
            for index, (state, suppressed) in self.states.items():
                finding = _finding(index, state, suppressed)
                finding["analysis"] = await self.get_analysis(project_uuid, f"c{index}", f"v{index}")
                findings.append(finding)
            return findings

    full = FullSource(20)
    full.details[5] = "Team A: edited in the source"
    token = FULL_ANALYSIS_DETAILS.set(True)
    try:
        await _read(manager, full)
    finally:
        FULL_ANALYSIS_DETAILS.reset(token)
    assert full.analysis_reads == 20
    assert manager.assessment_outbox.get_overlay((PROJECT, "c5", "v5"))["remote"]["details"] == (
        "Team A: edited in the source"
    )
