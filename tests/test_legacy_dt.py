import json

import httpx
import respx

from dtvp.legacy_dt import decode
from dtvp.providers import import_dt


def test_plain_documentation_without_any_metadata():
    parsed = decode(
        {
            "analysisState": "NOT_AFFECTED",
            "analysisDetails": "The vulnerable feature is not built.",
            "isSuppressed": True,
        }
    )
    assert parsed["format"] == "plain-dt"
    assert parsed["state"] == "not_affected"
    assert parsed["assessed"]
    assert parsed["current_records"][0]["assessor"] is None
    assert parsed["current_records"][0]["reviewer"] is None
    assert parsed["suppressed"]
    assert parsed["raw_text"] == "The vulnerable feature is not built."
    prose = decode({"analysisDetails": "Legacy documentation with no state or identity."})
    assert prose["documented"] and not prose["assessed"]
    assert prose["state"] is None


def test_dtvp_blocks_claimed_history_ssvc_and_rescoring():
    raw = """--- [Team: General] [State: NOT_AFFECTED] [Assessed By: alice] [Reviewed By: bob] [Rescored: 4.0] [Rescored Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N] [SSVC: DEFER] [Date: 1720000000000] ---
Global rationale.
[SSVC Details]
{"rationale": "--- [Team: Fake] [State: EXPLOITABLE] ---", "model": "deployer"}
[/SSVC Details]
--- [Team: API] [State: IN_TRIAGE] [Assessed By: analyst] [Assigned: alice, bob] [Copied From: Former] ---
Team rationale.
--- [Team: Former] [State: EXPLOITABLE] [Historical: yes] ---
Historic rationale."""
    parsed = decode({"analysisState": "NOT_AFFECTED", "analysisDetails": raw})
    assert parsed["state"] == "not_affected"
    assert len(parsed["records"]) == 3
    assert len(parsed["current_records"]) == 2
    assert all(record["team"] != "Fake" for record in parsed["records"])
    general = parsed["current_records"][0]
    assert general["assessor"] == "alice" and general["reviewer"] == "bob"
    assert general["rescored_score"] == 4.0
    assert general["assessed_at"]
    assert parsed["ssvc"][0]["model"] == "deployer"
    assert parsed["raw_text"] == raw
    assert not parsed["conflicting"]  # General precedence retained.


def test_pending_conflict_duplicates_and_historical_blocks():
    raw = "--- [Team: API] [State: NOT_AFFECTED] [Date: 1000] ---\nOld.\n--- [Team: api] [State: EXPLOITABLE] [Date: 2000] ---\nNew.\n--- [Team: Other] [State: NOT_AFFECTED] ---\nDifferent.\n[Status: Pending Review]"
    parsed = decode({"analysisDetails": raw, "analysisState": "EXPLOITABLE"})
    assert parsed["pending_review"] and parsed["conflicting"]
    assert len(parsed["current_records"]) == 2
    assert parsed["current_records"][0]["rationale"] == "New."




@respx.mock
def test_dt_connector_reads_full_analysis_and_preserves_raw_metadata(bom):
    respx.get("https://dt.example.invalid/api/v1/bom/cyclonedx/project/project-id").mock(
        return_value=httpx.Response(200, json=bom)
    )
    respx.get("https://dt.example.invalid/api/v1/finding/project/project-id").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "component": {"uuid": "http"},
                    "vulnerability": {
                        "uuid": "vuln-uuid",
                        "vulnId": "CVE-2099-20001",
                        "cvssV3Vector": bom["vulnerabilities"][0]["ratings"][0]["vector"],
                        "cvssV3BaseScore": 9.8,
                    },
                    "analysis": {"analysisState": "NOT_AFFECTED"},
                }
            ],
        )
    )
    raw = {
        "analysis": {
            "analysisState": "NOT_AFFECTED",
            "analysisDetails": "Plain older DT documentation.",
        },
        "comments": [{"comment": "Historical comment", "commenter": "claimed author"}],
    }
    respx.get("https://dt.example.invalid/api/v1/analysis").mock(
        return_value=httpx.Response(200, json=raw)
    )
    with httpx.Client() as http:
        imported = import_dt(http, "https://dt.example.invalid", "read-only-test-key", "project-id")
    value = imported["vulnerabilities"][0]
    assert value["analysis"]["state"] == "not_affected"
    assert (
        json.loads(next(p["value"] for p in value["properties"] if p["name"] == "dtvp:dt-analysis"))
        == raw
    )
