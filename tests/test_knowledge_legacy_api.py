"""Native review preserves DT documentation without importing authorization."""

import json

from tests.test_knowledge_api import app as knowledge_app
from tests.test_workflow_api import setup, workspace

app = knowledge_app


def test_tagged_and_plain_dt_analysis_is_readable_but_not_approved(analyst, bom):
    tagged = "[Team: Platform] [State: NOT_AFFECTED] [Assessed by: Alice] [Reviewed by: Bob]\nDeployment excludes this path."
    for index, vulnerability in enumerate(bom["vulnerabilities"]):
        vulnerability["properties"] = [
            {
                "name": "dtvp:dt-analysis",
                "value": json.dumps(
                    {
                        "analysisState": "NOT_AFFECTED",
                        "analysisDetails": tagged
                        if index == 0
                        else "Plain legacy rationale without metadata.",
                    }
                ),
            }
        ]
    project_id, _ = setup(analyst, bom)
    current = workspace(analyst, project_id)
    evidence = [claim for row in current["items"] for claim in row.get("legacy_evidence", [])]
    assert evidence
    assert any("Deployment excludes this path." in claim.get("raw_text", "") for claim in evidence)
    assert any("Plain legacy rationale" in claim.get("raw_text", "") for claim in evidence)
    assert all(claim["approved"] is False for claim in evidence)
    assert all(claim["authenticated_identity"] is False for claim in evidence)
    assert current["statistics"]["approved"] == 0
    assert all(row["published_score"] is None for row in current["items"])
