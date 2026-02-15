import uvicorn
from fastapi import FastAPI, Request
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import uuid

app = FastAPI()


# Data Models
class Project(BaseModel):
    name: str
    version: str
    uuid: str
    classifier: str = "APPLICATION"


class Analysis(BaseModel):
    analysisState: str
    isSuppressed: bool = False
    analysisDetails: Optional[str] = None
    analysisJustification: Optional[str] = None
    comment: Optional[str] = None


class AnalysisUpdate(BaseModel):
    project: str
    component: str
    vulnerability: str
    analysisState: str
    isSuppressed: bool = False
    analysisDetails: Optional[str] = None
    analysisJustification: Optional[str] = None
    comment: Optional[str] = None


# Mock Data
PROJECT_UUID = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
COMPONENT_UUID = "c253b708-3012-4277-8461-893bd5cd61e1"
VULN_UUID_1 = "d9401347-1941-4c12-8700-1c0563821017"  # CVE-2021-44228 (Log4Shell)
VULN_UUID_2 = "e5781a7b-0346-4927-991c-7033580539f5"  # Generic Vuln

mock_projects = [
    Project(
        name="Vulnerable Project",
        version="1.0.0",
        uuid=PROJECT_UUID,
        classifier="APPLICATION",
    )
]

mock_analysis = {
    f"{PROJECT_UUID}:{COMPONENT_UUID}:{VULN_UUID_1}": {
        "analysisState": "NOT_SET",
        "isSuppressed": False,
    },
    f"{PROJECT_UUID}:{COMPONENT_UUID}:{VULN_UUID_2}": {
        "analysisState": "IN_TRIAGE",
        "isSuppressed": False,
        "analysisDetails": "Investigating impact.",
    },
}

mock_vulnerabilities = {
    VULN_UUID_1: {
        "uuid": VULN_UUID_1,
        "vulnId": "CVE-2021-44228",
        "source": "NVD",
        "severity": "CRITICAL",
        "cvssV3BaseScore": 10.0,
        "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "description": "Log4j JNDI vulnerabilities",
        "recommendation": "Upgrade to Log4j 2.17.1",
    },
    VULN_UUID_2: {
        "uuid": VULN_UUID_2,
        "vulnId": "CVE-2023-12345",
        "source": "NVD",
        "severity": "MEDIUM",
        "cvssV3BaseScore": 5.4,
        "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        "description": "Generic medium severity vulnerability",
        "recommendation": "Apply patch.",
    },
}

mock_findings = [
    {
        "component": {
            "uuid": COMPONENT_UUID,
            "name": "log4j-core",
            "version": "2.14.0",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
        },
        "vulnerability": mock_vulnerabilities[VULN_UUID_1],
        "analysis": mock_analysis[f"{PROJECT_UUID}:{COMPONENT_UUID}:{VULN_UUID_1}"],
        "matrix": f"{PROJECT_UUID}:{COMPONENT_UUID}:{VULN_UUID_1}",
    },
    {
        "component": {
            "uuid": COMPONENT_UUID,
            "name": "log4j-core",
            "version": "2.14.0",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
        },
        "vulnerability": mock_vulnerabilities[VULN_UUID_2],
        "analysis": mock_analysis[f"{PROJECT_UUID}:{COMPONENT_UUID}:{VULN_UUID_2}"],
        "matrix": f"{PROJECT_UUID}:{COMPONENT_UUID}:{VULN_UUID_2}",
    },
]


@app.get("/api/v1/project")
def get_projects(name: Optional[str] = None):
    if name:
        return [p for p in mock_projects if name.lower() in p.name.lower()]
    return mock_projects


@app.get("/api/v1/finding/project/{project_uuid}")
def get_findings(project_uuid: str):
    # Returns raw list of findings. In real DT, this returns Finding objects.
    # We simulate returning ALL findings for this project.
    if project_uuid == PROJECT_UUID:
        # Need to dynamically attach current analysis state to findings
        current_findings = []
        for f in mock_findings:
            f_copy = f.copy()
            # Update analysis from robust state
            key = f_copy.get("matrix")
            if key in mock_analysis:
                f_copy["analysis"] = mock_analysis[key]
            current_findings.append(f_copy)
        return current_findings
    return []


@app.get("/api/v1/vulnerability/project/{project_uuid}")
def get_vulns(project_uuid: str):
    if project_uuid == PROJECT_UUID:
        return list(mock_vulnerabilities.values())
    return []


@app.get("/api/v1/bom/cyclonedx/project/{project_uuid}")
def get_bom(project_uuid: str):
    # Minimal valid CycloneDX BOM
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "component": {
                "name": "Vulnerable Project",
                "version": "1.0.0",
                "type": "application",
            }
        },
        "components": [
            {
                "type": "library",
                "name": "log4j-core",
                "version": "2.14.0",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
                "bom-ref": COMPONENT_UUID,
            }
        ],
    }


@app.get("/api/v1/analysis")
def get_analysis(project: str, component: str, vulnerability: str):
    key = f"{project}:{component}:{vulnerability}"
    if key in mock_analysis:
        return mock_analysis[key]
    return {}  # Or 404? DT returns 404 if finding doesn't exist, but analysis requires finding exists.


@app.put("/api/v1/analysis")
def update_analysis(update: AnalysisUpdate):
    key = f"{update.project}:{update.component}:{update.vulnerability}"
    if key in mock_analysis:
        mock_analysis[key]["analysisState"] = update.analysisState
        mock_analysis[key]["isSuppressed"] = update.isSuppressed
        mock_analysis[key]["analysisDetails"] = update.analysisDetails
        if update.analysisJustification:
            mock_analysis[key]["analysisJustification"] = update.analysisJustification
        if update.comment:
            # Append comment? Or verify behavior. For simplicity, just store last comment.
            mock_analysis[key]["comment"] = (
                update.comment
            )  # Actually comments are separate usually
        return mock_analysis[key]
    return {"error": "Finding not found"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8081)
