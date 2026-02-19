import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional

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
PROJECT_V2_UUID = "4fa85f64-5717-4562-b3fc-2c963f66afa7"
LIB_UUID = "5fa85f64-5717-4562-b3fc-2c963f66afa8"
LIB_V2_UUID = "6fa85f64-5717-4562-b3fc-2c963f66afa9"

COMPONENT_UUID = "c253b708-3012-4277-8461-893bd5cd61e1"
VULN_UUID_1 = "d9401347-1941-4c12-8700-1c0563821017"  # CVE-2021-44228 (Log4Shell)
VULN_UUID_2 = "e5781a7b-0346-4927-991c-7033580539f5"  # Generic Vuln

mock_projects = [
    Project(
        name="Vulnerable Project",
        version="1.0.0",
        uuid=PROJECT_UUID,
        classifier="APPLICATION",
    ),
    Project(
        name="Vulnerable Project",
        version="2.0.0",
        uuid=PROJECT_V2_UUID,
        classifier="APPLICATION",
    ),
    Project(
        name="Core Library",
        version="1.0.0",
        uuid=LIB_UUID,
        classifier="LIBRARY",
    ),
    Project(
        name="Core Library",
        version="1.1.0",
        uuid=LIB_V2_UUID,
        classifier="LIBRARY",
    ),
]

# Analysis key format: project_uuid:component_uuid:vulnerability_uuid
# We will generate mock analysis/findings dynamically for all projects for simplicity
# but keep specific state for the main PROJECT_UUID to pass existing tests.

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

# Shared map for analysis state
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

# Pre-populate other projects with default state
for p in mock_projects:
    if p.uuid == PROJECT_UUID:
        continue
    mock_analysis[f"{p.uuid}:{COMPONENT_UUID}:{VULN_UUID_1}"] = {
        "analysisState": "NOT_SET",
        "isSuppressed": False,
    }


@app.get("/api/v1/project")
def get_projects(name: Optional[str] = None):
    # D-T API paginates, here we return all matches
    if name:
        return [p for p in mock_projects if name.lower() in p.name.lower()]
    return mock_projects


@app.get("/api/v1/finding/project/{project_uuid}")
def get_findings(project_uuid: str):
    # Check if project exists
    project = next((p for p in mock_projects if p.uuid == project_uuid), None)
    if not project:
        return []

    # Generate findings for this project
    # We pretend every project uses the same component with the same vulns for simplicity

    current_findings = []

    # Finding 1: Log4Shell
    key1 = f"{project_uuid}:{COMPONENT_UUID}:{VULN_UUID_1}"
    finding1 = {
        "component": {
            "uuid": COMPONENT_UUID,
            "name": "log4j-core",
            "version": "2.14.0",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
        },
        "vulnerability": mock_vulnerabilities[VULN_UUID_1],
        "analysis": mock_analysis.get(
            key1, {"analysisState": "NOT_SET", "isSuppressed": False}
        ),
        "matrix": key1,
    }
    current_findings.append(finding1)

    # Finding 2: Generic (only on Vulnerable Project v1 for variety?)
    # Let's add it to all for now, or just v1s
    if "1.0.0" in project.version:
        key2 = f"{project_uuid}:{COMPONENT_UUID}:{VULN_UUID_2}"
        finding2 = {
            "component": {
                "uuid": COMPONENT_UUID,
                "name": "log4j-core",
                "version": "2.14.0",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
            },
            "vulnerability": mock_vulnerabilities[VULN_UUID_2],
            "analysis": mock_analysis.get(
                key2, {"analysisState": "NOT_SET", "isSuppressed": False}
            ),
            "matrix": key2,
        }
        current_findings.append(finding2)

    return current_findings


@app.get("/api/v1/vulnerability/project/{project_uuid}")
def get_vulns(project_uuid: str):
    # Return vulnerabilities present in the project
    findings = get_findings(project_uuid)
    # Extract unique vulns
    vulns = {}
    for f in findings:
        v = f["vulnerability"]
        vulns[v["uuid"]] = v
    return list(vulns.values())


@app.get("/api/v1/bom/cyclonedx/project/{project_uuid}")
def get_bom(project_uuid: str):
    project = next((p for p in mock_projects if p.uuid == project_uuid), None)

    # Minimal valid CycloneDX BOM
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "component": {
                "name": project.name if project else "Unknown",
                "version": project.version if project else "0.0.0",
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
