import json
import time
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel

app = FastAPI()


def check_auth(request: Request):
    api_key = request.headers.get("X-Api-Key")
    auth_header = request.headers.get("Authorization")
    # In a real D-T, any of these would work depending on the endpoint/session
    if not api_key and not auth_header:
        raise HTTPException(
            status_code=401, detail="X-Api-Key or Authorization header required"
        )


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
    analysisComments: Optional[list] = None


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
VULN_JACKSON_UUID = "f6781a7b-0346-4927-991c-7033580539f6"  # CVE-2019-12384
VULN_NETTY_UUID = "a7781a7b-0346-4927-991c-7033580539f7"  # CVE-2021-21290
VULN_INCOMPLETE_UUID = "b8881a7b-0346-4927-991c-7033580539f8"
VULN_INCONSISTENT_UUID = "c9991a7b-0346-4927-991c-7033580539f9"

JACKSON_UUID = "b253b708-3012-4277-8461-893bd5cd61e2"
NETTY_UUID = "d253b708-3012-4277-8461-893bd5cd61e3"
TEAM_TEST_LIB_UUID = "7fa85f64-5717-4562-b3fc-2c963f66afb0"
VULN_UUID_TEAM = "f6781a7b-0346-4927-991c-7033580539f8"
PROJECT_V1_1_UUID = "8fa85f64-5717-4562-b3fc-2c963f66afb1"
PROJECT_V1_2_UUID = "9fa85f64-5717-4562-b3fc-2c963f66afb2"
PROJECT_V2_1_UUID = "afa85f64-5717-4562-b3fc-2c963f66afb3"
PROJECT_V3_UUID = "bfa85f64-5717-4562-b3fc-2c963f66afb4"
# Additional mock vulnerabilities to exercise plaintext assessment formats
VULN_PLAINTEXT_NOT_SET_UUID = "d1111a7b-0346-4927-991c-7033580539f0"
VULN_PLAINTEXT_NOT_AFFECTED_UUID = "d2222a7b-0346-4927-991c-7033580539f1"
VULN_OPEN_PENDING_UUID = "d7777a7b-0346-4927-991c-7033580539fa"
VULN_TEAM_PARTIAL_UUID = "d8888a7b-0346-4927-991c-7033580539fb"
COMMONS_TEXT_UUID = "e253b708-3012-4277-8461-893bd5cd61e4"
VULN_COMMONS_TEXT_UUID = "e1111a7b-0346-4927-991c-7033580539fc"
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
    Project(
        name="Vulnerable Project",
        version="1.1.0",
        uuid=PROJECT_V1_1_UUID,
        classifier="APPLICATION",
    ),
    Project(
        name="Vulnerable Project",
        version="1.2.0",
        uuid=PROJECT_V1_2_UUID,
        classifier="APPLICATION",
    ),
    Project(
        name="Vulnerable Project",
        version="1.2.10",
        uuid="cfa85f64-5717-4562-b3fc-2c963f66afb5",
        classifier="APPLICATION",
    ),
    Project(
        name="Vulnerable Project",
        version="2.1.0",
        uuid=PROJECT_V2_1_UUID,
        classifier="APPLICATION",
    ),
    Project(
        name="Vulnerable Project",
        version="3.0.0",
        uuid=PROJECT_V3_UUID,
        classifier="APPLICATION",
    ),
]

# Analysis key format: project_uuid:component_uuid:vulnerability_uuid
# We will generate mock analysis/findings dynamically for all projects for simplicity
# but keep specific state for the main PROJECT_UUID to pass existing tests.


def load_vulnerability_definitions():
    definitions_path = Path(__file__).resolve().parent / "vuln_definitions.json"
    with open(definitions_path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    return {entry["uuid"]: entry for entry in payload}


def load_mock_analysis():
    analysis_path = Path(__file__).resolve().parent / "mock_dt_analysis.json"
    with open(analysis_path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    return payload.get("mock_analysis", {})


mock_vulnerabilities = load_vulnerability_definitions()
mock_analysis = load_mock_analysis()

# Pre-populate other projects with default state
for p in mock_projects:
    if p.uuid == PROJECT_UUID:
        continue
    mock_analysis[f"{p.uuid}:{COMPONENT_UUID}:{VULN_UUID_1}"] = {
        "analysisState": "NOT_SET",
        "isSuppressed": False,
    }


@app.get("/api/v1/user/me")
def get_me(request: Request):
    check_auth(request)
    return {"username": "analyst", "email": "analyst@example.com"}


@app.get("/api/v1/project")
def get_projects(request: Request, name: Optional[str] = None):
    check_auth(request)
    # D-T API paginates, here we return all matches
    if name:
        return [p for p in mock_projects if name.lower() in p.name.lower()]
    return mock_projects


def _component_for_vuln(vuln_uuid: str):
    if vuln_uuid in [
        VULN_UUID_1,
        VULN_UUID_2,
        VULN_INCOMPLETE_UUID,
        VULN_INCONSISTENT_UUID,
    ]:
        return {
            "uuid": COMPONENT_UUID,
            "name": "log4j-core",
            "version": "2.14.0",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
        }
    if vuln_uuid == VULN_JACKSON_UUID:
        return {
            "uuid": JACKSON_UUID,
            "name": "jackson-databind",
            "version": "2.9.8",
            "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8",
        }
    if vuln_uuid == VULN_NETTY_UUID:
        return {
            "uuid": NETTY_UUID,
            "name": "netty-common",
            "version": "4.1.42.Final",
            "purl": "pkg:maven/io.netty/netty-common@4.1.42.Final",
        }
    if vuln_uuid == VULN_UUID_TEAM:
        return {
            "uuid": TEAM_TEST_LIB_UUID,
            "name": "team-test-lib",
            "version": "1.0.0",
            "purl": "pkg:maven/org.example/team-test-lib@1.0.0",
        }
    if vuln_uuid == VULN_COMMONS_TEXT_UUID:
        return {
            "uuid": COMMONS_TEXT_UUID,
            "name": "commons-text",
            "version": "1.9",
            "purl": "pkg:maven/org.apache.commons/commons-text@1.9",
        }
    # default fallback component
    return {
        "uuid": COMPONENT_UUID,
        "name": "misc-lib",
        "version": "1.0.0",
        "purl": "pkg:maven/com.example/misc-lib@1.0.0",
    }


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

    # Finding 2: Generic + plaintext state coverage (for major version 1 and 2 builds)
    if project.version.startswith("1.") or project.version.startswith("2."):
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

        # Add a plaintext NOT_SET assessment vuln for filter coverage
        key_plain_not_set = (
            f"{project_uuid}:{COMPONENT_UUID}:{VULN_PLAINTEXT_NOT_SET_UUID}"
        )
        finding_plain_not_set = {
            "component": {
                "uuid": COMPONENT_UUID,
                "name": "log4j-core",
                "version": "2.14.0",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
            },
            "vulnerability": mock_vulnerabilities[VULN_PLAINTEXT_NOT_SET_UUID],
            "analysis": mock_analysis.get(
                key_plain_not_set, {"analysisState": "NOT_SET", "isSuppressed": False}
            ),
            "matrix": key_plain_not_set,
        }
        current_findings.append(finding_plain_not_set)

        # Add a plaintext NOT_AFFECTED assessment vuln for filter coverage
        key_plain_not_affected = (
            f"{project_uuid}:{COMPONENT_UUID}:{VULN_PLAINTEXT_NOT_AFFECTED_UUID}"
        )
        finding_plain_not_affected = {
            "component": {
                "uuid": COMPONENT_UUID,
                "name": "log4j-core",
                "version": "2.14.0",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
            },
            "vulnerability": mock_vulnerabilities[VULN_PLAINTEXT_NOT_AFFECTED_UUID],
            "analysis": mock_analysis.get(
                key_plain_not_affected,
                {"analysisState": "NOT_AFFECTED", "isSuppressed": False},
            ),
            "matrix": key_plain_not_affected,
        }
        current_findings.append(finding_plain_not_affected)

    # Finding 3: Jackson (on all)
    key3 = f"{project_uuid}:{JACKSON_UUID}:{VULN_JACKSON_UUID}"
    finding3 = {
        "component": {
            "uuid": JACKSON_UUID,
            "name": "jackson-databind",
            "version": "2.9.8",
            "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8",
        },
        "vulnerability": mock_vulnerabilities[VULN_JACKSON_UUID],
        "analysis": mock_analysis.get(
            key3, {"analysisState": "NOT_SET", "isSuppressed": False}
        ),
        "matrix": key3,
    }
    current_findings.append(finding3)

    # Finding 4: Team Mapping Test (on all projects)
    key4 = f"{project_uuid}:{TEAM_TEST_LIB_UUID}:{VULN_UUID_TEAM}"
    finding4 = {
        "component": {
            "uuid": TEAM_TEST_LIB_UUID,
            "name": "team-test-lib",
            "version": "1.0.0",
            "purl": "pkg:maven/org.example/team-test-lib@1.0.0",
        },
        "vulnerability": mock_vulnerabilities[VULN_UUID_TEAM],
        "analysis": mock_analysis.get(
            key4, {"analysisState": "NOT_SET", "isSuppressed": False}
        ),
        "matrix": key4,
    }
    current_findings.append(finding4)

    # Finding: Transitive dependency (commons-text via internal-lib-a, NOT team-mapped)
    key_ct = f"{project_uuid}:{COMMONS_TEXT_UUID}:{VULN_COMMONS_TEXT_UUID}"
    finding_ct = {
        "component": {
            "uuid": COMMONS_TEXT_UUID,
            "name": "commons-text",
            "version": "1.9",
            "purl": "pkg:maven/org.apache.commons/commons-text@1.9",
        },
        "vulnerability": mock_vulnerabilities[VULN_COMMONS_TEXT_UUID],
        "analysis": mock_analysis.get(
            key_ct, {"analysisState": "NOT_SET", "isSuppressed": False}
        ),
        "matrix": key_ct,
    }
    current_findings.append(finding_ct)

    # Finding 5: Open-filter scenario (pending review with open team assessment)
    key_open = f"{project_uuid}:{COMPONENT_UUID}:{VULN_OPEN_PENDING_UUID}"
    finding_open = {
        "component": {
            "uuid": COMPONENT_UUID,
            "name": "log4j-core",
            "version": "2.14.0",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
        },
        "vulnerability": mock_vulnerabilities[VULN_OPEN_PENDING_UUID],
        "analysis": mock_analysis.get(
            key_open,
            {
                "analysisState": "IN_TRIAGE",
                "isSuppressed": False,
                "analysisDetails": "--- [Team: team-a] [State: NOT_SET] [Assessed By: internal-test] ---\nPending approval for open workflow.\n\n[Status: Pending Review]",
            },
        ),
        "matrix": key_open,
    }
    current_findings.append(finding_open)

    # Finding 6: Partial team assessment (team-a assessed, team-b still open)
    key_partial = f"{project_uuid}:{COMPONENT_UUID}:{VULN_TEAM_PARTIAL_UUID}"
    finding_partial = {
        "component": {
            "uuid": COMPONENT_UUID,
            "name": "log4j-core",
            "version": "2.14.0",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
        },
        "vulnerability": mock_vulnerabilities[VULN_TEAM_PARTIAL_UUID],
        "analysis": mock_analysis.get(
            key_partial,
            {
                "analysisState": "IN_TRIAGE",
                "isSuppressed": False,
                "analysisDetails": "--- [Team: team-a] [State: NOT_AFFECTED] [Assessed By: reviewer] ---\n--- [Team: team-b] [State: NOT_SET] [Assessed By: reviewer] ---\nTeam-b assessment still required.\n\n[Status: Pending Review]",
            },
        ),
        "matrix": key_partial,
    }
    current_findings.append(finding_partial)

    # Finding 5: Netty (only on Vulnerable Project)
    if "Vulnerable Project" in project.name:
        key5 = f"{project_uuid}:{NETTY_UUID}:{VULN_NETTY_UUID}"
        finding5 = {
            "component": {
                "uuid": NETTY_UUID,
                "name": "netty-common",
                "version": "4.1.42.Final",
                "purl": "pkg:maven/io.netty/netty-common@4.1.42.Final",
            },
            "vulnerability": mock_vulnerabilities[VULN_NETTY_UUID],
            "analysis": mock_analysis.get(
                key5,
                {
                    "analysisState": "NOT_SET",
                    "isSuppressed": False,
                    # Plain-text details for NOT_SET state
                    "analysisDetails": "Default not set assessment; no structured blocks present.",
                },
            ),
            "matrix": key5,
        }
        current_findings.append(finding5)

        # Finding 6: INCOMPLETE logic triggers when some are matching and others missing
        key_inc = f"{project_uuid}:{COMPONENT_UUID}:{VULN_INCOMPLETE_UUID}"
        finding_inc = {
            "component": {
                "uuid": COMPONENT_UUID,
                "name": "log4j-core",
                "version": "2.14.0",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
            },
            "vulnerability": mock_vulnerabilities[VULN_INCOMPLETE_UUID],
            "analysis": mock_analysis.get(
                key_inc, {"analysisState": "NOT_SET", "isSuppressed": False}
            ),
            "matrix": key_inc,
        }
        current_findings.append(finding_inc)

        # Second instance for INCOMPLETE state (Jackson doesn't have assessment for this vuln)
        key_inc_2 = f"{project_uuid}:{JACKSON_UUID}:{VULN_INCOMPLETE_UUID}"
        finding_inc_2 = {
            "component": {
                "uuid": JACKSON_UUID,
                "name": "jackson-databind",
                "version": "2.9.8",
                "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8",
            },
            "vulnerability": mock_vulnerabilities[VULN_INCOMPLETE_UUID],
            "analysis": {"analysisState": "NOT_SET", "isSuppressed": False},
            "matrix": key_inc_2,
        }
        current_findings.append(finding_inc_2)

        # Finding 7: INCONSISTENT logic triggers when there are matching conflicting states
        key_incon = f"{project_uuid}:{COMPONENT_UUID}:{VULN_INCONSISTENT_UUID}"
        finding_incon = {
            "component": {
                "uuid": COMPONENT_UUID,
                "name": "log4j-core",
                "version": "2.14.0",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
            },
            "vulnerability": mock_vulnerabilities[VULN_INCONSISTENT_UUID],
            "analysis": mock_analysis.get(
                key_incon, {"analysisState": "NOT_SET", "isSuppressed": False}
            ),
            "matrix": key_incon,
        }
        current_findings.append(finding_incon)

        # Second instance for INCONSISTENT state (EXPLOITABLE vs FALSE_POSITIVE)
        key_incon_2 = f"{project_uuid}:{JACKSON_UUID}:{VULN_INCONSISTENT_UUID}"
        finding_incon_2 = {
            "component": {
                "uuid": JACKSON_UUID,
                "name": "jackson-databind",
                "version": "2.9.8",
                "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8",
            },
            "vulnerability": mock_vulnerabilities[VULN_INCONSISTENT_UUID],
            "analysis": {"analysisState": "EXPLOITABLE", "isSuppressed": False},
            "matrix": key_incon_2,
        }
        current_findings.append(finding_incon_2)

    # Add additional vulnerabilities to simulate realistic count
    existing_vuln_uuids = {fv["vulnerability"]["uuid"] for fv in current_findings}

    def add_vuln(vuln_uuid, component_override=None, analysis_override=None):
        if vuln_uuid in existing_vuln_uuids:
            return
        component = component_override or _component_for_vuln(vuln_uuid)
        key = f"{project_uuid}:{component['uuid']}:{vuln_uuid}"
        current_findings.append(
            {
                "component": component,
                "vulnerability": mock_vulnerabilities[vuln_uuid],
                "analysis": mock_analysis.get(
                    key,
                    analysis_override
                    or {"analysisState": "NOT_SET", "isSuppressed": False},
                ),
                "matrix": key,
            }
        )

    # Baseline realistic coverage per project type
    if project.name == "Vulnerable Project":
        base_set = [VULN_UUID_1, VULN_JACKSON_UUID, VULN_UUID_2]
        extra_by_version = {
            "1.0.0": [VULN_NETTY_UUID, VULN_PLAINTEXT_NOT_SET_UUID],
            "1.1.0": [
                VULN_NETTY_UUID,
                VULN_PLAINTEXT_NOT_SET_UUID,
                VULN_PLAINTEXT_NOT_AFFECTED_UUID,
            ],
            "1.2.0": [
                VULN_NETTY_UUID,
                VULN_INCOMPLETE_UUID,
                VULN_PLAINTEXT_NOT_SET_UUID,
                VULN_PLAINTEXT_NOT_AFFECTED_UUID,
            ],
            "1.2.10": [
                VULN_NETTY_UUID,
                VULN_INCOMPLETE_UUID,
                VULN_INCONSISTENT_UUID,
                "d3331a7b-0346-4927-991c-7033580539f2",
            ],
            "2.0.0": [
                VULN_NETTY_UUID,
                VULN_INCONSISTENT_UUID,
                "d3331a7b-0346-4927-991c-7033580539f2",
                "d4441a7b-0346-4927-991c-7033580539f3",
            ],
            "2.1.0": [
                VULN_NETTY_UUID,
                VULN_INCONSISTENT_UUID,
                "d3331a7b-0346-4927-991c-7033580539f2",
                "d4441a7b-0346-4927-991c-7033580539f3",
                "d5551a7b-0346-4927-991c-7033580539f4",
            ],
            "3.0.0": [
                VULN_NETTY_UUID,
                VULN_INCONSISTENT_UUID,
                "d3331a7b-0346-4927-991c-7033580539f2",
                "d4441a7b-0346-4927-991c-7033580539f3",
                "d5551a7b-0346-4927-991c-7033580539f4",
                VULN_INCOMPLETE_UUID,
            ],
        }

        add_vuln_list = base_set + extra_by_version.get(project.version, [])
        for vuln_uuid in add_vuln_list:
            add_vuln(vuln_uuid)

        # some projects add a second component to simulate dependency chain
        component = {
            "uuid": "accd5b70-8888-4277-8461-893bd5cd6200",
            "name": "utility-lib",
            "version": "3.1.2",
            "purl": "pkg:maven/org.example/utility-lib@3.1.2",
        }
        add_vuln("d3331a7b-0346-4927-991c-7033580539f2", component_override=component)

    elif project.name == "Core Library":
        for vuln_uuid in [
            VULN_JACKSON_UUID,
            VULN_NETTY_UUID,
            VULN_UUID_2,
            VULN_PLAINTEXT_NOT_SET_UUID,
            "d4441a7b-0346-4927-991c-7033580539f3",
        ]:
            add_vuln(vuln_uuid)

    else:
        # Economical sample data for other project versions
        for vuln_uuid in [VULN_UUID_1, VULN_JACKSON_UUID, VULN_UUID_2]:
            add_vuln(vuln_uuid)

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

    if project_uuid == PROJECT_V2_UUID:
        # Root -> TeamBComp -> TeamAComp -> log4j-core
        # Vulnerable component should inherit only TeamA, not the higher-level TeamB.
        team_a_uuid = "44444444-4444-4444-4444-444444444444"
        team_b_uuid = "55555555-5555-5555-5555-555555555555"

        metadata_component = {
            "bom-ref": project_uuid,
            "name": project.name if project else "Unknown",
            "version": project.version if project else "0.0.0",
            "type": "application",
            "uuid": project_uuid,
        }

        comp_team_b = {
            "type": "library",
            "name": "team-b-comp",
            "version": "1.0.0",
            "bom-ref": team_b_uuid,
            "uuid": team_b_uuid,
        }

        comp_team_a = {
            "type": "library",
            "name": "team-a-comp",
            "version": "1.0.0",
            "bom-ref": team_a_uuid,
            "uuid": team_a_uuid,
        }

        comp_log4j = {
            "type": "library",
            "name": "log4j-core",
            "version": "2.14.0",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
            "bom-ref": COMPONENT_UUID,
            "uuid": COMPONENT_UUID,
        }

        components = [comp_team_b, comp_team_a, comp_log4j]
        dependencies = [
            {"ref": project_uuid, "dependsOn": [team_b_uuid]},
            {"ref": team_b_uuid, "dependsOn": [team_a_uuid]},
            {"ref": team_a_uuid, "dependsOn": [COMPONENT_UUID]},
            {"ref": COMPONENT_UUID, "dependsOn": []},
        ]

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {"component": metadata_component},
            "components": components,
            "dependencies": dependencies,
        }

    # Define intermediate components for trace
    # App -> Intermediate Lib A -> Intermediate Lib B -> log4j-core
    # We will only add this structure for the main "Vulnerable Project" (PROJECT_UUID)
    # properly.

    components = []
    dependencies = []

    # root component (The Project itself)
    metadata_component = {
        "bom-ref": project_uuid,  # Usually the project UUID is the root ref
        "name": project.name if project else "Unknown",
        "version": project.version if project else "0.0.0",
        "type": "application",
        "uuid": project_uuid,
    }

    # Internal libraries
    lib_a_uuid = "11111111-1111-1111-1111-111111111111"
    lib_b_uuid = "22222222-2222-2222-2222-222222222222"
    lib_c_uuid = "33333333-3333-3333-3333-333333333333"

    comp_lib_a = {
        "type": "library",
        "name": "internal-lib-a",
        "version": "1.0.0",
        "bom-ref": lib_a_uuid,
        "uuid": lib_a_uuid,
    }

    comp_lib_b = {
        "type": "library",
        "name": "internal-lib-b",
        "version": "1.2.3",
        "bom-ref": lib_b_uuid,
        "uuid": lib_b_uuid,
    }

    comp_lib_c = {
        "type": "library",
        "name": "internal-lib-c",
        "version": "2.0.0",
        "bom-ref": lib_c_uuid,
        "uuid": lib_c_uuid,
    }

    # The Vulnerable Component (log4j-core)
    # defined globally as COMPONENT_UUID
    comp_log4j = {
        "type": "library",
        "name": "log4j-core",
        "version": "2.14.0",
        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
        "bom-ref": COMPONENT_UUID,
        "uuid": COMPONENT_UUID,
    }

    comp_jackson = {
        "type": "library",
        "name": "jackson-databind",
        "version": "2.9.8",
        "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8",
        "bom-ref": JACKSON_UUID,
        "uuid": JACKSON_UUID,
    }

    comp_netty = {
        "type": "library",
        "name": "netty-common",
        "version": "4.1.42.Final",
        "purl": "pkg:maven/io.netty/netty-common@4.1.42.Final",
        "bom-ref": NETTY_UUID,
        "uuid": NETTY_UUID,
    }

    comp_team_test = {
        "type": "library",
        "name": "team-test-lib",
        "version": "1.0.0",
        "purl": "pkg:maven/org.example/team-test-lib@1.0.0",
        "bom-ref": TEAM_TEST_LIB_UUID,
        "uuid": TEAM_TEST_LIB_UUID,
    }

    comp_commons_text = {
        "type": "library",
        "name": "commons-text",
        "version": "1.9",
        "purl": "pkg:maven/org.apache.commons/commons-text@1.9",
        "bom-ref": COMMONS_TEXT_UUID,
        "uuid": COMMONS_TEXT_UUID,
    }

    components = [
        comp_lib_a,
        comp_lib_b,
        comp_lib_c,
        comp_log4j,
        comp_jackson,
        comp_netty,
        comp_team_test,
        comp_commons_text,
    ]

    # Dependencies (The Chain)
    # Root -> Lib A, Lib C, Jackson, Netty, Team Test Lib
    dep_root = {
        "ref": project_uuid,
        "dependsOn": [
            lib_a_uuid,
            lib_c_uuid,
            JACKSON_UUID,
            NETTY_UUID,
            TEAM_TEST_LIB_UUID,
        ],
    }
    # Lib A -> Lib B, Commons Text
    dep_a = {
        "ref": lib_a_uuid,
        "dependsOn": [lib_b_uuid, COMMONS_TEXT_UUID],
    }
    # Lib B -> log4j
    dep_b = {
        "ref": lib_b_uuid,
        "dependsOn": [COMPONENT_UUID],
    }
    # Lib C -> log4j
    dep_c = {
        "ref": lib_c_uuid,
        "dependsOn": [COMPONENT_UUID],
    }
    # log4j -> []
    dep_log4j = {
        "ref": COMPONENT_UUID,
        "dependsOn": [],
    }
    # Jackson -> []
    dep_jackson = {
        "ref": JACKSON_UUID,
        "dependsOn": [],
    }
    # Netty -> []
    dep_netty = {
        "ref": NETTY_UUID,
        "dependsOn": [],
    }
    # Team Test Lib -> []
    dep_team_test = {
        "ref": TEAM_TEST_LIB_UUID,
        "dependsOn": [],
    }
    # Commons Text -> [] (transitive via lib_a which is NOT team-mapped)
    dep_commons_text = {
        "ref": COMMONS_TEXT_UUID,
        "dependsOn": [],
    }

    dependencies = [
        dep_root,
        dep_a,
        dep_b,
        dep_c,
        dep_log4j,
        dep_jackson,
        dep_netty,
        dep_team_test,
        dep_commons_text,
    ]

    # Minimal valid CycloneDX BOM
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {"component": metadata_component},
        "components": components,
        "dependencies": dependencies,
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
    if key not in mock_analysis:
        mock_analysis[key] = {
            "analysisState": "NOT_SET",
            "isSuppressed": False,
            "analysisDetails": "",
            "analysisComments": [],
        }

    mock_analysis[key]["analysisState"] = update.analysisState
    mock_analysis[key]["isSuppressed"] = update.isSuppressed
    if update.analysisDetails is not None:
        mock_analysis[key]["analysisDetails"] = update.analysisDetails
    if update.analysisJustification:
        mock_analysis[key]["analysisJustification"] = update.analysisJustification
    if update.comment:
        # In D-T, comments are usually a list.
        if "analysisComments" not in mock_analysis[key]:
            mock_analysis[key]["analysisComments"] = []

        # Add to the comments list (which is what DTVP reads)
        mock_analysis[key]["analysisComments"].append(
            {"comment": update.comment, "timestamp": int(time.time() * 1000)}
        )

        # Also append to details for backward compatibility in the text view if needed
        if "analysisDetails" not in mock_analysis[key]:
            mock_analysis[key]["analysisDetails"] = ""
        mock_analysis[key]["analysisDetails"] += f"\n\n[Comment] {update.comment}"

    return mock_analysis[key]


@app.get("/.well-known/openid-configuration")
def openid_configuration(request: Request):
    base_url = str(request.base_url).rstrip("/")
    return {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/auth/authorize",
        "token_endpoint": f"{base_url}/auth/token",
        "userinfo_endpoint": f"{base_url}/auth/userinfo",
        "jwks_uri": f"{base_url}/auth/jwks",
        "response_types_supported": ["code", "id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
        ],
        "claims_supported": ["sub", "preferred_username", "email", "name"],
    }


@app.get("/auth/authorize", response_class=HTMLResponse)
def authorize(
    client_id: str,
    redirect_uri: str,
    state: Optional[str] = None,
    scope: str = "openid",
    response_type: str = "code",
):
    return f"""
    <html>
        <head>
            <title>Mock Login (Mock Service)</title>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-gray-900 text-white flex items-center justify-center h-screen">
            <div class="bg-gray-800 p-8 rounded-lg shadow-xl w-96 border border-gray-700">
                <h1 class="text-2xl font-bold mb-6 text-center text-blue-400">Mock SSO Login</h1>
                <p class="text-gray-400 mb-8 text-center text-sm">Select a user role to simulate SSO authentication.</p>
                <div class="space-y-4">
                    <form action="/auth/authorize" method="POST">
                        <input type="hidden" name="redirect_uri" value="{redirect_uri}">
                        <input type="hidden" name="state" value="{state or ""}">
                        <input type="hidden" name="username" value="analyst">
                        <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-4 rounded transition-colors duration-200">
                            Login as Analyst
                        </button>
                    </form>
                    <form action="/auth/authorize" method="POST">
                        <input type="hidden" name="redirect_uri" value="{redirect_uri}">
                        <input type="hidden" name="state" value="{state or ""}">
                        <input type="hidden" name="username" value="reviewer">
                        <button type="submit" class="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-3 px-4 rounded transition-colors duration-200">
                            Login as Reviewer
                        </button>
                    </form>
                </div>
                <div class="mt-8 pt-6 border-t border-gray-700 text-center">
                   <p class="text-xs text-gray-500 italic">This page is served by the Dependency-Track Mock Service</p>
                </div>
            </div>
        </body>
    </html>
    """


@app.post("/auth/authorize")
def authorize_post(
    username: str = Form(...),
    redirect_uri: str = Form(...),
    state: str = Form(""),
):
    # Simulated auth code
    code = f"mock_code_{username}_{int(time.time())}"
    sep = "&" if "?" in redirect_uri else "?"
    url = f"{redirect_uri}{sep}code={code}"
    if state:
        url += f"&state={state}"
    return RedirectResponse(url=url, status_code=303)


@app.post("/auth/token")
def token(
    code: str = Form(...),
    grant_type: str = Form(...),
    redirect_uri: str = Form(...),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None),
):
    # Extract username from code
    username = "user"
    if "mock_code_" in code:
        username = code.split("_")[2]

    # Create a dummy JWT (signed with something simple or just unverified)
    # The production code uses jwt.get_unverified_claims, so we don't need a real signature.
    import jose.jwt as jose_jwt

    id_token = jose_jwt.encode(
        {
            "sub": username,
            "preferred_username": username,
            "name": username.capitalize(),
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        },
        "mock_secret",
        algorithm="HS256",
    )

    return {
        "access_token": "mock_access_token",
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": 3600,
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8081)
