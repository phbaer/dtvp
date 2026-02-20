from fastapi import FastAPI, Request, Response, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
from typing import Optional
import uvicorn
import time
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
PROJECT_V2_UUID = "4fa85f64-5717-4562-b3fc-2c963f66afa7"
LIB_UUID = "5fa85f64-5717-4562-b3fc-2c963f66afa8"
LIB_V2_UUID = "6fa85f64-5717-4562-b3fc-2c963f66afa9"

COMPONENT_UUID = "c253b708-3012-4277-8461-893bd5cd61e1"
VULN_UUID_1 = "d9401347-1941-4c12-8700-1c0563821017"  # CVE-2021-44228 (Log4Shell)
VULN_UUID_2 = "e5781a7b-0346-4927-991c-7033580539f5"  # Generic Vuln
VULN_JACKSON_UUID = "f6781a7b-0346-4927-991c-7033580539f6"  # CVE-2019-12384
VULN_NETTY_UUID = "a7781a7b-0346-4927-991c-7033580539f7"  # CVE-2021-21290

JACKSON_UUID = "b253b708-3012-4277-8461-893bd5cd61e2"
NETTY_UUID = "d253b708-3012-4277-8461-893bd5cd61e3"
TEAM_TEST_LIB_UUID = "7fa85f64-5717-4562-b3fc-2c963f66afb0"
VULN_UUID_TEAM = "f6781a7b-0346-4927-991c-7033580539f8"

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
    VULN_JACKSON_UUID: {
        "uuid": VULN_JACKSON_UUID,
        "vulnId": "CVE-2019-12384",
        "source": "NVD",
        "severity": "HIGH",
        "cvssV3BaseScore": 8.1,
        "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "Jackson-databind deserialization vulnerability",
        "recommendation": "Upgrade jackson-databind to 2.9.9.1 or later",
    },
    VULN_NETTY_UUID: {
        "uuid": VULN_NETTY_UUID,
        "vulnId": "CVE-2021-21290",
        "source": "NVD",
        "severity": "MEDIUM",
        "cvssV3BaseScore": 5.9,
        "cvssV3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "description": "Netty information disclosure vulnerability",
        "recommendation": "Upgrade Netty to 4.1.59.Final or later",
    },
    VULN_UUID_TEAM: {
        "uuid": VULN_UUID_TEAM,
        "vulnId": "CVE-2024-TEAM",
        "source": "NVD",
        "severity": "LOW",
        "cvssV3BaseScore": 2.5,
        "cvssV3Vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N",
        "description": "Team mapping test vulnerability",
        "recommendation": "Verify alternative labels.",
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
    f"{PROJECT_UUID}:{TEAM_TEST_LIB_UUID}:{VULN_UUID_TEAM}": {
        "analysisState": "NOT_AFFECTED",
        "isSuppressed": False,
        "analysisDetails": "--- [Team: Old-Label] [State: NOT_AFFECTED] [Assessed By: mock] ---\nThis was assessed using the old label.",
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
                key5, {"analysisState": "NOT_SET", "isSuppressed": False}
            ),
            "matrix": key5,
        }
        current_findings.append(finding5)
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

    components = [
        comp_lib_a,
        comp_lib_b,
        comp_log4j,
        comp_jackson,
        comp_netty,
        comp_team_test,
    ]

    # Dependencies (The Chain)
    # Root -> Lib A, Jackson, Netty, Team Test Lib
    dep_root = {
        "ref": project_uuid,
        "dependsOn": [lib_a_uuid, JACKSON_UUID, NETTY_UUID, TEAM_TEST_LIB_UUID],
    }
    # Lib A -> Lib B
    dep_a = {
        "ref": lib_a_uuid,
        "dependsOn": [lib_b_uuid],
    }
    # Lib B -> log4j
    dep_b = {
        "ref": lib_b_uuid,
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

    dependencies = [
        dep_root,
        dep_a,
        dep_b,
        dep_log4j,
        dep_jackson,
        dep_netty,
        dep_team_test,
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
