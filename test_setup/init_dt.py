import requests
import time
import os
import sys
import json

DT_API_URL = os.environ.get("DT_API_URL", "http://dtrack-apiserver:8080")
NEW_ADMIN_PASS = os.environ.get("NEW_ADMIN_PASS", "admin")


def wait_for_api():
    print(f"Waiting for API at {DT_API_URL}...")
    while True:
        try:
            r = requests.get(f"{DT_API_URL}/api/version")
            if r.status_code == 200:
                print("API is up!")
                return
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(5)


def login(username, password):
    url = f"{DT_API_URL}/api/v1/user/login"
    data = {"username": username, "password": password}
    r = requests.post(url, data=data)
    if r.status_code == 200:
        return r.text
    print(f"Login failed for user '{username}': {r.status_code} {r.text}")
    return None


def change_password(current_pass, new_pass):
    url = f"{DT_API_URL}/api/v1/user/forceChangePassword"
    data = {
        "username": "admin",
        "password": current_pass,
        "newPassword": new_pass,
        "confirmPassword": new_pass,
    }
    r = requests.post(url, data=data)
    return r.status_code == 200


def get_headers(token):
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def main():
    wait_for_api()

    # Initial Login
    # Initial Login with Retry
    print("Attempting initial login...")
    token = None
    retries = 10
    for i in range(retries):
        token = login("admin", "admin")
        if token:
            break
        print(f"Waiting for admin user to be ready... ({i + 1}/{retries})")
        time.sleep(3)

    if token:
        print("Initial login successful. Changing password...")
        if change_password("admin", NEW_ADMIN_PASS):
            print("Password changed successfully.")
            token = login("admin", NEW_ADMIN_PASS)
        else:
            print("Failed to change password (maybe already changed?).")
    else:
        print("Initial login failed. Trying with new password...")
        token = login("admin", NEW_ADMIN_PASS)
        if not token:
            print("Could not login. Exiting.")
            sys.exit(1)

    headers = get_headers(token)

    # Check if we removed the 'Force Change Password' requirement just in case?
    # Usually forceChangePassword handles it.

    # Create Team
    print("Creating Automation Team...")
    team_payload = {"name": "Automation"}
    # Check if team exists
    r = requests.get(f"{DT_API_URL}/api/v1/team", headers=headers)
    teams = r.json()
    automation_team = next((t for t in teams if t["name"] == "Automation"), None)

    if not automation_team:
        r = requests.put(
            f"{DT_API_URL}/api/v1/team", json=team_payload, headers=headers
        )
        if r.status_code == 201:
            automation_team = r.json()
            print("Team created.")
        else:
            print(f"Failed to create team: {r.text}")
            sys.exit(1)
    else:
        print("Team already exists.")

    # Generate API Key
    print("Generating API Key...")
    if not automation_team.get("apiKeys"):
        r = requests.put(
            f"{DT_API_URL}/api/v1/team/{automation_team['uuid']}/key", headers=headers
        )
        if r.status_code == 201:
            api_key = r.json()["key"]
            print(f"API Key generated: {api_key}")
        else:
            print(f"Failed to generate key: {r.text}")
            # Try to fetch existing keys if any (GET /api/v1/team returns them)
            # Re-fetch team
            r = requests.get(f"{DT_API_URL}/api/v1/team", headers=headers)
            automation_team = next(
                (t for t in r.json() if t["name"] == "Automation"), None
            )
            if automation_team and automation_team.get("apiKeys"):
                api_key = automation_team["apiKeys"][0]["key"]
                print(f"Using existing API Key: {api_key}")
            else:
                sys.exit(1)
    else:
        api_key = automation_team["apiKeys"][0]["key"]
        print(f"Using existing API Key: {api_key}")

    # Add permissions to team?
    # By default, new teams might have no permissions.
    # API Key needs permissions to upload BOMs, read projects, etc.
    # Let's grant all permissions.
    print("Granting permissions...")
    r = requests.get(f"{DT_API_URL}/api/v1/permission", headers=headers)
    all_permissions = r.json()
    for perm in all_permissions:
        requests.post(
            f"{DT_API_URL}/api/v1/permission/{perm['name']}/team/{automation_team['uuid']}",
            headers=headers,
        )

    # Create Project
    print("Creating Vulnerable Project...")
    project_payload = {
        "name": "Vulnerable Project",
        "version": "1.0.0",
        "classifier": "APPLICATION",
    }
    # Check if exists
    r = requests.get(
        f"{DT_API_URL}/api/v1/project?name=Vulnerable Project", headers=headers
    )
    project_uuid = None
    if r.status_code == 200 and r.json():
        project = next((p for p in r.json() if p["version"] == "1.0.0"), None)
        if project:
            project_uuid = project["uuid"]
            print("Project already exists.")

    if not project_uuid:
        r = requests.put(
            f"{DT_API_URL}/api/v1/project", json=project_payload, headers=headers
        )
        if r.status_code == 201:
            project_uuid = r.json()["uuid"]
            print("Project created.")
        else:
            print(f"Failed to create project: {r.text}")
            sys.exit(1)

    # Upload BOM with Vulnerability
    print("Uploading BOM with Vulnerabilities...")
    bom_json = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "log4j-core",
                "group": "org.apache.logging.log4j",
                "version": "2.14.1",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                "bom-ref": "log4j",
            }
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2021-44228",
                "source": {
                    "name": "NVD",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                },
                "ratings": [
                    {
                        "source": {"name": "NVD"},
                        "score": 10.0,
                        "severity": "critical",
                        "method": "CVSSv31",
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    }
                ],
                "affects": [{"ref": "log4j"}],
            }
        ],
    }

    # Needs to be multipart upload encoded as base64?
    # API: POST /api/v1/bom
    # Body: multipart/form-data
    # project: uuid
    # bom: file

    files = {"bom": ("bom.json", json.dumps(bom_json), "application/json")}
    data = {"project": project_uuid}

    # Use the API Key for this upload to test it? Or just use admin token.
    # Let's use admin token for setup.
    # IMPORTANT: Do not set Content-Type header manually, let requests do it for multipart
    upload_headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    r = requests.post(
        f"{DT_API_URL}/api/v1/bom",
        files=files,
        data=data,
        headers=upload_headers,
    )
    if r.status_code == 200:
        print(
            "BOM uploaded successfully. Token (for reference): "
            + r.json().get("token", "")
        )
    else:
        print(f"Failed to upload BOM: {r.status_code} {r.text}")

    print("\n---------------------------------------------------")
    print("SETUP COMPLETE.")
    print(
        "Dependency-Track URL: http://localhost:8080 (Frontend) / http://localhost:8081 (API)"
    )
    print("Admin User: admin")
    print(f"Admin Pass: {NEW_ADMIN_PASS}")
    print(f"API KEY: {api_key}")
    print("---------------------------------------------------\n")


if __name__ == "__main__":
    main()
