import requests
import time
import base64
import os
import sys
import subprocess

# Configuration
DT_URL = os.environ.get("DT_URL", "http://dtrack-apiserver:8081")
ADMIN_USER = os.environ.get("DT_ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("DT_ADMIN_PASS", "admin")  # Default DT password


def preseed_admin_via_db():
    print("Preseeding admin password and disabling force change via DB...")
    # SQL to set password to 'admin' (BCrypt hash) and disable force change
    # Hash for 'admin': $2a$10$DQxsLp6ynhiXJh.Xj70QU.u3uXcCAllzTCupqKKGKBPs0jcpX6g/.
    hash_val = "$2a$10$DQxsLp6ynhiXJh.Xj70QU.u3uXcCAllzTCupqKKGKBPs0jcpX6g/."
    sql = f'UPDATE "MANAGEDUSER" SET "PASSWORD" = \'{hash_val}\', "FORCE_PASSWORD_CHANGE" = false, "NON_EXPIRY_PASSWORD" = true, "LAST_PASSWORD_CHANGE" = NOW() WHERE "USERNAME" = \'admin\';'

    try:
        # Run psql command. Environment variables (PGHOST, etc.) are already in the env.
        subprocess.run(["psql", "-c", sql], check=True)
        print("Database update successful.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Database update failed: {e}")
        return False


def wait_for_dt():
    print(f"Waiting for Dependency-Track at {DT_URL}...")
    for i in range(120):  # Increased wait
        try:
            resp = requests.get(f"{DT_URL}/api/version")
            if resp.status_code == 200:
                print("Dependency-Track is ready!")
                return True
        except Exception:
            pass
        time.sleep(5)
    print("Timed out waiting for Dependency-Track.")
    return False


def login():
    print("Logging in...")
    # Try multiple times as the auth service might start slightly after the main API
    for i in range(10):  # Increased retries
        try:
            # Try form-data first (standard) with explicit headers
            headers_form = {"Content-Type": "application/x-www-form-urlencoded"}
            resp = requests.post(
                f"{DT_URL}/api/v1/user/login",
                data=f"username={ADMIN_USER}&password={ADMIN_PASS}",
                headers=headers_form,
            )
            if resp.status_code == 200:
                print("Logged in successfully (form-data).")
                return resp.text

            # Try JSON next
            headers_json = {"Content-Type": "application/json"}
            resp = requests.post(
                f"{DT_URL}/api/v1/user/login",
                json={"username": ADMIN_USER, "password": ADMIN_PASS},
                headers=headers_json,
            )
            if resp.status_code == 200:
                print("Logged in successfully (JSON).")
                return resp.text

            print(f"Login attempt {i + 1} failed: {resp.status_code} {resp.text}")
        except Exception as e:
            print(f"Login effort {i + 1} errored: {e}")

        time.sleep(5)

    return None


def create_automation_team(token):
    print("Creating Automation team...")
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # Check if team exists
    resp = requests.get(f"{DT_URL}/api/v1/team", headers=headers)
    teams = resp.json()
    team_uuid = None
    for team in teams:
        if team["name"] == "Automation":
            print("Automation team already exists.")
            team_uuid = team["uuid"]
            break

    if not team_uuid:
        # Create team
        resp = requests.post(
            f"{DT_URL}/api/v1/team", headers=headers, json={"name": "Automation"}
        )
        team_uuid = resp.json()["uuid"]

    # Assign permissions (added BOM_UPLOAD and SYSTEM_CONFIGURATION for safety)
    permissions = [
        "VULNERABILITY_ANALYSIS",
        "PROJECT_CREATION_UPLOAD",
        "VIEW_PORTFOLIO",
        "PORTFOLIO_MANAGEMENT",
        "BOM_UPLOAD",
    ]
    for perm in permissions:
        requests.post(
            f"{DT_URL}/api/v1/permission/{perm}/team/{team_uuid}", headers=headers
        )

    # Return or create API key
    resp = requests.get(f"{DT_URL}/api/v1/team", headers=headers)
    teams = resp.json()
    for team in teams:
        if team["uuid"] == team_uuid and team["apiKeys"]:
            return team["apiKeys"][0]["key"]

    return create_api_key(token, team_uuid)


def create_api_key(token, team_uuid):
    print("Creating API Key...")
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    resp = requests.put(f"{DT_URL}/api/v1/team/{team_uuid}/key", headers=headers)
    return resp.text


def upload_bom(api_key, project_name, project_version, bom_path):
    print(f"Uploading BOM for {project_name} v{project_version}...")
    with open(bom_path, "rb") as f:
        bom_data = base64.b64encode(f.read()).decode("utf-8")

    headers = {"X-Api-Key": api_key, "Content-Type": "application/json"}
    payload = {
        "projectName": project_name,
        "projectVersion": project_version,
        "autoCreate": True,
        "bom": bom_data,
    }
    resp = requests.put(f"{DT_URL}/api/v1/bom", headers=headers, json=payload)
    if resp.status_code == 200:
        print("BOM uploaded successfully. Token:", resp.json()["token"])
    else:
        print(f"BOM upload failed: {resp.status_code} {resp.text}")


def main():
    if not wait_for_dt():
        sys.exit(1)

    # Extra wait to ensure DB and Auth are fully ready
    time.sleep(10)

    # Preseed via DB before trying to login
    preseed_admin_via_db()

    token = login()
    if not token:
        print(
            "Please ensure Dependency-Track is initialized and admin password is set to 'admin'."
        )
        sys.exit(1)

    api_key = create_automation_team(token)
    print(f"SECRET_API_KEY={api_key}")

    # Wait a bit for DT to settle
    time.sleep(5)

    # Upload sample BOMs
    bom_file = os.path.join(os.path.dirname(__file__), "sample_bom.json")
    upload_bom(api_key, "Demo Project", "1.0.0", bom_file)
    upload_bom(api_key, "Demo Project", "2.0.0", bom_file)

    # Write the API key to a file so it can be picked up by the dtvp service
    with open("/shared/dt_api_key.txt", "w") as f:
        f.write(api_key)

    print("Seeding completed successfully!")


if __name__ == "__main__":
    main()
