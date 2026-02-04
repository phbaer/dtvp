# Test Setup for VPDT

This directory contains a Docker Compose setup to spin up a local Dependency-Track instance populated with test data.

## Prerequisites

- Docker or Podman
- Docker Compose or podman-compose

## Usage

1.  Start the environment:
    ```bash
    ./start.sh
    ```
    This will:
    - Start Postgres, Dependency-Track API Server, and Dependency-Track Frontend.
    - Run an initialization script (`init_dt.py`) inside a container.
    - The initialization script will:
        - Change the default admin password to `admin12345`.
        - Create a team named `Automation`.
        - Generate an API Key for that team.
        - Create a project named `Vulnerable Project`.
        - Upload a CycloneDX BOM containing `log4j-core` 2.14.1 and the Log4Shell vulnerability (CVE-2021-44228).
    - Output the **API Key** at the end.

2.  Access Dependency-Track:
    - Frontend: [http://localhost:8080](http://localhost:8080)
    - API: [http://localhost:8081](http://localhost:8081)
    - Credentials: `admin` / `admin12345`

3.  Configure `vpdt`:
    - Use the API Key output by the script in your `.env` file or environment variables for `vpdt`.
    - `DTVP_DT_API_KEY=<generated_key>`
    - `DTVP_DT_API_URL=http://localhost:8081`

4.  Stop the environment:
    ```bash
    ./stop.sh
    ```
    (Note: This removes volumes and data. Remove `-v` in `stop.sh` if you want to persist data).

## Files

- `docker-compose.yml`: Defines the services.
- `init_dt.py`: Python script performing the setup/population.
- `start.sh`: Helper to start everything.
- `stop.sh`: Helper to teardown.
