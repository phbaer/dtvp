# Test Setup for VPDT

This directory contains a Docker Compose setup to spin up a local Dependency-Track instance populated with test data.

## Prerequisites

- Docker or Podman
- Docker Compose or podman-compose

## Usage

1.  Start the environment:
    ```bash
    cd test_setup
    podman-compose up
    ```
    This will:
    - Start Postgres, Dependency-Track API Server, and Dependency-Track Frontend.
    - Run an initialization container (`init-dtrack`).
    - The initialization script will wait for the API to be ready, then:
        - Change the default admin password to `admin` (effectively keeping the default).
        - Create a team named `Automation`.
        - Generate an **API Key**.
        - Create a project named `Vulnerable Project`.
        - Upload a CycloneDX BOM containing `log4j-core` 2.14.1 and the Log4Shell vulnerability (CVE-2021-44228).
    - Watch the logs for the `init-dtrack` service to see the generated **API Key**.

2.  Access Dependency-Track:
    - Frontend: [http://localhost:8080](http://localhost:8080)
    - API: [http://localhost:8081](http://localhost:8081)
    - Credentials: `admin` / `admin`

3.  Configure `vpdt`:
    - Use the API Key output in the logs in your `.env` file or environment variables for `vpdt`.
    - `DTVP_DT_API_KEY=<generated_key>`
    - `DTVP_DT_API_URL=http://localhost:8081`

4.  Stop the environment:
    ```bash
    podman-compose down -v
    ```

## Files

- `docker-compose.yml`: Defines the services.
- `init_dt.py`: Python script performing the setup/population.
