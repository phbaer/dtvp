# Test Setup for VPDT

This directory contains small local test services used by DTVP development.

- `mock_dt.py` provides the in-memory Dependency-Track API used by the pm2 workflow.
- `mock_tmrescore.py` provides the in-memory tmrescore API used by the threat-model integration.
- `docker-compose.yml` is a small container wrapper around both mocks.

## Prerequisites

- Docker or Podman
- Docker Compose or podman-compose

## Mock Dependency-Track Container

1.  Start the environment:
    ```bash
    cd test_setup
    podman-compose up
    ```
        This starts:
        - mock Dependency-Track on port `8081`
        - mock tmrescore on port `8090`

2.  Access the mock APIs:
    - Dependency-Track API: [http://localhost:8081](http://localhost:8081)
    - TMRescore API/UI: [http://localhost:8090/ui](http://localhost:8090/ui)

3.  Configure DTVP:
    - `DTVP_DT_API_KEY=mock_key`
    - `DTVP_DT_API_URL=http://localhost:8081`
    - `DTVP_TMRESCORE_URL=http://localhost:8090`

4.  Stop the environment:
    ```bash
    podman-compose down -v
    ```

## Files

- `docker-compose.yml`: Defines the services.
- `mock_dt.py`: In-memory Dependency-Track mock.
- `mock_tmrescore.py`: In-memory tmrescore mock.

## Mock TMRescore

The tmrescore mock is primarily intended for the pm2-based local stack, but it can also be run directly:

```bash
cd test_setup
uv run uvicorn mock_tmrescore:app --host 127.0.0.1 --port 8090
```

Useful endpoints:

- `GET /health`
- `GET /ui`
- `POST /api/v1/sessions`
- `POST /api/v1/sessions/{session_id}/inventory`
- `GET /api/v1/sessions/{session_id}/results/json`
- `GET /api/v1/sessions/{session_id}/results/vex`
- `GET /api/v1/sessions/{session_id}/outputs/{filename}`

Minimal example flow:

1. Create a session with an application name and version.
2. Upload a TM7 file and CycloneDX SBOM to the inventory endpoint.
3. Read the returned analysis result.
4. Download the generated mock artifacts from the outputs endpoints.
