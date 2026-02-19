# Dependency Track Vulnerability Processor (DTVP)

**DTVP** is an opinionated tool for processing Dependency Track vulnerabilities. It reads all project versions of a specific project from Dependency Track, grouping vulnerabilities by Common Vulnerability ID (CVE). Users can then assess these vulnerabilities across all versions of the project and update their analysis state in bulk.

## Key Features

-   **Vulnerability Grouping**: Automatically groups identical vulnerabilities (CVEs) across all project versions.
-   **Bulk Assessment**: Assess a vulnerability once and apply the analysis to all affected versions simultaneously.
-   **Team-Specific Assessments**: Support for multiple teams (e.g., AppSec, DevOps) to provide their own assessment of a vulnerability.
-   **Mock Service**: Includes a mock Dependency-Track service for easy development and testing without a live instance.

## Tech Stack

This project is built using:

-   **Backend**: Python 3.13+, FastAPI, Uvicorn, httpx.
-   **Frontend**: Vue 3, Vite, TailwindCSS.
-   **Package Management**: `uv` (Python), `npm` (Node.js).
-   **Containerization**: Docker, Docker Compose.

## Prerequisites

Ensure you have the following installed:

-   **Python** v3.13+
-   **Node.js** v22.0.0+
-   **Docker** & **Docker Compose** (or Podman)
-   **uv** (for Python package management)
-   **pm2** (for running the mock service)

## Getting Started

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/phbaer/dtvp.git
    cd dtvp
    ```

2.  **Install Backend Dependencies:**
    ```bash
    uv sync --dev
    ```

3.  **Install Frontend Dependencies:**
    ```bash
    cd frontend
    npm ci
    cd ..
    ```

4.  **Configure Environment:**
    Copy the example environment file:
    ```bash
    cp .env.dist .env
    ```
    Edit `.env` with your specific configuration. See the [Environment Variables](#environment-variables) section below for details.

## Running the Application

### Development Mode (Manual)

To run the application manually for development:

1.  **Start the Mock Service (Optional):**
    If you don't have a live Dependency-Track instance, start the mock service:
    ```bash
    pm2 start ecosystem.config.js --only mock-dt
    ```
    This serves a mock Dependency-Track instance at `http://localhost:8081`.

2.  **Start the Backend:**
    ```bash
    uv run uvicorn main:app --reload --port 8000
    ```

3.  **Start the Frontend:**
    Open a new terminal:
    ```bash
    cd frontend
    npm run dev
    ```
    Access the frontend at `http://localhost:5173`.

4.  **Stop the Mock Service:**
    When finished:
    ```bash
    pm2 delete mock-dt
    ```

### Production Mode (Docker)

To run the application using Docker Compose:

1.  **Configure Docker Compose:**
    ```bash
    cp compose.yml.dist compose.yml
    # Edit .env and compose.yml with your specific configuration
    ```

2.  **Start Services:**
    ```bash
    docker compose up -d
    ```

## Testing

### Backend Tests
Run unit tests using `pytest`:

```bash
uv run pytest
```

### Frontend Tests
Run unit tests using `vitest`:

```bash
cd frontend
npm run test:unit
```

### End-to-End (UI) Tests
The E2E tests use Playwright and require the full stack (backend + frontend + mock services) to be running or orchestrated.

```bash
# Start all services
pm2 start ecosystem.config.js

# Run E2E tests
cd frontend
npm run test:ui

# Clean up
cd ..
pm2 stop ecosystem.config.js
```

## Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `DTVP_API_KEY` | Dependency Track API key | Required |
| `DTVP_API_URL` | Dependency Track Base URL | Required |
| `DTVP_OIDC_AUTHORITY` | OIDC Authority URL | Required |
| `DTVP_OIDC_CLIENT_ID` | OIDC Client ID | Required |
| `DTVP_OIDC_CLIENT_SECRET` | OIDC Client Secret | Required |
| `DTVP_SESSION_SECRET_KEY` | Secret key for session encryption | Required |
| `DTVP_CONTEXT_PATH` | Application context path | `/` |
| `DTVP_FRONTEND_URL` | Frontend URL | `http://localhost:8000` |
| `DTVP_OIDC_REDIRECT_URI` | OIDC Redirect URI | `http://localhost:8000/auth/callback` |

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
