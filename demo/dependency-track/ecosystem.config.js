const path = require("path");

const root = path.resolve(__dirname, "../..");

module.exports = {
    apps: [
        {
            name: "mock-dt",
            script: "uv",
            args: "run uvicorn mock_dt:app --host 127.0.0.1 --port 8081",
            cwd: path.join(root, "test_setup"),
            interpreter: "none",
            env: {
                PYTHONUNBUFFERED: "1"
            }
        },
        {
            name: "mock-tmrescore",
            script: "uv",
            args: "run uvicorn mock_tmrescore:app --host 127.0.0.1 --port 8090",
            cwd: path.join(root, "test_setup"),
            interpreter: "none",
            env: {
                PYTHONUNBUFFERED: "1"
            }
        },
        {
            name: "mock-code-analysis",
            script: "uv",
            args: "run uvicorn mock_code_analysis:app --host 127.0.0.1 --port 8095",
            cwd: path.join(root, "test_setup"),
            interpreter: "none",
            env: {
                PYTHONUNBUFFERED: "1"
            }
        },
        {
            name: "dtvp-backend",
            script: "uv",
            args: "run uvicorn dtvp.boot:app --host 0.0.0.0 --port 8000",
            cwd: root,
            interpreter: "none",
            env: {
                DTVP_ENVIRONMENT: "development",
                DTVP_VULNERABILITY_BACKEND_ID: "dependency-track-mock",
                DTVP_VULNERABILITY_BACKEND_TYPE: "dependency-track",
                DTVP_VULNERABILITY_BACKEND_LABEL: "Dependency-Track Mock",
                DTVP_VULNERABILITY_BACKEND_API_URL: "http://127.0.0.1:8081",
                DTVP_VULNERABILITY_BACKEND_API_KEY: "mock_key",
                DTVP_OIDC_AUTHORITY: "http://127.0.0.1:8081",
                DTVP_OIDC_CLIENT_ID: "mock_id",
                DTVP_OIDC_CLIENT_SECRET: "mock_secret",
                DTVP_SESSION_SECRET_KEY: "local-development-session-secret-1234567890abcdef",
                DTVP_OIDC_REDIRECT_URI: "http://localhost:5173/auth/callback",
                DTVP_FRONTEND_URL: "http://localhost:5173",
                DTVP_TMRESCORE_URL: "http://127.0.0.1:8090",
                DTVP_CODE_ANALYSIS_URL: "http://127.0.0.1:8095",
                PYTHONUNBUFFERED: "1"
            }
        },
        {
            name: "dtvp-frontend",
            script: "npm",
            args: "run dev -- --host 0.0.0.0",
            cwd: path.join(root, "frontend"),
            interpreter: "none"
        }
    ]
};
