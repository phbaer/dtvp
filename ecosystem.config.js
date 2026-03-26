module.exports = {
    apps: [
        {
            name: "mock-dt",
            script: "uv",
            args: "run uvicorn mock_dt:app --host 127.0.0.1 --port 8081",
            cwd: "test_setup",
            interpreter: "none",
            env: {
                PYTHONUNBUFFERED: "1"
            }
        },
        {
            name: "dtvp-backend",
            script: "uv",
            args: "run uvicorn main:app --host 0.0.0.0 --port 8000",
            interpreter: "none",
            env: {
                DTVP_DT_API_URL: "http://127.0.0.1:8081",
                DTVP_DT_API_KEY: "mock_key",
                DTVP_OIDC_AUTHORITY: "http://127.0.0.1:8081",
                DTVP_OIDC_CLIENT_ID: "mock_id",
                DTVP_OIDC_CLIENT_SECRET: "mock_secret",
                DTVP_OIDC_REDIRECT_URI: "http://localhost:5173/auth/callback",
                DTVP_FRONTEND_URL: "http://localhost:5173",
                PYTHONUNBUFFERED: "1"
            }
        },
        {
            name: "dtvp-frontend",
            script: "npm",
            args: "run dev -- --host 0.0.0.0",
            cwd: "frontend",
            interpreter: "none"
        }
    ]
};
