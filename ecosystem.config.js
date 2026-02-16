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
            args: "run uvicorn main:app --host 127.0.0.1 --port 8000",
            interpreter: "none",
            env: {
                DTVP_DT_API_URL: "http://127.0.0.1:8081",
                DTVP_DT_API_KEY: "mock_key",
                DTVP_DEV_DISABLE_AUTH: "true",
                PYTHONUNBUFFERED: "1"
            }
        },
        {
            name: "dtvp-frontend",
            script: "npm",
            args: "run dev",
            cwd: "frontend",
            interpreter: "none"
        }
    ]
};
