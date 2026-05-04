# Test Setup for DTVP

This directory contains the mock service implementations used by the local pm2 development stack.

- `mock_dt.py` provides the in-memory Dependency-Track API.
- `mock_tmrescore.py` provides the in-memory tmrescore API.
- `mock_code_analysis.py` provides locally hosted service mocks for analysis integrations.

## Run the Local Mock Stack

The recommended local workflow is to start the mock services via `pm2` using the repository-wide `ecosystem.config.js`:

```bash
pm2 start ecosystem.config.js --update-env
```

The mock services are available at:

- Dependency-Track API: `http://127.0.0.1:8081`
- TMRescore API/UI: `http://127.0.0.1:8090`
- Code Analysis API: `http://127.0.0.1:8095`

To stop the stack:

```bash
pm2 delete mock-dt mock-tmrescore mock-code-analysis
```

## Direct Startup

If you want to run an individual mock service directly without `pm2`, use `uv` from the `test_setup` directory, for example:

```bash
cd test_setup
uv run uvicorn mock_dt:app --host 127.0.0.1 --port 8081
```

## Files

- `mock_dt.py`: In-memory Dependency-Track mock.
- `mock_tmrescore.py`: In-memory tmrescore mock.
- `mock_agentizer.py`: In-memory agentizer mock.
- `mock_code_analysis.py`: In-memory code analysis mock.
