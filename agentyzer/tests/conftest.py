import os
import tempfile


os.environ.setdefault("AGENTYZER_ENVIRONMENT", "test")
os.environ.setdefault(
    "AGENTYZER_SERVICE_TOKEN",
    "test-only-agentyzer-service-token-1234567890",
)
os.environ.setdefault(
    "AGENTYZER_ADMIN_TOKEN",
    "test-only-agentyzer-admin-token-123456789012",
)
os.environ.setdefault(
    "AGENTYZER_JOB_STORE_PATH",
    os.path.join(tempfile.mkdtemp(prefix="agentyzer-tests-"), "jobs.sqlite"),
)
