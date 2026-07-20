CREATE TABLE IF NOT EXISTS code_analysis_result_applications (
    analysis_run_id TEXT NOT NULL,
    finding_uuid TEXT NOT NULL,
    group_id_lower TEXT NOT NULL DEFAULT '',
    workflow_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    applied_by TEXT NOT NULL DEFAULT '',
    applied_at TEXT NOT NULL,
    payload_fingerprint TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (analysis_run_id, finding_uuid)
);

CREATE INDEX IF NOT EXISTS idx_code_analysis_result_applications_group
ON code_analysis_result_applications (group_id_lower, status, applied_at DESC);

CREATE INDEX IF NOT EXISTS idx_code_analysis_result_applications_run
ON code_analysis_result_applications (analysis_run_id, status, applied_at DESC);
