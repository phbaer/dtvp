CREATE TABLE IF NOT EXISTS code_analysis_results (
    analysis_run_id TEXT PRIMARY KEY,
    project_name_lower TEXT NOT NULL DEFAULT '',
    vuln_id_lower TEXT NOT NULL DEFAULT '',
    component_name_lower TEXT NOT NULL DEFAULT '',
    source_lower TEXT NOT NULL DEFAULT '',
    context_fingerprint TEXT NOT NULL DEFAULT '',
    finished_at TEXT NOT NULL DEFAULT '',
    submitted_at TEXT NOT NULL DEFAULT '',
    recorded_at TEXT NOT NULL DEFAULT '',
    record_timestamp TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS code_analysis_result_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_code_analysis_results_target
ON code_analysis_results (
    project_name_lower,
    vuln_id_lower,
    component_name_lower,
    source_lower,
    finished_at DESC,
    submitted_at DESC
);

CREATE INDEX IF NOT EXISTS idx_code_analysis_results_context
ON code_analysis_results (
    project_name_lower,
    vuln_id_lower,
    component_name_lower,
    source_lower,
    context_fingerprint,
    finished_at DESC
);
