CREATE TABLE IF NOT EXISTS code_analysis_assessment_metadata (
    analysis_run_id TEXT PRIMARY KEY,
    metadata_version INTEGER NOT NULL DEFAULT 1,
    has_assessment INTEGER NOT NULL DEFAULT 0,
    vuln_id_lower TEXT NOT NULL DEFAULT '',
    project_names_json TEXT NOT NULL DEFAULT '[]',
    component_names_json TEXT NOT NULL DEFAULT '[]',
    scan_target_lower TEXT NOT NULL DEFAULT '',
    source_kind TEXT NOT NULL DEFAULT 'unknown',
    assessment_data_json TEXT NOT NULL DEFAULT '{}',
    record_data_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_code_analysis_assessment_metadata_vuln
ON code_analysis_assessment_metadata (
    has_assessment,
    vuln_id_lower,
    source_kind,
    analysis_run_id
);

CREATE INDEX IF NOT EXISTS idx_code_analysis_assessment_metadata_target
ON code_analysis_assessment_metadata (
    has_assessment,
    scan_target_lower,
    analysis_run_id
);
