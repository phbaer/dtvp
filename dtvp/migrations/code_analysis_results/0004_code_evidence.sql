CREATE TABLE IF NOT EXISTS code_evidence (
    evidence_id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'mcp',
    project_name TEXT NOT NULL,
    project_name_lower TEXT NOT NULL,
    vuln_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    targets_json TEXT NOT NULL,
    title TEXT NOT NULL,
    body_markdown TEXT NOT NULL,
    references_json TEXT NOT NULL DEFAULT '[]',
    suggested_state TEXT,
    suggested_justification TEXT,
    confidence TEXT,
    author_username TEXT NOT NULL,
    token_id TEXT NOT NULL,
    agent_label TEXT NOT NULL,
    authority TEXT NOT NULL DEFAULT 'ANALYST',
    idempotency_key TEXT,
    created_at TEXT NOT NULL,
    withdrawn_at TEXT,
    withdrawn_by TEXT,
    withdrawn_reason TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_code_evidence_idempotency
ON code_evidence (token_id, idempotency_key)
WHERE idempotency_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_code_evidence_project
ON code_evidence (project_name_lower, created_at DESC);

CREATE TABLE IF NOT EXISTS code_evidence_vuln_ids (
    evidence_id TEXT NOT NULL,
    vuln_id_lower TEXT NOT NULL,
    PRIMARY KEY (evidence_id, vuln_id_lower)
);

CREATE INDEX IF NOT EXISTS idx_code_evidence_vuln
ON code_evidence_vuln_ids (vuln_id_lower);

CREATE TABLE IF NOT EXISTS code_evidence_applications (
    evidence_id TEXT NOT NULL,
    finding_uuid TEXT NOT NULL,
    workflow_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    applied_by TEXT NOT NULL,
    applied_at TEXT NOT NULL,
    PRIMARY KEY (evidence_id, finding_uuid)
);
