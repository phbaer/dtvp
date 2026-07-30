CREATE TABLE assessment_state (
    project_uuid TEXT NOT NULL,
    component_uuid TEXT NOT NULL,
    vulnerability_uuid TEXT NOT NULL,
    revision INTEGER NOT NULL,
    analysis_state TEXT NOT NULL,
    analysis_details TEXT NOT NULL,
    suppressed INTEGER NOT NULL,
    sync_status TEXT NOT NULL,
    update_id TEXT,
    last_error TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project_uuid, component_uuid, vulnerability_uuid)
);

CREATE TABLE assessment_outbox (
    project_uuid TEXT NOT NULL,
    component_uuid TEXT NOT NULL,
    vulnerability_uuid TEXT NOT NULL,
    revision INTEGER NOT NULL,
    update_id TEXT NOT NULL UNIQUE,
    payload_json TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project_uuid, component_uuid, vulnerability_uuid)
);

CREATE INDEX assessment_outbox_due_idx
ON assessment_outbox (next_attempt_at, updated_at);
