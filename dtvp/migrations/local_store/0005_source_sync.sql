-- Per-version sync state (ADR 0004, "Sync state"). One row per project
-- version the source has listed. Digests are over what the source returned;
-- NULL means unknown, and the first read stores it without counting a change.
CREATE TABLE sync_versions (
    project_uuid TEXT PRIMARY KEY,
    product_name TEXT,
    version TEXT,
    active_in_dt INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'never_synced',
    settled_status TEXT NOT NULL DEFAULT 'never_synced',
    first_seen_at TEXT NOT NULL,
    last_attempt_at TEXT,
    last_success_at TEXT,
    last_change_at TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    next_due_at TEXT,
    last_error_class TEXT,
    last_error TEXT,
    dt_last_bom_import TEXT,
    dt_last_vuln_analysis TEXT,
    findings_digest TEXT,
    analyses_digest TEXT,
    vulns_digest TEXT,
    bom_digest TEXT,
    -- Per finding key, a hash of the analysis last read; tells which
    -- analyses changed, to classify them as echoes or changes in the source.
    analyses_index_json TEXT,
    analyses_changed_in_dt INTEGER NOT NULL DEFAULT 0,
    analyses_export_echoes INTEGER NOT NULL DEFAULT 0,
    generation INTEGER NOT NULL DEFAULT 0,
    staged_generation INTEGER,
    requested_at TEXT,
    requested_by TEXT,
    request_id TEXT
);

CREATE INDEX sync_versions_product ON sync_versions (product_name);
CREATE INDEX sync_versions_last_change ON sync_versions (last_change_at);
