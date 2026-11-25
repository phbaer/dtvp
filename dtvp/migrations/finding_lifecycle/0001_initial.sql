-- River's record of what happened to findings: when the source reported
-- them, when it stopped and why. Not source data: it cannot be imported
-- again, so it lives next to the assessment records.

CREATE TABLE finding_presence (
    project_uuid TEXT NOT NULL,
    component_uuid TEXT NOT NULL,
    vulnerability_uuid TEXT NOT NULL,
    vuln_id TEXT,
    component_name TEXT,
    component_version TEXT,
    component_purl TEXT,
    -- Package URL without version, else the name, lower case.
    component_identity TEXT,
    first_seen_at TEXT NOT NULL,
    -- 'reported' or 'gone'
    status TEXT NOT NULL,
    gone_at TEXT,
    last_seen_at TEXT,
    -- 'replaced', 'component_removed', 'no_longer_matched', 'undetermined',
    -- 'missing_at_export'
    gone_reason TEXT,
    successor_component_uuid TEXT,
    -- 'carried', 'conflict', 'own_assessment' or NULL
    carry_over TEXT,
    returned_at TEXT,
    PRIMARY KEY (project_uuid, component_uuid, vulnerability_uuid)
);

CREATE INDEX finding_presence_status_idx
ON finding_presence (project_uuid, status);
CREATE INDEX finding_presence_vulnerability_idx
ON finding_presence (project_uuid, vulnerability_uuid);

-- The last read of each project's findings.
CREATE TABLE finding_reads (
    project_uuid TEXT PRIMARY KEY,
    -- When the read started; for a finding gone at the next read, when it
    -- was last known to be reported.
    read_at TEXT NOT NULL,
    went_json TEXT NOT NULL,
    returned INTEGER NOT NULL,
    carried_over INTEGER NOT NULL,
    not_carried INTEGER NOT NULL
);

CREATE TABLE finding_lifecycle_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
