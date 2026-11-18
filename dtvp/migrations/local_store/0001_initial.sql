-- Source data imported from Dependency-Track (or another source).
-- Every table keeps the source document losslessly in payload_json; the
-- other columns exist for lookup and are derived from it.

CREATE TABLE store_metadata (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- One row per stored collection. Distinguishes "never imported" (no row)
-- from "imported and empty", and holds documents that are not a list.
CREATE TABLE source_snapshots (
    kind TEXT NOT NULL,
    project_uuid TEXT NOT NULL,
    item_count INTEGER NOT NULL,
    raw_json TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (kind, project_uuid)
);

CREATE TABLE source_projects (
    position INTEGER PRIMARY KEY,
    project_uuid TEXT,
    name TEXT,
    version TEXT,
    payload_json TEXT NOT NULL
);

CREATE INDEX source_projects_uuid_idx ON source_projects (project_uuid);
CREATE INDEX source_projects_name_idx ON source_projects (name);

CREATE TABLE source_findings (
    project_uuid TEXT NOT NULL,
    position INTEGER NOT NULL,
    component_uuid TEXT,
    vulnerability_uuid TEXT,
    vuln_id TEXT,
    severity TEXT,
    component_name TEXT,
    component_version TEXT,
    payload_json TEXT NOT NULL,
    PRIMARY KEY (project_uuid, position)
);

CREATE INDEX source_findings_identity_idx
ON source_findings (project_uuid, component_uuid, vulnerability_uuid);
CREATE INDEX source_findings_vuln_id_idx ON source_findings (vuln_id);

CREATE TABLE source_project_vulnerabilities (
    project_uuid TEXT NOT NULL,
    position INTEGER NOT NULL,
    vulnerability_uuid TEXT,
    vuln_id TEXT,
    payload_json TEXT NOT NULL,
    PRIMARY KEY (project_uuid, position)
);

CREATE INDEX source_project_vulnerabilities_vuln_id_idx
ON source_project_vulnerabilities (vuln_id);

CREATE TABLE source_boms (
    project_uuid TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- The assessment last read from or written to the source, per finding.
CREATE TABLE source_analyses (
    project_uuid TEXT NOT NULL,
    component_uuid TEXT NOT NULL,
    vulnerability_uuid TEXT NOT NULL,
    analysis_state TEXT,
    analysis_details TEXT,
    suppressed INTEGER,
    payload_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project_uuid, component_uuid, vulnerability_uuid)
);
