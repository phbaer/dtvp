-- The value last known to agree with the source (base) and, while the two
-- sides disagree, the value the source reported (remote).
ALTER TABLE assessment_state ADD COLUMN base_state TEXT;
ALTER TABLE assessment_state ADD COLUMN base_details TEXT;
ALTER TABLE assessment_state ADD COLUMN base_suppressed INTEGER;
ALTER TABLE assessment_state ADD COLUMN remote_state TEXT;
ALTER TABLE assessment_state ADD COLUMN remote_details TEXT;
ALTER TABLE assessment_state ADD COLUMN remote_suppressed INTEGER;

-- A synchronized assessment is its own base. Pending ones keep an unknown
-- base until their next export or import.
UPDATE assessment_state
SET base_state = analysis_state,
    base_details = analysis_details,
    base_suppressed = suppressed
WHERE sync_status = 'synced';

-- Append-only history of every local assessment value.
CREATE TABLE assessment_revisions (
    revision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_uuid TEXT NOT NULL,
    component_uuid TEXT NOT NULL,
    vulnerability_uuid TEXT NOT NULL,
    revision INTEGER NOT NULL,
    analysis_state TEXT NOT NULL,
    analysis_details TEXT NOT NULL,
    suppressed INTEGER NOT NULL,
    origin TEXT NOT NULL,
    author TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX assessment_revisions_finding_idx
ON assessment_revisions (
    project_uuid, component_uuid, vulnerability_uuid, revision_id
);
