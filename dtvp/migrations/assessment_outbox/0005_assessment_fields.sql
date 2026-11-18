-- The assessment of a finding as atomic fields, read from the text markup
-- when a value is adopted or saved. One row per finding and one per team.
CREATE TABLE assessment_fields (
    project_uuid TEXT NOT NULL,
    component_uuid TEXT NOT NULL,
    vulnerability_uuid TEXT NOT NULL,
    revision INTEGER NOT NULL,
    -- Digest of the text these fields were read from.
    details_digest TEXT NOT NULL,
    state TEXT NOT NULL,
    suppressed INTEGER NOT NULL,
    pending_review INTEGER NOT NULL,
    rescored_score REAL,
    rescored_vector TEXT,
    -- Free text outside the team blocks, without markers. Kept as written.
    free_text TEXT NOT NULL,
    -- structured: has team blocks; text: plain or legacy text; empty.
    form TEXT NOT NULL,
    PRIMARY KEY (project_uuid, component_uuid, vulnerability_uuid)
);

CREATE TABLE assessment_team_fields (
    project_uuid TEXT NOT NULL,
    component_uuid TEXT NOT NULL,
    vulnerability_uuid TEXT NOT NULL,
    position INTEGER NOT NULL,
    team TEXT NOT NULL,
    state TEXT NOT NULL,
    justification TEXT,
    assessed_by TEXT,
    reviewed_by TEXT,
    assessed_at_ms INTEGER,
    rescored_score REAL,
    rescored_vector TEXT,
    ssvc TEXT,
    ssvc_details TEXT,
    assigned_json TEXT NOT NULL,
    historical INTEGER NOT NULL,
    copied_from TEXT,
    details TEXT NOT NULL,
    PRIMARY KEY (project_uuid, component_uuid, vulnerability_uuid, position)
);

CREATE INDEX assessment_team_fields_team_idx
ON assessment_team_fields (team, state);
