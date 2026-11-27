ALTER TABLE code_evidence ADD COLUMN assessment_summary TEXT;
ALTER TABLE code_evidence ADD COLUMN attachments_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE code_evidence_applications RENAME TO code_evidence_applications_legacy;
CREATE TABLE code_evidence_applications (
    evidence_id TEXT NOT NULL,
    finding_uuid TEXT NOT NULL,
    team TEXT NOT NULL DEFAULT '',
    assessment_revision INTEGER NOT NULL DEFAULT -1,
    workflow_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    applied_by TEXT NOT NULL,
    applied_at TEXT NOT NULL,
    PRIMARY KEY (evidence_id, finding_uuid, team, assessment_revision)
);
INSERT INTO code_evidence_applications (evidence_id, finding_uuid, workflow_id, status, applied_by, applied_at)
SELECT evidence_id, finding_uuid, workflow_id, status, applied_by, applied_at FROM code_evidence_applications_legacy;
DROP TABLE code_evidence_applications_legacy;
ALTER TABLE code_evidence_applications ADD COLUMN selected INTEGER NOT NULL DEFAULT 1;

CREATE INDEX IF NOT EXISTS idx_code_evidence_application_scope
ON code_evidence_applications (finding_uuid, team, assessment_revision);
