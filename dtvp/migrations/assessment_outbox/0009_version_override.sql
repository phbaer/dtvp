-- A finding's version override (ADR 0010): the label and reason of the
-- [Version Override: ...] and [Override Reason: ...] tags beside the team
-- blocks. NULL when the finding has none.
ALTER TABLE assessment_fields ADD COLUMN version_override TEXT;
ALTER TABLE assessment_fields ADD COLUMN version_override_reason TEXT;
CREATE INDEX assessment_fields_version_override_idx
    ON assessment_fields (project_uuid, vulnerability_uuid)
    WHERE version_override IS NOT NULL;

-- Read every assessment into fields again at the next start, so existing
-- ones get the new fields.
DELETE FROM assessment_team_fields;
DELETE FROM assessment_fields;
