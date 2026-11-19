-- What is done about a finding (Dependency-Track's analysisResponse,
-- CycloneDX's analysis.response): one value per finding, read from the
-- [Response: ...] tag beside the team blocks. NULL when not set.
ALTER TABLE assessment_fields ADD COLUMN response TEXT;

-- Read every assessment into fields again at the next start, so existing
-- ones get the new field.
DELETE FROM assessment_team_fields;
DELETE FROM assessment_fields;
