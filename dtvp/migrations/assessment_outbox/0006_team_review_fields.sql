-- Ticket reference and review confirmations of a team's assessment.
ALTER TABLE assessment_team_fields ADD COLUMN ticket TEXT;
ALTER TABLE assessment_team_fields ADD COLUMN evidence_reviewed TEXT;
ALTER TABLE assessment_team_fields ADD COLUMN version_coverage TEXT;

-- Read every assessment into fields again at the next start, so existing
-- ones get the new fields.
DELETE FROM assessment_team_fields;
DELETE FROM assessment_fields;
