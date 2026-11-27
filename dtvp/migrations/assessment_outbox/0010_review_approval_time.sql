-- Approval provenance is separate from the assessor's original date.
ALTER TABLE assessment_team_fields ADD COLUMN reviewed_at_ms INTEGER;

-- Rebuild only derived fields from the canonical assessment texts.
-- Legacy approvals remain unknown; this migration fabricates no history.
DELETE FROM assessment_team_fields;
DELETE FROM assessment_fields;
