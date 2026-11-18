-- Store an assessment's text once where it used to be stored three times.

-- The value last agreed with the source usually is the record's own text.
-- Then base_details is NULL and base_same says so.
ALTER TABLE assessment_state ADD COLUMN base_same INTEGER NOT NULL DEFAULT 0;

UPDATE assessment_state
SET base_details = NULL, base_same = 1
WHERE base_state IS NOT NULL AND base_details IS analysis_details;

-- The history entry of an adopted assessment holds the record's text again
-- as long as the record is unchanged. Then its text is empty and
-- text_in_record says where it is.
ALTER TABLE assessment_revisions ADD COLUMN text_in_record INTEGER NOT NULL DEFAULT 0;

UPDATE assessment_revisions
SET analysis_details = '', text_in_record = 1
WHERE revision = 0 AND origin = 'import'
  AND EXISTS (
      SELECT 1 FROM assessment_state
      WHERE assessment_state.project_uuid = assessment_revisions.project_uuid
        AND assessment_state.component_uuid = assessment_revisions.component_uuid
        AND assessment_state.vulnerability_uuid = assessment_revisions.vulnerability_uuid
        AND assessment_state.revision = 0
        AND assessment_state.analysis_details IS assessment_revisions.analysis_details
  );

-- Whoever changes a record's text: the text it replaces is first written to
-- the places that referred to it. No writer has to remember this.
CREATE TRIGGER assessment_state_keep_replaced_text
AFTER UPDATE OF analysis_details ON assessment_state
WHEN NEW.analysis_details IS NOT OLD.analysis_details
BEGIN
    UPDATE assessment_revisions
    SET analysis_details = OLD.analysis_details, text_in_record = 0
    WHERE project_uuid = OLD.project_uuid
      AND component_uuid = OLD.component_uuid
      AND vulnerability_uuid = OLD.vulnerability_uuid
      AND text_in_record = 1;
    UPDATE assessment_state
    SET base_details = OLD.analysis_details, base_same = 0
    WHERE project_uuid = NEW.project_uuid
      AND component_uuid = NEW.component_uuid
      AND vulnerability_uuid = NEW.vulnerability_uuid
      AND base_same = 1
      AND base_details IS NULL
      AND base_state IS NOT NULL;
END;

-- Space freed by the two updates is reused by SQLite; the file shrinks only
-- with VACUUM, which is left to the operator.
