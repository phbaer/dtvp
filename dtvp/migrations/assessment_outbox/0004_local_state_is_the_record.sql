-- The local database is the record; the source never changes it.

-- How often in a row the source was found not to hold a value that had been
-- exported to it. Spaces out repeated exports and makes them visible.
ALTER TABLE assessment_state
ADD COLUMN export_rejections INTEGER NOT NULL DEFAULT 0;

-- Conflicts no longer exist: a finding that was in conflict keeps its local
-- value, which is queued for export like any other change.
INSERT OR IGNORE INTO assessment_outbox (
    project_uuid, component_uuid, vulnerability_uuid, revision, update_id,
    payload_json, attempts, next_attempt_at, last_error, created_at, updated_at
)
SELECT
    project_uuid, component_uuid, vulnerability_uuid, revision,
    lower(hex(randomblob(16))),
    json_object(
        'project_uuid', project_uuid,
        'component_uuid', component_uuid,
        'vulnerability_uuid', vulnerability_uuid,
        'state', analysis_state,
        'details', analysis_details,
        'suppressed', json(CASE WHEN suppressed THEN 'true' ELSE 'false' END)
    ),
    0, NULL, NULL, updated_at, updated_at
FROM assessment_state
WHERE sync_status = 'diverged';

UPDATE assessment_state
SET sync_status = 'pending',
    last_error = NULL,
    update_id = (
        SELECT update_id FROM assessment_outbox
        WHERE assessment_outbox.project_uuid = assessment_state.project_uuid
          AND assessment_outbox.component_uuid = assessment_state.component_uuid
          AND assessment_outbox.vulnerability_uuid = assessment_state.vulnerability_uuid
    )
WHERE sync_status = 'diverged';
