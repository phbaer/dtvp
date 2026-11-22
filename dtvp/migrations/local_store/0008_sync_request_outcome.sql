-- The outcome of the last manual request per version (ADR 0004 step 8): a
-- request is cleared when it is answered, and what became of it is kept here
-- so GET /api/sync/versions can show done (with the read time) or failed
-- (with why).
ALTER TABLE sync_versions ADD COLUMN last_request_id TEXT;
ALTER TABLE sync_versions ADD COLUMN last_request_by TEXT;
ALTER TABLE sync_versions ADD COLUMN last_request_at TEXT;
ALTER TABLE sync_versions ADD COLUMN last_request_state TEXT;
ALTER TABLE sync_versions ADD COLUMN last_request_finished_at TEXT;
ALTER TABLE sync_versions ADD COLUMN last_request_error TEXT;
