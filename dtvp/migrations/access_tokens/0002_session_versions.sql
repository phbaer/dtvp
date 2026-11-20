-- Per-user browser session version. A session token carries the version it
-- was issued with; raising it (logout, revocation) ends every session of the
-- user. Users without a row are at version 0.
CREATE TABLE session_versions (
    username TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    revoked_at TEXT NOT NULL
);
