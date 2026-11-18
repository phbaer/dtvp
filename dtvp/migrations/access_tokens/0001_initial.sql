CREATE TABLE access_tokens (
    token_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    scopes TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at TEXT
);

CREATE INDEX access_tokens_username_idx
ON access_tokens (username, created_at);

CREATE TABLE access_token_audit (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    username TEXT NOT NULL,
    token_id TEXT NOT NULL,
    agent TEXT NOT NULL,
    action TEXT NOT NULL,
    outcome TEXT NOT NULL,
    target_json TEXT NOT NULL,
    detail TEXT NOT NULL
);

CREATE INDEX access_token_audit_username_idx
ON access_token_audit (username, audit_id);
