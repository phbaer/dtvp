-- Saved views (ADR 0015). A view is a named filter state of the project
-- review: the canonical query string of its filters, for one project or any
-- (project NULL). Scope 'personal' belongs to its owner, 'global' is visible
-- to all and managed by reviewers. Its code is its short link (/v/<code>).
CREATE TABLE saved_views (
    code TEXT PRIMARY KEY,
    scope TEXT NOT NULL CHECK (scope IN ('personal', 'global')),
    name TEXT NOT NULL,
    project TEXT,
    query TEXT NOT NULL,
    owner TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
);

CREATE INDEX saved_views_owner_idx
ON saved_views (owner, scope, created_at);

-- A default view: of a user (subject_kind 'user') or a role ('role'), for
-- one project or all projects (project '').
CREATE TABLE saved_view_defaults (
    subject_kind TEXT NOT NULL CHECK (subject_kind IN ('user', 'role')),
    subject TEXT NOT NULL,
    project TEXT NOT NULL,
    code TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    PRIMARY KEY (subject_kind, subject, project)
);
