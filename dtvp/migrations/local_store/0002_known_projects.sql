-- Every project the source has ever reported. The project list itself is
-- replaced on each import, so a deleted project would otherwise leave its
-- stored findings and queued exports without a name.
CREATE TABLE known_projects (
    project_uuid TEXT PRIMARY KEY,
    name TEXT,
    version TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);

INSERT INTO known_projects (project_uuid, name, version, first_seen_at, last_seen_at)
SELECT project_uuid, name, version,
       COALESCE((SELECT updated_at FROM source_snapshots WHERE kind = 'projects'), '1970-01-01T00:00:00+00:00'),
       COALESCE((SELECT updated_at FROM source_snapshots WHERE kind = 'projects'), '1970-01-01T00:00:00+00:00')
FROM source_projects
WHERE project_uuid IS NOT NULL
GROUP BY project_uuid;
