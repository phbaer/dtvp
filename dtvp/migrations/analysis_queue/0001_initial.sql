CREATE TABLE analysis_queue_items (
    queue_id TEXT PRIMARY KEY,
    sequence INTEGER NOT NULL,
    in_order INTEGER NOT NULL DEFAULT 1,
    payload_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX analysis_queue_items_order_idx
    ON analysis_queue_items (in_order, sequence);
