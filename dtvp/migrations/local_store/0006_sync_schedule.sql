-- The scheduler's bookkeeping per version (ADR 0004, "Schedule and
-- priorities", "Generations"): when each kind was last read, the list
-- signals as of the last sync that read them, and a staged sync's changed
-- kinds and digests, which only its commit applies.
ALTER TABLE sync_versions ADD COLUMN findings_read_at TEXT;
ALTER TABLE sync_versions ADD COLUMN vulns_read_at TEXT;
ALTER TABLE sync_versions ADD COLUMN bom_read_at TEXT;
ALTER TABLE sync_versions ADD COLUMN read_bom_signal TEXT;
ALTER TABLE sync_versions ADD COLUMN read_analysis_signal TEXT;
ALTER TABLE sync_versions ADD COLUMN staged_kinds TEXT;
ALTER TABLE sync_versions ADD COLUMN staged_digests_json TEXT;

-- Versions read before this migration count as read as of their last
-- success: otherwise every one of them would look signalled and the whole
-- portfolio would be re-read at once after the upgrade.
UPDATE sync_versions
SET findings_read_at = last_success_at,
    vulns_read_at = last_success_at,
    bom_read_at = last_success_at,
    read_bom_signal = dt_last_bom_import,
    read_analysis_signal = dt_last_vuln_analysis
WHERE last_success_at IS NOT NULL;
