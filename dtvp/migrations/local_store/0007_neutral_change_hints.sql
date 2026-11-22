-- The source's change hints get neutral names: any source may offer them
-- (dtvp/ports.py, ChangeHints), Dependency-Track is one adapter among
-- others (ADR 0004, "Change hints are optional").
ALTER TABLE sync_versions RENAME COLUMN dt_last_bom_import TO source_bom_hint;
ALTER TABLE sync_versions RENAME COLUMN dt_last_vuln_analysis TO source_analysis_hint;
