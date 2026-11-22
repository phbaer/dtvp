-- The portfolio pass (ADR 0004): per version, a digest of what a portfolio-
-- wide findings list can show (finding keys, analysis state, details,
-- suppression), recorded at every findings read of the version. A pass that
-- finds the same digest marks the version checked without reading it.
ALTER TABLE sync_versions ADD COLUMN portfolio_digest TEXT;
