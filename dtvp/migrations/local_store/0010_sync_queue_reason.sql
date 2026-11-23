-- Why a version is queued (ADR 0004, "Queue reasons"): the reason of the
-- plan that queued it (a request, a first import, a change hint, an interval,
-- the safety re-read, a portfolio pass's change). Set with the queued status;
-- cleared when the version settles or its sync starts.
ALTER TABLE sync_versions ADD COLUMN queued_reason TEXT;
