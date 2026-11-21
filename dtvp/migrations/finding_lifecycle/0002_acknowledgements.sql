-- A person looked at a gone finding and decided nothing more is to be done:
-- who and when. Shared by every user. Cleared when the finding is reported
-- again, so a finding that goes a second time asks again.
ALTER TABLE finding_presence ADD COLUMN acknowledged_by TEXT;
ALTER TABLE finding_presence ADD COLUMN acknowledged_at TEXT;
