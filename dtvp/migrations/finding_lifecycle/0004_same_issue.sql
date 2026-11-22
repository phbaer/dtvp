-- A person confirmed that this finding is the same issue as another one
-- that no source names as its alias (for example a CVE and a GitHub
-- advisory with the same description, see dtvp/same_issue.py): the other
-- finding, why DTVP proposed it, who confirmed and when. NULL otherwise.
-- Not part of a read: reads leave these columns alone.
ALTER TABLE finding_presence ADD COLUMN same_issue_component_uuid TEXT;
ALTER TABLE finding_presence ADD COLUMN same_issue_vulnerability_uuid TEXT;
ALTER TABLE finding_presence ADD COLUMN same_issue_reason TEXT;
ALTER TABLE finding_presence ADD COLUMN same_issue_confirmed_by TEXT;
ALTER TABLE finding_presence ADD COLUMN same_issue_confirmed_at TEXT;
