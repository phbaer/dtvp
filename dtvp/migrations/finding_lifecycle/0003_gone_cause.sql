-- Why a finding went, where the stored BOMs tell: for a finding no longer
-- matched on a component that is unchanged except for its CPE, for example
-- "CPE changed from cpe:2.3:a:cure53:dompurify:… to cpe:2.3:a:dompurify:…".
-- NULL when nothing more is known than the reason.
ALTER TABLE finding_presence ADD COLUMN gone_cause TEXT;

-- 1 for a row made for an assessment record whose finding went before River
-- followed findings: when it was first seen is unknown (first_seen_at ''),
-- and it is left out of "followed since" and of what went at a read.
ALTER TABLE finding_presence ADD COLUMN predates_tracking INTEGER NOT NULL DEFAULT 0;
