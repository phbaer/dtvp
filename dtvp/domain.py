"""Shared operational audit records."""

from dtvp.models import Audit


def audit(db, actor_id, action, subject_id, project_id=None, details=None):
    db.add(
        Audit(
            actor_id=actor_id,
            action=action,
            subject_id=subject_id,
            project_id=project_id,
            details=details or {},
        )
    )
