"""Original severity is independent of local rescoring."""

import math

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")


def original_severity(score, fallback=None) -> str:
    if score is not None and not isinstance(score, bool):
        try:
            value = float(score)
            if math.isfinite(value) and 0 <= value <= 10:
                for minimum, severity in ((9, "CRITICAL"), (7, "HIGH"), (4, "MEDIUM"), (0.1, "LOW"), (0, "INFO")):
                    if value >= minimum:
                        return severity
        except (TypeError, ValueError):
            pass
    label = str(fallback or "UNKNOWN").upper()
    return label if label in SEVERITIES else "UNKNOWN"


def group_original_severity(group: dict) -> str:
    if group.get("original_severity") in SEVERITIES:
        return group["original_severity"]
    # Older summaries may have an effective severity in `severity`.
    fallback = group.get("severity") if group.get("rescored_cvss") is None else None
    score = group.get("cvss_score")
    return original_severity(score if score is not None else group.get("cvss"), fallback)
