"""CVSS vector parsing, scoring, and environmental rescoring.

Uses the ``cvss`` library (https://pypi.org/project/cvss/) for proper
scoring of CVSS v2.0, v3.0/v3.1 and v4.0 vectors.  Environmental
metrics are derived from code-reachability analysis findings and applied
to the vector before recomputing the score.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError

logger = logging.getLogger(__name__)


# ===================================================================== #
# Public result type                                                     #
# ===================================================================== #


@dataclass
class CvssResult:
    """Result of rescoring a CVSS vector."""

    version: str  # "2.0", "3.0", "3.1", "4.0"
    original_vector: str  # input vector string
    original_score: float  # score computed from original vector
    modified_vector: str  # vector with environmental modifications
    adjusted_score: float  # score computed from modified vector
    reasons: list[str] = field(default_factory=list)


# ===================================================================== #
# Vector helpers                                                         #
# ===================================================================== #


def _detect_version(vector: str) -> str:
    """Return the CVSS version ('2.0', '3.0', '3.1', '4.0') or ''."""
    v = vector.strip().lstrip("(").rstrip(")")
    if v.startswith("CVSS:4.0/"):
        return "4.0"
    if v.startswith("CVSS:3.1/"):
        return "3.1"
    if v.startswith("CVSS:3.0/"):
        return "3.0"
    # CVSS 2.0 has no prefix; detect by the Au metric (unique to v2).
    if "Au:" in v or "Au:" in vector:
        return "2.0"
    return ""


def _parse_metrics(vector: str) -> dict[str, str]:
    """Parse a CVSS vector string into a {metric: value} dict."""
    v = vector.strip().lstrip("(").rstrip(")")
    for prefix in ("CVSS:4.0/", "CVSS:3.1/", "CVSS:3.0/"):
        if v.startswith(prefix):
            v = v[len(prefix) :]
            break
    metrics: dict[str, str] = {}
    for part in v.split("/"):
        if ":" in part:
            key, val = part.split(":", 1)
            metrics[key] = val
    return metrics


def _build_vector(version: str, metrics: dict[str, str]) -> str:
    """Reconstruct a CVSS vector string from version and metrics dict."""
    if version == "2.0":
        base_order = ["AV", "AC", "Au", "C", "I", "A"]
        temporal = ["E", "RL", "RC"]
        env = ["CDP", "TD", "CR", "IR", "AR"]
        order = base_order + temporal + env
    elif version.startswith("3."):
        base_order = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
        temporal = ["E", "RL", "RC"]
        env = ["CR", "IR", "AR", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA"]
        order = base_order + temporal + env
    else:  # 4.0
        base_order = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]
        threat = ["E"]
        env = [
            "CR",
            "IR",
            "AR",
            "MAV",
            "MAC",
            "MAT",
            "MPR",
            "MUI",
            "MVC",
            "MVI",
            "MVA",
            "MSC",
            "MSI",
            "MSA",
        ]
        supplemental = ["S", "AU", "R", "V", "RE", "U"]
        order = base_order + threat + env + supplemental

    nd = "ND" if version == "2.0" else "X"
    parts: list[str] = []
    for k in order:
        v = metrics.get(k, "")
        if v and v != nd:
            parts.append(f"{k}:{v}")

    # Include any unknown metrics at the end.
    for k, v in metrics.items():
        if k not in order and v and v != nd:
            parts.append(f"{k}:{v}")

    prefix = "" if version == "2.0" else f"CVSS:{version}/"
    return prefix + "/".join(parts)


def _append_metrics(vector: str, **mods: str) -> str:
    """Append or override metric values in a vector string.

    Parses the vector, merges in *mods*, and reconstructs it.
    """
    version = _detect_version(vector)
    metrics = _parse_metrics(vector)
    metrics.update(mods)
    return _build_vector(version, metrics)


# ===================================================================== #
# Scoring — thin wrappers around the ``cvss`` library                    #
# ===================================================================== #


def _make_cvss(vector: str) -> CVSS2 | CVSS3 | CVSS4 | None:
    """Construct the appropriate CVSS object, or None on error."""
    v = vector.strip().lstrip("(").rstrip(")")
    try:
        version = _detect_version(v)
        if version == "2.0":
            return CVSS2(v)
        if version.startswith("3."):
            return CVSS3(v)
        if version == "4.0":
            return CVSS4(v)
    except CVSSError as exc:
        logger.debug("Cannot parse CVSS vector %r: %s", vector, exc)
    return None


def score_vector(vector: str) -> float | None:
    """Compute the CVSS base score for any version vector string.

    Returns ``None`` if the vector cannot be parsed.
    """
    obj = _make_cvss(vector)
    if obj is None:
        return None
    return float(obj.base_score)


def environmental_score(vector: str) -> float | None:
    """Compute the environmental/adjusted score for a vector.

    For v2.0 and v3.x this returns the environmental score (third
    element of ``scores()``).  For v4.0 the environmental metrics are
    folded into the single score returned by ``scores()``.
    """
    obj = _make_cvss(vector)
    if obj is None:
        return None

    scores = obj.scores()
    if isinstance(obj, CVSS4):
        # CVSS4.scores() returns a 1-tuple: (score,)
        return float(scores[0])
    # CVSS2/CVSS3.scores() returns (base, temporal, environmental)
    return float(scores[2])


# ===================================================================== #
# Rescoring — apply analysis findings to vector                          #
# ===================================================================== #


def _apply_env_modifications(
    version: str,
    metrics: dict[str, str],
    *,
    dep_found: bool,
    dep_direct: bool,
    llm_reachable: bool,
    deep_confirmed: bool,
    deep_exploitable: str,
    transitive_reachable: str,
) -> tuple[dict[str, str], list[str]]:
    """Apply environmental metric overrides based on analysis findings.

    When multiple conditions apply simultaneously (e.g. a component is
    both a direct dependency and transitively reachable), each eligible
    scenario is evaluated independently and the one producing the
    **highest** (worst-case) score is selected.

    Returns the modified metrics dict and a list of human-readable
    reasons for the changes.
    """
    deep_expl_upper = deep_exploitable.upper()
    trans_upper = transitive_reachable.upper()

    # Collect every applicable scenario.
    candidates: list[tuple[dict[str, str], list[str]]] = []

    if llm_reachable and deep_confirmed:
        candidates.append(_env_confirmed(version, metrics, deep_expl_upper))
    if llm_reachable and not deep_confirmed:
        candidates.append(_env_reachable(version, metrics))
    if trans_upper in ("YES", "LIKELY"):
        candidates.append(_env_transitive_reachable(version, metrics))
    if dep_direct:
        candidates.append(_env_direct_not_reachable(version, metrics))

    # If dependency was not found in manifests/lock files and no source-level
    # evidence overrides that, fall back to "not found".
    if not candidates:
        if not dep_found:
            return _env_not_found(version, metrics)
        candidates.append(_env_transitive_not_reachable(version, metrics))

    if len(candidates) == 1:
        return candidates[0]

    # Pick the candidate that produces the highest score (worst case).
    best: tuple[dict[str, str], list[str]] | None = None
    best_score = -1.0
    for mods, reasons in candidates:
        vec = _build_vector(version, mods)
        obj = _make_cvss(vec)
        if obj is None:
            continue
        scores = obj.scores()
        if isinstance(obj, CVSS4):
            s = float(scores[0])
        elif isinstance(obj, CVSS2):
            s = float(scores[2]) if scores[2] is not None else float(scores[0])
        else:
            s = float(scores[2])
        if s > best_score:
            best_score = s
            best = (mods, reasons)

    return best if best is not None else candidates[0]


# -- individual scenario helpers ----------------------------------------- #


def _env_not_found(
    version: str, metrics: dict[str, str]
) -> tuple[dict[str, str], list[str]]:
    mods = dict(metrics)
    if version.startswith("3."):
        mods.update(MC="N", MI="N", MA="N")
        return mods, ["dependency not found → MC:N/MI:N/MA:N"]
    if version == "4.0":
        mods.update(MVC="N", MVI="N", MVA="N", MSC="N", MSI="N", MSA="N")
        return mods, ["dependency not found → MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N"]
    mods.update(CR="L", IR="L", AR="L")
    return mods, ["dependency not found → CR:L/IR:L/AR:L"]


def _env_confirmed(
    version: str, metrics: dict[str, str], deep_expl: str
) -> tuple[dict[str, str], list[str]]:
    mods = dict(metrics)
    if version.startswith("3."):
        if deep_expl in ("YES", "LIKELY"):
            return mods, ["confirmed exploitable — no adjustment"]
        mods.update(RL="W")
        return mods, ["reachable but exploitation uncertain → RL:W"]
    if version == "4.0":
        if deep_expl in ("YES", "LIKELY"):
            mods.update(E="A")
            return mods, ["confirmed exploitable → E:A"]
        mods.update(E="P")
        return mods, ["reachable but exploitation uncertain → E:P"]
    # 2.0
    if deep_expl in ("YES", "LIKELY"):
        mods.update(E="H")
        return mods, ["confirmed exploitable → E:H"]
    return mods, ["reachable but exploitation uncertain"]


def _env_reachable(
    version: str, metrics: dict[str, str]
) -> tuple[dict[str, str], list[str]]:
    mods = dict(metrics)
    if version.startswith("3."):
        mods.update(E="F")
        return mods, ["reachable in code → E:F"]
    if version == "4.0":
        mods.update(E="P")
        return mods, ["reachable in code → E:P"]
    mods.update(E="F")
    return mods, ["reachable in code → E:F"]


def _env_transitive_reachable(
    version: str, metrics: dict[str, str]
) -> tuple[dict[str, str], list[str]]:
    mods = dict(metrics)
    if version.startswith("3."):
        mods.update(MAC="H", CR="L", IR="L", AR="L")
        return mods, ["transitively reachable → MAC:H/CR:L/IR:L/AR:L"]
    if version == "4.0":
        mods.update(MAC="H", MAT="P", CR="L", IR="L", AR="L")
        return mods, ["transitively reachable → MAC:H/MAT:P/CR:L/IR:L/AR:L"]
    mods.update(CR="L", IR="L", AR="L")
    return mods, ["transitively reachable → CR:L/IR:L/AR:L"]


def _env_direct_not_reachable(
    version: str, metrics: dict[str, str]
) -> tuple[dict[str, str], list[str]]:
    mods = dict(metrics)
    if version.startswith("3."):
        mods.update(MAC="H", CR="M", IR="M", AR="M")
        return mods, ["direct dependency but not reachable → MAC:H/CR:M/IR:M/AR:M"]
    if version == "4.0":
        mods.update(MAC="H", CR="M", IR="M", AR="M")
        return mods, ["direct dependency but not reachable → MAC:H/CR:M/IR:M/AR:M"]
    mods.update(CR="M", IR="M", AR="M")
    return mods, ["direct dependency but not reachable → CR:M/IR:M/AR:M"]


def _env_transitive_not_reachable(
    version: str, metrics: dict[str, str]
) -> tuple[dict[str, str], list[str]]:
    mods = dict(metrics)
    if version.startswith("3."):
        mods.update(MAC="H", CR="L", IR="L", AR="L", E="U")
        return mods, ["transitive dep, not reachable → MAC:H/CR:L/IR:L/AR:L/E:U"]
    if version == "4.0":
        mods.update(MAC="H", MAT="P", CR="L", IR="L", AR="L", E="U")
        return mods, ["transitive dep, not reachable → MAC:H/MAT:P/CR:L/IR:L/AR:L/E:U"]
    mods.update(CR="L", IR="L", AR="L", E="U")
    return mods, ["transitive dep, not reachable → CR:L/IR:L/AR:L/E:U"]


def rescore_vector(
    vector: str,
    *,
    dep_found: bool,
    dep_direct: bool,
    llm_reachable: bool,
    deep_confirmed: bool,
    deep_exploitable: str,
    transitive_reachable: str,
) -> CvssResult | None:
    """Rescore a CVSS vector based on code-analysis findings.

    Parses the vector, computes the original score via the ``cvss``
    library, applies environmental metric modifications derived from
    the analysis findings, builds the modified vector, and recomputes
    the score.

    Returns ``None`` if the vector cannot be parsed.
    """
    version = _detect_version(vector)
    if not version:
        return None

    # Compute original base score via the library.
    original_obj = _make_cvss(vector)
    if original_obj is None:
        return None
    original_score = float(original_obj.base_score)

    # Apply environmental modifications based on analysis findings.
    metrics = _parse_metrics(vector)
    modified_metrics, reasons = _apply_env_modifications(
        version,
        metrics,
        dep_found=dep_found,
        dep_direct=dep_direct,
        llm_reachable=llm_reachable,
        deep_confirmed=deep_confirmed,
        deep_exploitable=deep_exploitable,
        transitive_reachable=transitive_reachable,
    )

    # Build modified vector and compute the adjusted score.
    modified_vector = _build_vector(version, modified_metrics)

    # Replace the delta-only notation (e.g. "→ MC:N/MI:N/MA:N") in each
    # reason with the full adjusted vector string so consumers always see
    # the complete CVSS string.
    reasons = [
        r.split("→")[0].rstrip() + f" → {modified_vector}" if "→" in r else r
        for r in reasons
    ]

    modified_obj = _make_cvss(modified_vector)
    if modified_obj is None:
        # Fallback: if the modified vector is somehow invalid, return
        # the original score unchanged.
        return CvssResult(
            version=version,
            original_vector=vector,
            original_score=original_score,
            modified_vector=modified_vector,
            adjusted_score=original_score,
            reasons=reasons + ["(modified vector could not be scored)"],
        )

    scores = modified_obj.scores()
    if isinstance(modified_obj, CVSS4):
        # CVSS4.scores() → (score,)
        adjusted_score = float(scores[0])
    elif isinstance(modified_obj, CVSS2):
        # CVSS2.scores() → (base, temporal, environmental)
        # Environmental is None when no env metrics exist.
        adjusted_score = float(scores[2]) if scores[2] is not None else float(scores[0])
    else:
        # CVSS3.scores() → (base, temporal, environmental)
        adjusted_score = float(scores[2])

    return CvssResult(
        version=version,
        original_vector=vector,
        original_score=original_score,
        modified_vector=modified_vector,
        adjusted_score=adjusted_score,
        reasons=reasons,
    )


def rescore_for_not_affected(vector: str) -> CvssResult | None:
    """Re-rescore a CVSS vector when the final verdict is "Not Affected".

    When analysis determines the vulnerability does not impact the
    project, the environmental metrics should reflect zero effective
    impact — the vulnerability exists in the dependency but is not
    exploitable in this deployment context.

    Returns ``None`` if the vector cannot be parsed.
    """
    version = _detect_version(vector)
    if not version:
        return None

    original_obj = _make_cvss(vector)
    if original_obj is None:
        return None
    original_score = float(original_obj.base_score)

    metrics = _parse_metrics(vector)
    reason_label = "verdict: not affected"

    if version.startswith("3."):
        metrics.update(MC="N", MI="N", MA="N", E="U")
        reason_label += " → MC:N/MI:N/MA:N/E:U"
    elif version == "4.0":
        metrics.update(
            MVC="N", MVI="N", MVA="N", MSC="N", MSI="N", MSA="N", E="U",
        )
        reason_label += " → MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N/E:U"
    else:
        # CVSS 2.0
        metrics.update(CR="L", IR="L", AR="L", E="U")
        reason_label += " → CR:L/IR:L/AR:L/E:U"

    modified_vector = _build_vector(version, metrics)
    reasons = [reason_label.split("→")[0].rstrip() + f" → {modified_vector}"]

    modified_obj = _make_cvss(modified_vector)
    if modified_obj is None:
        return CvssResult(
            version=version,
            original_vector=vector,
            original_score=original_score,
            modified_vector=modified_vector,
            adjusted_score=original_score,
            reasons=reasons + ["(modified vector could not be scored)"],
        )

    scores = modified_obj.scores()
    if isinstance(modified_obj, CVSS4):
        adjusted_score = float(scores[0])
    elif isinstance(modified_obj, CVSS2):
        adjusted_score = float(scores[2]) if scores[2] is not None else float(scores[0])
    else:
        adjusted_score = float(scores[2])

    return CvssResult(
        version=version,
        original_vector=vector,
        original_score=original_score,
        modified_vector=modified_vector,
        adjusted_score=adjusted_score,
        reasons=reasons,
    )
