from dtvp.assessment_restore_services import (
    build_missing_rescoring_vector_restore_candidate,
)


OLD_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MAC:H/MPR:H"
LATEST_VECTOR = (
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:L/IR:L/AR:L/"
    "MAC:H/MPR:H/MC:N/MI:N/MA:N"
)


def _analysis(comments):
    return {
        "analysisState": "NOT_AFFECTED",
        "analysisDetails": (
            "--- [Team: General] [State: NOT_AFFECTED] "
            "[Justification: CODE_NOT_PRESENT] ---\n\n"
            "Unused dependency."
        ),
        "analysisComments": comments,
    }


def test_restore_uses_strictly_newest_vector_after_multiple_rescores():
    candidate = build_missing_rescoring_vector_restore_candidate(
        _analysis(
            [
                {
                    "timestamp": "2026-04-09T06:12:15Z",
                    "comment": (
                        f"[Rescored: 6.6] [Rescored Vector: {OLD_VECTOR}]"
                    ),
                },
                {
                    "timestamp": "2026-04-09T06:13:27Z",
                    "comment": (
                        f"[Rescored: 0] [Rescored Vector: {LATEST_VECTOR}]"
                    ),
                },
            ]
        )
    )

    assert candidate is not None
    assert candidate["status"] == "recoverable"
    assert candidate["restored_score"] == 0
    assert candidate["restored_vector"] == LATEST_VECTOR
    assert candidate["candidate_vectors"] == sorted([OLD_VECTOR, LATEST_VECTOR])


def test_restore_keeps_same_timestamp_vector_conflicts_ambiguous():
    candidate = build_missing_rescoring_vector_restore_candidate(
        _analysis(
            [
                {
                    "timestamp": 1775708008995,
                    "comment": f"[Rescored Vector: {OLD_VECTOR}]",
                },
                {
                    "timestamp": 1775708008995,
                    "comment": f"[Rescored Vector: {LATEST_VECTOR}]",
                },
            ]
        )
    )

    assert candidate is not None
    assert candidate["status"] == "ambiguous"
    assert candidate["restored_vector"] is None


def test_restore_keeps_newest_vector_ambiguous_when_current_score_disagrees():
    analysis = _analysis(
        [
            {
                "timestamp": "2026-04-09T06:12:15Z",
                "comment": f"[Rescored: 6.6] [Rescored Vector: {OLD_VECTOR}]",
            },
            {
                "timestamp": "2026-04-09T06:13:27Z",
                "comment": f"[Rescored: 0] [Rescored Vector: {LATEST_VECTOR}]",
            },
        ]
    )
    analysis["analysisDetails"] = "[Rescored: 6.6]\n\nCurrent assessment."

    candidate = build_missing_rescoring_vector_restore_candidate(analysis)

    assert candidate is not None
    assert candidate["status"] == "ambiguous"
    assert candidate["restored_vector"] is None


def test_restore_keeps_undated_vector_conflicts_ambiguous():
    candidate = build_missing_rescoring_vector_restore_candidate(
        _analysis(
            [
                {"comment": f"[Rescored Vector: {OLD_VECTOR}]"},
                {"comment": f"[Rescored Vector: {LATEST_VECTOR}]"},
            ]
        )
    )

    assert candidate is not None
    assert candidate["status"] == "ambiguous"
    assert candidate["restored_vector"] is None
