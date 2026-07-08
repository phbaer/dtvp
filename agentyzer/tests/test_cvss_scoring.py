"""Tests for the CVSS scoring module — v2.0, v3.x, and v4.0."""

from src.agents.cvss_scoring import (
    _detect_version,
    _parse_metrics,
    environmental_score,
    rescore_vector,
    score_vector,
)

# ===================================================================== #
# Version detection                                                      #
# ===================================================================== #


class TestDetectVersion:
    def test_v2(self):
        assert _detect_version("AV:N/AC:L/Au:N/C:C/I:C/A:C") == "2.0"

    def test_v2_parens(self):
        assert _detect_version("(AV:N/AC:L/Au:N/C:C/I:C/A:C)") == "2.0"

    def test_v31(self):
        assert _detect_version("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == "3.1"

    def test_v30(self):
        assert _detect_version("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == "3.0"

    def test_v40(self):
        vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        assert _detect_version(vec) == "4.0"

    def test_unknown(self):
        assert _detect_version("not a vector") == ""


# ===================================================================== #
# Metric parsing                                                         #
# ===================================================================== #


class TestParseMetrics:
    def test_v31_base(self):
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        m = _parse_metrics(vec)
        assert m["AV"] == "N"
        assert m["S"] == "U"
        assert m["C"] == "H"

    def test_v2(self):
        m = _parse_metrics("AV:N/AC:L/Au:N/C:C/I:C/A:C")
        assert m["Au"] == "N"
        assert m["C"] == "C"

    def test_v40(self):
        vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        m = _parse_metrics(vec)
        assert m["AT"] == "N"
        assert m["VC"] == "H"
        assert m["SC"] == "N"


# ===================================================================== #
# CVSS 2.0 scoring                                                      #
# ===================================================================== #


class TestV2Scoring:
    def test_max_base(self):
        """AV:N/AC:L/Au:N/C:C/I:C/A:C → 10.0"""
        score = score_vector("AV:N/AC:L/Au:N/C:C/I:C/A:C")
        assert score == 10.0

    def test_medium_base(self):
        """AV:N/AC:M/Au:S/C:P/I:P/A:N → known score."""
        score = score_vector("AV:N/AC:M/Au:S/C:P/I:P/A:N")
        assert score is not None
        assert 3.0 < score < 7.0

    def test_zero_impact(self):
        """All impacts None → 0."""
        score = score_vector("AV:N/AC:L/Au:N/C:N/I:N/A:N")
        assert score == 0.0

    def test_environmental(self):
        """Environmental score with CR:L reduces from base."""
        base = score_vector("AV:N/AC:L/Au:N/C:C/I:C/A:C")
        env = environmental_score("AV:N/AC:L/Au:N/C:C/I:C/A:C/CR:L/IR:L/AR:L")
        assert base is not None and env is not None
        assert env < base


# ===================================================================== #
# CVSS 3.x scoring                                                      #
# ===================================================================== #


class TestV3Scoring:
    def test_max_base_unchanged(self):
        """AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8"""
        score = score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score == 9.8

    def test_max_base_changed(self):
        """AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0"""
        score = score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert score == 10.0

    def test_medium(self):
        """A typical medium-severity vector."""
        score = score_vector("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N")
        assert score is not None
        assert 2.0 < score < 6.0

    def test_no_impact(self):
        """All C/I/A = N → 0.0"""
        score = score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        assert score == 0.0

    def test_v30(self):
        """v3.0 uses the same formula as v3.1."""
        score = score_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score == 9.8

    def test_environmental_reduces(self):
        """Environmental with MC:N/MI:N/MA:N should give 0."""
        env = environmental_score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MC:N/MI:N/MA:N"
        )
        assert env == 0.0

    def test_environmental_requirements_reduce(self):
        """CR:L/IR:L/AR:L should reduce the score."""
        base = score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        env = environmental_score(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:L/IR:L/AR:L"
        )
        assert base is not None and env is not None
        assert env < base

    def test_environmental_mac_h(self):
        """MAC:H should reduce exploitability."""
        base = score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        env = environmental_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MAC:H")
        assert base is not None and env is not None
        assert env < base

    def test_log4shell(self):
        """CVE-2021-44228 (Log4Shell): CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0"""
        score = score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert score == 10.0


# ===================================================================== #
# CVSS 4.0 scoring                                                      #
# ===================================================================== #


class TestV4Scoring:
    def test_max_score(self):
        """Maximum severity v4.0 vector → 10.0"""
        vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
        score = score_vector(vec)
        assert score == 10.0

    def test_all_none_impact(self):
        """All impact metrics N → 0.0"""
        vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
        score = score_vector(vec)
        assert score == 0.0

    def test_network_high_vuln_no_subseq(self):
        """High vuln impact, no subsequent impact."""
        vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        score = score_vector(vec)
        assert score is not None
        assert 8.0 <= score <= 10.0

    def test_low_attack_surface(self):
        """Physical AV + high complexity should yield lower score."""
        vec = "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N"
        score = score_vector(vec)
        assert score is not None
        assert score < 3.0

    def test_environmental_e_u(self):
        """E:U (unreported) should reduce the score."""
        vec_base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        vec_eu = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U"
        base = score_vector(vec_base)
        env = score_vector(vec_eu)
        assert base is not None and env is not None
        assert env < base

    def test_modified_metrics_reduce(self):
        """MVC:N/MVI:N/MVA:N should give 0."""
        vec = (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"
            "/SC:N/SI:N/SA:N/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N"
        )
        score = score_vector(vec)
        assert score == 0.0


# ===================================================================== #
# Rescoring based on findings                                            #
# ===================================================================== #


class TestRescore:
    FINDINGS_NOT_FOUND = dict(
        dep_found=False,
        dep_direct=False,
        llm_reachable=False,
        deep_confirmed=False,
        deep_exploitable="",
        transitive_reachable="",
    )
    FINDINGS_EXPLOITABLE = dict(
        dep_found=True,
        dep_direct=True,
        llm_reachable=True,
        deep_confirmed=True,
        deep_exploitable="YES",
        transitive_reachable="",
    )
    FINDINGS_TRANSITIVE_UNREACHABLE = dict(
        dep_found=True,
        dep_direct=False,
        llm_reachable=False,
        deep_confirmed=False,
        deep_exploitable="",
        transitive_reachable="",
    )

    def test_v31_not_found(self):
        """Dependency not found → zero impact."""
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        result = rescore_vector(vec, **self.FINDINGS_NOT_FOUND)
        assert result is not None
        assert result.adjusted_score == 0.0

    def test_v31_exploitable(self):
        """Confirmed exploitable → keeps original score."""
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        result = rescore_vector(vec, **self.FINDINGS_EXPLOITABLE)
        assert result is not None
        assert result.adjusted_score == result.original_score

    def test_v31_transitive_unreachable(self):
        """Transitive dep, not reachable → significantly reduced."""
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        result = rescore_vector(vec, **self.FINDINGS_TRANSITIVE_UNREACHABLE)
        assert result is not None
        assert result.adjusted_score < result.original_score
        assert "MAC:H" in result.modified_vector
        assert "E:U" in result.modified_vector

    def test_v40_transitive_unreachable(self):
        """v4.0 transitive dep, not reachable → reduced."""
        vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        result = rescore_vector(vec, **self.FINDINGS_TRANSITIVE_UNREACHABLE)
        assert result is not None
        assert result.adjusted_score < result.original_score
        assert "E:U" in result.modified_vector

    def test_v2_exploitable(self):
        """v2.0 confirmed exploitable → E:H applied."""
        vec = "AV:N/AC:L/Au:N/C:C/I:C/A:C"
        result = rescore_vector(vec, **self.FINDINGS_EXPLOITABLE)
        assert result is not None
        # E:H with no other temporal mods should keep score close to base
        assert result.adjusted_score == result.original_score

    def test_returns_none_for_garbage(self):
        assert rescore_vector("not a vector", **self.FINDINGS_EXPLOITABLE) is None

    def test_v31_direct_and_transitive_picks_worst(self):
        """When dep is both direct and transitively reachable, pick worst score."""
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        # direct-only (not reachable): MAC:H/CR:M/IR:M/AR:M
        result_direct = rescore_vector(
            vec,
            dep_found=True,
            dep_direct=True,
            llm_reachable=False,
            deep_confirmed=False,
            deep_exploitable="",
            transitive_reachable="",
        )
        # transitive-only (reachable): MAC:H/CR:L/IR:L/AR:L
        result_trans = rescore_vector(
            vec,
            dep_found=True,
            dep_direct=False,
            llm_reachable=False,
            deep_confirmed=False,
            deep_exploitable="",
            transitive_reachable="YES",
        )
        # both direct AND transitively reachable: should pick worst
        result_both = rescore_vector(
            vec,
            dep_found=True,
            dep_direct=True,
            llm_reachable=False,
            deep_confirmed=False,
            deep_exploitable="",
            transitive_reachable="YES",
        )
        assert result_direct is not None
        assert result_trans is not None
        assert result_both is not None
        # Worst case should be >= each individual scenario
        assert result_both.adjusted_score >= result_trans.adjusted_score
        assert result_both.adjusted_score >= result_direct.adjusted_score

    def test_v40_direct_and_transitive_picks_worst(self):
        """v4.0: direct + transitive → worst-case score selected."""
        vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        result_direct = rescore_vector(
            vec,
            dep_found=True,
            dep_direct=True,
            llm_reachable=False,
            deep_confirmed=False,
            deep_exploitable="",
            transitive_reachable="",
        )
        result_trans = rescore_vector(
            vec,
            dep_found=True,
            dep_direct=False,
            llm_reachable=False,
            deep_confirmed=False,
            deep_exploitable="",
            transitive_reachable="YES",
        )
        result_both = rescore_vector(
            vec,
            dep_found=True,
            dep_direct=True,
            llm_reachable=False,
            deep_confirmed=False,
            deep_exploitable="",
            transitive_reachable="YES",
        )
        assert result_direct is not None
        assert result_trans is not None
        assert result_both is not None
        assert result_both.adjusted_score >= result_trans.adjusted_score
        assert result_both.adjusted_score >= result_direct.adjusted_score

    def test_v2_direct_and_transitive_picks_worst(self):
        """v2.0: direct + transitive → worst-case score selected."""
        vec = "AV:N/AC:L/Au:N/C:C/I:C/A:C"
        result_direct = rescore_vector(
            vec,
            dep_found=True,
            dep_direct=True,
            llm_reachable=False,
            deep_confirmed=False,
            deep_exploitable="",
            transitive_reachable="",
        )
        result_trans = rescore_vector(
            vec,
            dep_found=True,
            dep_direct=False,
            llm_reachable=False,
            deep_confirmed=False,
            deep_exploitable="",
            transitive_reachable="YES",
        )
        result_both = rescore_vector(
            vec,
            dep_found=True,
            dep_direct=True,
            llm_reachable=False,
            deep_confirmed=False,
            deep_exploitable="",
            transitive_reachable="YES",
        )
        assert result_direct is not None
        assert result_trans is not None
        assert result_both is not None
        assert result_both.adjusted_score >= result_trans.adjusted_score
        assert result_both.adjusted_score >= result_direct.adjusted_score

    def test_reachable_and_direct_picks_worst(self):
        """When code-reachable AND direct dep, worst scenario wins."""
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        result = rescore_vector(
            vec,
            dep_found=True,
            dep_direct=True,
            llm_reachable=True,
            deep_confirmed=False,
            deep_exploitable="",
            transitive_reachable="YES",
        )
        assert result is not None
        # LLM-reachable (E:F) should produce highest score for this vector
        assert result.adjusted_score > 0


# ===================================================================== #
# Verdict-level rescore_cvss integration                                 #
# ===================================================================== #


class TestVerdictRescore:
    def test_vector_preferred_over_numeric(self):
        """rescore_cvss should prefer vector strings over bare numerics."""
        from src.agents.verdict import rescore_cvss

        cvss_list = [
            9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ]
        result = rescore_cvss(
            cvss_list,
            dep_found=True,
            dep_direct=True,
            llm_reachable=True,
            deep_confirmed=True,
            deep_exploitable="YES",
            transitive_reachable="",
        )
        assert result is not None
        assert "original_vector" in result
        assert result["version"] == "3.1"

    def test_numeric_only(self):
        """When only numeric scores available, returns None (no vector = no score)."""
        from src.agents.verdict import rescore_cvss

        result = rescore_cvss(
            [7.5],
            dep_found=True,
            dep_direct=True,
            llm_reachable=False,
            deep_confirmed=False,
            deep_exploitable="",
            transitive_reachable="",
        )
        assert result is None

    def test_empty_list(self):
        from src.agents.verdict import rescore_cvss

        assert (
            rescore_cvss(
                [],
                dep_found=True,
                dep_direct=True,
                llm_reachable=False,
                deep_confirmed=False,
                deep_exploitable="",
                transitive_reachable="",
            )
            is None
        )


# ===================================================================== #
# Known CVE vectors (cross-validation with published scores)             #
# ===================================================================== #


class TestKnownCVEs:
    """Validate our scoring against published CVSS scores for well-known CVEs."""

    def test_cve_2021_44228_log4shell(self):
        """Log4Shell: CVSS 3.1 = 10.0"""
        assert score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0

    def test_cve_2014_0160_heartbleed(self):
        """Heartbleed: CVSS 3.1 = 7.5"""
        assert score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") == 7.5

    def test_cve_2017_5638_struts(self):
        """Apache Struts: CVSS 3.0 = 10.0"""
        assert score_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0

    def test_cve_2014_0160_heartbleed_v2(self):
        """Heartbleed: CVSS 2.0 = 5.0"""
        assert score_vector("AV:N/AC:L/Au:N/C:P/I:N/A:N") == 5.0


# ===================================================================== #
# Post-verdict rescoring for "Not Affected"                              #
# ===================================================================== #


class TestRescoreNotAffected:
    """Validate that rescore_for_not_affected zeros out impact."""

    def test_cvss4_not_affected_zeros_impact(self):
        from src.agents.cvss_scoring import rescore_for_not_affected

        vec = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
        result = rescore_for_not_affected(vec)
        assert result is not None
        assert result.adjusted_score < result.original_score
        # Modified impact metrics should be zeroed out.
        for metric in ("MVC:N", "MVI:N", "MVA:N", "MSC:N", "MSI:N", "MSA:N", "E:U"):
            assert metric in result.modified_vector

    def test_cvss31_not_affected_zeros_impact(self):
        from src.agents.cvss_scoring import rescore_for_not_affected

        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        result = rescore_for_not_affected(vec)
        assert result is not None
        assert result.adjusted_score < result.original_score
        for metric in ("MC:N", "MI:N", "MA:N", "E:U"):
            assert metric in result.modified_vector

    def test_cvss4_user_vector_9_4_rescored_aggressively(self):
        """The exact vector from the user's report should score much lower."""
        from src.agents.cvss_scoring import rescore_for_not_affected

        vec = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N"
        result = rescore_for_not_affected(vec)
        assert result is not None
        # Original is ~9.4; "not affected" should drop well below 8.9.
        assert result.adjusted_score < 5.0, (
            f"Expected aggressive rescoring for Not Affected, "
            f"got {result.original_score} → {result.adjusted_score}"
        )

    def test_invalid_vector_returns_none(self):
        from src.agents.cvss_scoring import rescore_for_not_affected

        assert rescore_for_not_affected("not a vector") is None

    def test_post_verdict_rescore_in_aggregate(self):
        """_post_verdict_rescore replaces adjusted_cvss when verdict is Not Affected."""
        from src.agents.verdict import _post_verdict_rescore

        verdict_dict = {
            "verdict": "Not Affected",
            "affected": False,
            "confidence": "High",
            "adjusted_cvss": {
                "original_score": 9.4,
                "adjusted_score": 8.9,
                "original_vector": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N",
                "adjusted_vector": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N/CR:M/IR:M/AR:M/MAC:H",
            },
        }
        cvss_list = ["CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N"]
        version_ctx = {}

        result = _post_verdict_rescore(verdict_dict, cvss_list, version_ctx)
        adj = result["adjusted_cvss"]
        # Should now be much lower than the original 8.9.
        assert adj["adjusted_score"] < 5.0
        assert "E:U" in adj["adjusted_vector"]

    def test_post_verdict_rescore_skips_affected(self):
        """_post_verdict_rescore should not touch verdicts other than Not Affected."""
        from src.agents.verdict import _post_verdict_rescore

        verdict_dict = {
            "verdict": "Affected",
            "affected": True,
            "adjusted_cvss": {"adjusted_score": 9.4},
        }
        result = _post_verdict_rescore(verdict_dict, ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"], {})
        # Should be unchanged.
        assert result["adjusted_cvss"]["adjusted_score"] == 9.4
