import pytest

from dtvp.rescoring import calculate

BASE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


VECTOR = BASE + "/MAV:P/MAC:H/MPR:H/MUI:R/MC:N/MI:N/MA:N"


@pytest.mark.parametrize(
    "vector",
    [
        BASE.replace("AV:N", "AV:P"),
        VECTOR.replace("CVSS:3.1", "CVSS:3.0"),
        BASE + "/AV:P",
        BASE + "/MC:BAD",
    ],
)
def test_base_metrics_version_duplicates_and_values_cannot_be_changed(vector):
    with pytest.raises(ValueError):
        calculate(BASE, vector)


@pytest.mark.parametrize(
    "base,contextual",
    [
        ("AV:N/AC:L/Au:N/C:C/I:C/A:C", "AV:N/AC:L/Au:N/C:C/I:C/A:C/TD:N"),
        (BASE.replace("3.1", "3.0"), VECTOR.replace("3.1", "3.0")),
        (
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/MVC:N/MVI:N/MVA:N",
        ),
    ],
)
def test_calculator_supports_all_v1_specification_versions(base, contextual):
    assert calculate(base, contextual)["score"] == 0
