from datetime import datetime
from unittest.mock import Mock

import pytest

from dtvp.runtime_value_services import get_env_int_with_floor, parse_iso_timestamp


def test_get_env_int_with_floor_uses_default_and_minimum(monkeypatch):
    monkeypatch.delenv("DTVP_TEST_LIMIT", raising=False)
    logger = Mock()

    assert (
        get_env_int_with_floor(
            "DTVP_TEST_LIMIT",
            default=10,
            minimum=2,
            logger=logger,
        )
        == 10
    )

    monkeypatch.setenv("DTVP_TEST_LIMIT", "1")
    assert (
        get_env_int_with_floor(
            "DTVP_TEST_LIMIT",
            default=10,
            minimum=2,
            logger=logger,
        )
        == 2
    )
    logger.warning.assert_not_called()


def test_get_env_int_with_floor_warns_and_falls_back_for_invalid_value(monkeypatch):
    monkeypatch.setenv("DTVP_TEST_LIMIT", "many")
    logger = Mock()

    result = get_env_int_with_floor(
        "DTVP_TEST_LIMIT",
        default=10,
        minimum=2,
        logger=logger,
    )

    assert result == 10
    logger.warning.assert_called_once_with(
        "Invalid %s=%r, falling back to %s",
        "DTVP_TEST_LIMIT",
        "many",
        10,
    )


@pytest.mark.parametrize("value", [None, "", "not-a-date", object()])
def test_parse_iso_timestamp_returns_none_for_missing_or_invalid_values(value):
    assert parse_iso_timestamp(value) is None


def test_parse_iso_timestamp_parses_valid_value():
    value = "2026-07-15T10:30:00+00:00"

    assert parse_iso_timestamp(value) == datetime.fromisoformat(value).timestamp()
