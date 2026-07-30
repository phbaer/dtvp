from dtvp.team_group_services import (
    canonical_team_group_structure,
    configured_team_names,
    resolve_team_groups,
    validate_team_group_config,
)


TEAM_MAPPING = {
    "core-component": "Core-MUC",
    "vendor-component": ["3rd Party", "Third Party Legacy"],
    "runtime-component": "Runtime",
}


def test_resolve_team_groups_supports_team_named_and_abstract_nested_groups():
    config = {
        "Core-MUC": {
            "teams": ["Core-MUC", "Third Party Legacy"],
            "groups": [],
        },
        "Product Engineering": {
            "teams": ["Runtime"],
            "groups": ["Core-MUC"],
        },
    }

    assert validate_team_group_config(config, TEAM_MAPPING) == []
    assert canonical_team_group_structure(config, TEAM_MAPPING) == {
        "Core-MUC": {
            "teams": ["Core-MUC", "3rd Party"],
            "groups": [],
        },
        "Product Engineering": {
            "teams": ["Runtime"],
            "groups": ["Core-MUC"],
        },
    }
    assert resolve_team_groups(config, TEAM_MAPPING) == {
        "Core-MUC": ["Core-MUC", "3rd Party"],
        "Product Engineering": ["Runtime", "Core-MUC", "3rd Party"],
    }


def test_team_group_validation_rejects_unknown_members_and_cycles():
    config = {
        "Core-MUC": {
            "teams": ["Unknown Team"],
            "groups": ["Product Engineering"],
        },
        "Product Engineering": {
            "teams": [],
            "groups": ["Core-MUC"],
        },
    }

    errors = validate_team_group_config(config, TEAM_MAPPING)

    assert "Team group Core-MUC references unknown configured team Unknown Team" in errors
    assert (
        "Team group cycle detected: Core-MUC -> Product Engineering -> Core-MUC"
        in errors
    )


def test_team_group_validation_requires_explicit_non_empty_members():
    assert validate_team_group_config(
        {"Empty": {"teams": [], "groups": []}},
        TEAM_MAPPING,
    ) == ["Team group Empty must contain at least one team or group"]


def test_configured_team_names_returns_primary_teams_only():
    assert configured_team_names(TEAM_MAPPING) == [
        "3rd Party",
        "Core-MUC",
        "Runtime",
    ]
