"""The settings files River reads, with the rules a new version must meet.

Every write of a settings file goes through ``write_settings_file``: the
document is validated first and then written atomically, so a rejected or
interrupted write leaves the previous file as it was. The instance dump
(``dtvp.backup``) uses the same registry to find the files.
"""

import json
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from . import logic
from .file_io_services import atomic_write_bytes, json_document_bytes
from .rescore_rule_services import validate_rescore_rule_config
from .team_group_services import validate_team_group_config
from .team_config import is_team_format, team_config_errors
from .team_mapping import team_mapping_key_errors

Validator = Callable[[Any, Mapping[str, Any]], list[str]]


class SettingsValidationError(ValueError):
    """A settings document violates the rules of its file."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


@dataclass(frozen=True)
class SettingsFile:
    name: str
    path_provider: Callable[[], str]
    validate: Validator

    def path(self) -> str:
        return self.path_provider()


def _object(message: str) -> Validator:
    def validate(parsed: Any, _context: Mapping[str, Any]) -> list[str]:
        return [] if isinstance(parsed, dict) else [message]

    return validate


def validate_user_roles_config(config: Any) -> list[str]:
    """A role map: an object whose keys (user names) and values (roles) are
    strings."""
    if not isinstance(config, dict):
        return ["User roles must be a JSON object"]
    return [
        f"Role of {key!r} must be a string"
        for key, value in config.items()
        if not isinstance(key, str) or not isinstance(value, str)
    ]


def _team_mapping(parsed: Any, _context: Mapping[str, Any]) -> list[str]:
    """Organised by team (``dtvp.team_config.team_config_errors``), or the
    older selector format whose keys must be valid selectors: unknown or
    contradicting modifiers are rejected, not read as names."""
    if not isinstance(parsed, dict):
        return ["Team mapping must be a JSON object"]
    if is_team_format(parsed):
        return team_config_errors(parsed)
    return team_mapping_key_errors(parsed)


def _team_groups(parsed: Any, context: Mapping[str, Any]) -> list[str]:
    return validate_team_group_config(parsed, context.get("team_mapping") or {})


def _user_roles(parsed: Any, _context: Mapping[str, Any]) -> list[str]:
    return validate_user_roles_config(parsed)


def _rescore_rules(parsed: Any, _context: Mapping[str, Any]) -> list[str]:
    return validate_rescore_rule_config(parsed)


# Ordered; the dump lists the files in this order. Path providers look the
# function up on each call so that tests and configuration changes apply.
SETTINGS_FILES: tuple[SettingsFile, ...] = (
    SettingsFile(
        "team_mapping",
        lambda: logic.get_team_mapping_path(),
        _team_mapping,
    ),
    SettingsFile(
        "team_groups",
        lambda: logic.get_team_groups_path(),
        _team_groups,
    ),
    SettingsFile(
        "user_roles",
        lambda: logic.get_user_roles_path(),
        _user_roles,
    ),
    SettingsFile(
        "rescore_rules",
        lambda: logic.get_rescore_rules_path(),
        _rescore_rules,
    ),
    SettingsFile(
        "auto_analysis_guidance",
        lambda: logic.get_auto_analysis_guidance_path(),
        _object("Auto-analysis guidance JSON must be an object"),
    ),
)

SETTINGS_FILE_NAMES = tuple(item.name for item in SETTINGS_FILES)


def get_settings_file(name: str) -> SettingsFile:
    for item in SETTINGS_FILES:
        if item.name == name:
            return item
    raise KeyError(f"Unknown settings file: {name}")


def validate_settings_document(
    name: str,
    parsed: Any,
    context: Mapping[str, Any] | None = None,
) -> list[str]:
    return get_settings_file(name).validate(parsed, context or {})


_UNSET: Any = object()


def write_settings_file(
    name: str,
    *,
    payload: Any = _UNSET,
    content: bytes | None = None,
    path: str | None = None,
    context: Mapping[str, Any] | None = None,
) -> str:
    """Validate a settings document, then write it atomically.

    ``content`` is an uploaded file, kept byte for byte; ``payload`` is a
    parsed document, written as JSON with an indent of 2. ``path`` overrides
    the configured location. Raises ``SettingsValidationError`` before
    anything is written. Returns the path written.
    """
    settings_file = get_settings_file(name)
    if content is not None:
        try:
            parsed = json.loads(content)
        except (TypeError, ValueError):
            raise SettingsValidationError(["Invalid JSON"]) from None
        data = bytes(content)
    elif payload is not _UNSET:
        parsed = payload
        data = json_document_bytes(payload)
    else:
        raise ValueError("write_settings_file needs a payload or content")
    errors = settings_file.validate(parsed, context or {})
    if errors:
        raise SettingsValidationError(errors)
    target = path or settings_file.path()
    atomic_write_bytes(target, data)
    return target
