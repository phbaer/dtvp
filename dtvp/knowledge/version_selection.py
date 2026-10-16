"""Closed finite selection of current product branches, never dynamic assessment coverage."""

import re

from pydantic import Field, model_validator

from dtvp.knowledge.journal import Name
from dtvp.schemas import RequestModel

MAX_VERSION_HEADS = 1000
MAX_SELECTION_ROWS = 1000
RELEASE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", re.ASCII)


def numeric_release(value):
    if not isinstance(value, str) or len(value) > 200 or not RELEASE.fullmatch(value):
        return None
    return tuple(int(part) for part in value.split("."))


class VersionSelection(RequestModel):
    lower: Name | None = None
    upper: Name | None = None
    include: list[Name] = Field(default_factory=list, max_length=200)
    exclude: list[Name] = Field(default_factory=list, max_length=200)

    @model_validator(mode="after")
    def validate_selection(self):
        for bound in (self.lower, self.upper):
            if bound is not None and numeric_release(bound) is None:
                raise ValueError("Range bounds require strict numeric major.minor.patch labels")
        if self.lower and self.upper and numeric_release(self.lower) > numeric_release(self.upper):
            raise ValueError("Lower version bound must not exceed upper bound")
        if len(set(self.include)) != len(self.include) or len(set(self.exclude)) != len(
            self.exclude
        ):
            raise ValueError("Include and exclude version labels must each be distinct")
        if set(self.include) & set(self.exclude):
            raise ValueError("A version cannot be both explicitly included and excluded")
        return self


def select_versions(heads, selection):
    if len(heads) > MAX_VERSION_HEADS:
        raise ValueError("Version selection exceeds the complete 1000-head budget")
    unknown = (set(selection.include) | set(selection.exclude)) - set(heads)
    if unknown:
        raise ValueError("Explicit version labels must name current product branches")
    lower, upper = numeric_release(selection.lower), numeric_release(selection.upper)
    rows, selected = [], []
    for version, state in sorted(heads.items()):
        number = numeric_release(version)
        if version in selection.exclude:
            status = "excluded_explicitly"
        elif version in selection.include:
            status = "selected_explicitly"
        elif number is None:
            status = "unknown_ordering"
        elif (lower is None or number >= lower) and (upper is None or number <= upper):
            status = "selected_numeric_range"
        else:
            status = "outside_numeric_range"
        if status.startswith("selected_"):
            selected.append(version)
        rows.append({"version": version, "state": state, "status": status})
    return {
        "format": "dtvp.closed-version-selection/1",
        "selector": selection.model_dump(mode="json"),
        "captured_versions": len(heads),
        "selected_versions": selected,
        "versions": rows,
        "semantics": "Inclusive numeric release bounds over these exact current heads only; other labels require explicit inclusion. No future version, applicability or approval is implied.",
    }
