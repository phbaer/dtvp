"""Authenticated CVSS metric descriptions for presentation clients."""

import importlib

from fastapi import APIRouter, HTTPException

from dtvp.api import Auth
from dtvp.api_contract import API_PREFIX
from dtvp.rescoring import (
    BASE,
)

router = APIRouter(prefix=API_PREFIX)


@router.get("/cvss/metrics/{version}")
def metric_catalog(version: str, actor: Auth):
    if version not in BASE:
        raise HTTPException(422, "Unsupported CVSS version")
    constants = importlib.import_module(f"cvss.constants{version[0]}")
    return {
        "version": version,
        "metrics": [
            {
                "key": key,
                "name": name,
                "base": key in BASE[version],
                "values": [
                    {"value": value, "name": label}
                    for value, label in constants.METRICS_VALUE_NAMES[key].items()
                ],
            }
            for key, name in constants.METRICS_ABBREVIATIONS.items()
        ],
    }
