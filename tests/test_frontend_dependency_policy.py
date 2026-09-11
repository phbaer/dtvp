import json
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]


def test_frontend_lock_uses_only_the_default_npm_registry():
    lock = json.loads((ROOT / "frontend" / "package-lock.json").read_text())
    resolved_urls = {
        package["resolved"]
        for package in lock["packages"].values()
        if str(package.get("resolved", "")).startswith(("http://", "https://"))
    }

    assert resolved_urls
    assert {urlsplit(url).hostname for url in resolved_urls} == {
        "registry.npmjs.org"
    }

