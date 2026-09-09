import asyncio

from src.agents import web_fetcher


class _Response:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


class _Client:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return None

    async def get(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.responses.pop(0)


def test_fetch_advisory_preserves_package_scopes_and_osv_boundaries(monkeypatch):
    osv = {
        "id": "CVE-2026-1234",
        "summary": "Two packages use different affected ranges.",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "wrong-package"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "1.0.0"},
                            {"limit": "2.0.0"},
                        ],
                    }
                ],
                "versions": ["1.5.0"],
            },
            {
                "package": {"ecosystem": "npm", "name": "target-package"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "3.0.0"},
                            {"last_affected": "3.4.7"},
                        ],
                    },
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "4.0.0"},
                            {"fixed": "4.1.0"},
                        ],
                    },
                ],
                "versions": ["3.2.1"],
            },
        ],
    }
    client = _Client(
        [
            _Response(200, osv),
            _Response(404),
            _Response(404),
        ]
    )
    monkeypatch.setattr(web_fetcher, "async_client", lambda **_kwargs: client)

    advisory = asyncio.run(web_fetcher.fetch_advisory("CVE-2026-1234"))

    assert advisory["affected_ranges"] == [
        {
            "type": "SEMVER",
            "event": {"introduced": "1.0.0", "limit": "2.0.0"},
            "source": "osv",
            "package": "wrong-package",
            "ecosystem": "npm",
        },
        {
            "type": "SEMVER",
            "event": {"introduced": "3.0.0", "last_affected": "3.4.7"},
            "source": "osv",
            "package": "target-package",
            "ecosystem": "npm",
        },
        {
            "type": "SEMVER",
            "event": {"introduced": "4.0.0", "fixed": "4.1.0"},
            "source": "osv",
            "package": "target-package",
            "ecosystem": "npm",
        },
    ]
    assert advisory["affected_version_entries"] == [
        {
            "version": "1.5.0",
            "source": "osv",
            "package": "wrong-package",
            "ecosystem": "npm",
        },
        {
            "version": "3.2.1",
            "source": "osv",
            "package": "target-package",
            "ecosystem": "npm",
        },
    ]
    assert advisory["fixed_versions"] == ["4.1.0"]
    assert advisory["fixed_version_entries"] == [
        {
            "version": "4.1.0",
            "source": "osv",
            "package": "target-package",
            "ecosystem": "npm",
        }
    ]


def test_github_advisory_keeps_fix_attached_to_its_release_line(monkeypatch):
    github_advisory = {
        "summary": "Angular template sanitization bypass",
        "vulnerabilities": [
            {
                "package": {"ecosystem": "npm", "name": "@angular/core"},
                "vulnerable_version_range": ">= 21.0.0-next.0, < 21.2.15",
                "first_patched_version": "21.2.15",
            },
            {
                "package": {"ecosystem": "npm", "name": "@angular/core"},
                "vulnerable_version_range": ">= 20.0.0-next.0, < 20.3.22",
                "first_patched_version": "20.3.22",
            },
        ],
    }
    client = _Client(
        [
            _Response(404),
            _Response(200, github_advisory),
        ]
    )
    monkeypatch.setattr(web_fetcher, "async_client", lambda **_kwargs: client)

    advisory = asyncio.run(
        web_fetcher.fetch_advisory("GHSA-F3M7-GQXR-G87X")
    )

    assert advisory["affected_ranges"] == [
        {
            "type": "ECOSYSTEM",
            "event": {
                "range": ">= 21.0.0-next.0, < 21.2.15",
                "fixed": "21.2.15",
            },
            "source": "github_advisory",
            "package": "@angular/core",
            "ecosystem": "npm",
        },
        {
            "type": "ECOSYSTEM",
            "event": {
                "range": ">= 20.0.0-next.0, < 20.3.22",
                "fixed": "20.3.22",
            },
            "source": "github_advisory",
            "package": "@angular/core",
            "ecosystem": "npm",
        },
    ]


def test_uppercase_ghsa_uses_canonical_lookup_ids_and_authenticated_github(
    monkeypatch,
):
    osv = {
        "id": "GHSA-37ch-88jc-xwx2",
        "aliases": ["CVE-2024-45296"],
        "summary": "",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "path-to-regexp"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "0.1.13"},
                        ],
                    }
                ],
            }
        ],
    }
    github_advisory = {
        "summary": "path-to-regexp is vulnerable to regular expression denial of service",
        "vulnerabilities": [],
    }
    client = _Client(
        [
            _Response(200, osv),
            _Response(200, {"vulnerabilities": []}),
            _Response(200, github_advisory),
        ]
    )
    monkeypatch.setattr(web_fetcher, "async_client", lambda **_kwargs: client)
    monkeypatch.setenv("AGENTYZER_GITHUB_TOKEN", "test-token")

    advisory = asyncio.run(
        web_fetcher.fetch_advisory("GHSA-37CH-88JC-XWX2")
    )

    assert client.calls[0][0][0].endswith("/GHSA-37ch-88jc-xwx2")
    assert "cveId=CVE-2024-45296" in client.calls[1][0][0]
    assert client.calls[2][0][0].endswith(
        "/advisories/GHSA-37ch-88jc-xwx2"
    )
    assert client.calls[2][1]["headers"]["Authorization"] == "Bearer test-token"
    assert advisory["id"] == "GHSA-37CH-88JC-XWX2"
    assert advisory["lookup_id"] == "GHSA-37ch-88jc-xwx2"
    assert advisory["summary"] == github_advisory["summary"]
    assert advisory["affected_packages"] == ["npm:path-to-regexp"]
    assert advisory["fixed_versions"] == ["0.1.13"]


def test_failed_advisory_lookups_are_reported_as_failures(monkeypatch):
    client = _Client(
        [
            _Response(404),
            _Response(403),
            _Response(403),
        ]
    )
    monkeypatch.setattr(web_fetcher, "async_client", lambda **_kwargs: client)

    advisory = asyncio.run(
        web_fetcher.fetch_advisory("GHSA-37CH-88JC-XWX2")
    )

    assert advisory["sources"] == []
    assert advisory["lookup_failures"] == [
        "OSV returned HTTP 404",
        "GitHub Advisory returned HTTP 403",
        "GitHub search returned HTTP 403",
    ]
    assert any(
        "Advisory lookup did not return a description" in warning
        for warning in advisory["data_warnings"]
    )
