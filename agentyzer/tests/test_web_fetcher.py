import asyncio
from contextlib import asynccontextmanager

from src.agents import web_fetcher


class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class FakeClient:
    def __init__(self, *, get_responses=None, post_responses=None):
        self.get_responses = get_responses or {}
        self.post_responses = list(post_responses or [])
        self.get_calls = []
        self.post_calls = []

    async def get(self, url, **kwargs):
        self.get_calls.append((url, kwargs))
        response = self.get_responses[url]
        if isinstance(response, Exception):
            raise response
        return response

    async def post(self, url, **kwargs):
        self.post_calls.append((url, kwargs))
        response = self.post_responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def install_fake_client(monkeypatch, client):
    @asynccontextmanager
    async def fake_async_client(**kwargs):
        assert kwargs["timeout"] in {20, 30}
        yield client

    monkeypatch.setattr(web_fetcher, "async_client", fake_async_client)


def test_guess_ecosystem_prefers_manifest_evidence():
    assert web_fetcher.guess_ecosystem("anything", {"declared_in": ["ui/package.json"]}) == "npm"
    assert web_fetcher.guess_ecosystem("anything", {"lock_files": ["api/uv.lock"]}) == "PyPI"
    assert web_fetcher.guess_ecosystem("@scope/pkg") == "npm"
    assert web_fetcher.guess_ecosystem("com.example.library") == "Maven"
    assert web_fetcher.guess_ecosystem("ambiguous") is None


def test_discover_vulnerabilities_caps_pagination_and_sorts(monkeypatch):
    responses = []
    for index in range(5):
        responses.append(
            FakeResponse(
                200,
                {
                    "vulns": [
                        {
                            "id": f"OSV-{index}",
                            "summary": f"Issue {index}",
                            "database_specific": {
                                "cvss": float(index + 1),
                                "cwe_ids": [f"CWE-{100 + index}"],
                            },
                        }
                    ],
                    "next_page_token": f"page-{index}",
                },
            )
        )
    client = FakeClient(post_responses=responses)
    install_fake_client(monkeypatch, client)

    vulns = asyncio.run(web_fetcher.discover_vulnerabilities("demo", "PyPI"))

    assert [vuln["id"] for vuln in vulns] == [
        "OSV-4",
        "OSV-3",
        "OSV-2",
        "OSV-1",
        "OSV-0",
    ]
    assert len(client.post_calls) == 5
    assert "page_token" not in client.post_calls[0][1]["json"]
    assert client.post_calls[1][1]["json"]["page_token"] == "page-0"


def test_discover_vulnerabilities_rejects_malformed_payload(monkeypatch):
    client = FakeClient(post_responses=[FakeResponse(200, ["not-an-object"])])
    install_fake_client(monkeypatch, client)

    assert asyncio.run(web_fetcher.discover_vulnerabilities("demo", "npm")) == []
    assert asyncio.run(web_fetcher.discover_vulnerabilities("demo", None)) == []


def test_fetch_advisory_normalizes_sources_and_encodes_identifiers(monkeypatch):
    vuln_id = "CVE-2026-1/../../?scope=test"
    encoded_id = "CVE-2026-1%2F..%2F..%2F%3Fscope%3Dtest"
    ghsa_id = "GHSA-aaaa-bbbb-cccc"
    osv = {
        "aliases": [ghsa_id, None],
        "summary": "Parser.run() can trigger CWE-79",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "demo"},
                "ranges": [
                    {
                        "type": "GIT",
                        "events": [
                            {"introduced": "abc"},
                            {"fixed": "def"},
                        ],
                    }
                ],
                "versions": ["v1.0.0", "1.1.0"],
                "database_specific": {"cwe_ids": ["CWE-79"]},
            }
        ],
        "database_specific": {
            "cwe_ids": ["CWE-89"],
            "cvss": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        },
    }
    osv_ghsa = {
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "@scope/demo"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "2.0.0"},
                        ],
                    }
                ],
            }
        ],
        "database_specific": {"cwe_ids": ["CWE-20"], "cvss": 8.8},
    }
    nvd = {
        "vulnerabilities": [
            {
                "cve": {
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"vectorString": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L"}}
                        ],
                        "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}],
                    },
                    "weaknesses": [{"description": [{"value": "CWE-22"}]}],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {"criteria": "cpe:2.3:a:vendor:demo_product:*:*:*:*:*:*:*:*"}
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }
    github_advisory = {
        "summary": "Structured GHSA summary",
        "vulnerabilities": [
            {
                "package": {"ecosystem": "pip", "name": "demo"},
                "vulnerable_version_range": ">= 1.0, < 2.1",
                "first_patched_version": "=2.1.0",
                "vulnerable_functions": ["demo.parse"],
            }
        ],
        "cvss": {"vector_string": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
        "cwes": [{"cwe_id": "CWE-94"}],
    }
    client = FakeClient(
        get_responses={
            f"https://api.osv.dev/v1/vulns/{encoded_id}": FakeResponse(200, osv),
            f"https://api.osv.dev/v1/vulns/{ghsa_id}": FakeResponse(200, osv_ghsa),
            "https://services.nvd.nist.gov/rest/json/cves/2.0": FakeResponse(200, nvd),
            f"https://api.github.com/advisories/{ghsa_id}": FakeResponse(200, github_advisory),
            "https://api.github.com/search/issues": FakeResponse(
                200,
                {"items": [{"title": "Demo.parse()", "body": "Namespace::method CWE-94"}]},
            ),
        }
    )
    install_fake_client(monkeypatch, client)

    advisory = asyncio.run(web_fetcher.fetch_advisory(vuln_id))

    assert advisory["summary"] == "Parser.run() can trigger CWE-79"
    assert {"PyPI:demo", "npm:@scope/demo", "pip:demo", "NVD:demo_product"} <= set(
        advisory["affected_packages"]
    )
    assert {"1.0.0", "1.1.0"} == set(advisory["affected_versions"])
    assert "2.1.0" in advisory["fixed_versions"]
    assert {"CWE-79", "CWE-89", "CWE-20", "CWE-22", "CWE-94"} <= set(advisory["cwe"])
    assert {"demo.parse", "Parser.run"} <= set(
        advisory["vulnerable_symbols"]
    )
    assert advisory["cpe_entries"][0]["product"] == "demo_product"
    assert {item["source"] for item in advisory["affected_ranges"]} == {
        "osv",
        "osv_ghsa",
        "github_advisory",
    }
    assert advisory["data_warnings"] == []

    calls = dict(client.get_calls)
    assert calls["https://services.nvd.nist.gov/rest/json/cves/2.0"]["params"] == {
        "cveId": vuln_id
    }
    assert "https://api.github.com/search/issues" not in calls
    assert all("../" not in url and "?scope=" not in url for url, _ in client.get_calls)


def test_fetch_advisory_degrades_safely_on_network_errors(monkeypatch):
    client = FakeClient(
        get_responses={
            "https://api.osv.dev/v1/vulns/CVE-2026-9": RuntimeError("OSV offline"),
            "https://services.nvd.nist.gov/rest/json/cves/2.0": RuntimeError("NVD offline"),
            "https://api.github.com/search/issues": RuntimeError("GitHub offline"),
        }
    )
    install_fake_client(monkeypatch, client)

    advisory = asyncio.run(web_fetcher.fetch_advisory("CVE-2026-9"))

    assert advisory["raw"] == {
        "osv_error": "OSV offline",
        "nvd_error": "NVD offline",
        "github_error": "GitHub offline",
    }
    assert len(advisory["data_warnings"]) == 3
    assert advisory["affected_packages"] == []


def test_fetch_advisory_tolerates_non_object_success_payloads(monkeypatch):
    client = FakeClient(
        get_responses={
            "https://api.osv.dev/v1/vulns/CVE-2026-10": FakeResponse(200, ["bad"]),
            "https://services.nvd.nist.gov/rest/json/cves/2.0": FakeResponse(200, ["bad"]),
            "https://api.github.com/search/issues": FakeResponse(200, ["bad"]),
        }
    )
    install_fake_client(monkeypatch, client)

    advisory = asyncio.run(web_fetcher.fetch_advisory("CVE-2026-10"))

    assert advisory["summary"] == ""
    assert advisory["affected_packages"] == []
    assert len(advisory["data_warnings"]) == 3


def test_fetch_advisory_tolerates_malformed_nested_osv_fields(monkeypatch):
    client = FakeClient(
        get_responses={
            "https://api.osv.dev/v1/vulns/CVE-2026-11": FakeResponse(
                200,
                {
                    "aliases": [None, {"bad": "alias"}],
                    "summary": {"unexpected": "object"},
                    "affected": [None, {"package": "bad", "ranges": "bad", "versions": [1]}],
                    "severity": [None, "bad"],
                    "database_specific": {"cwe_ids": "CWE-79"},
                },
            ),
            "https://services.nvd.nist.gov/rest/json/cves/2.0": FakeResponse(404, {}),
            "https://api.github.com/search/issues": FakeResponse(200, {"items": [None]}),
        }
    )
    install_fake_client(monkeypatch, client)

    advisory = asyncio.run(web_fetcher.fetch_advisory("CVE-2026-11"))

    assert advisory["summary"] == "{'unexpected': 'object'}"
    assert advisory["affected_packages"] == []
    assert len(advisory["data_warnings"]) == 2


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
    assert client.calls[1][0][0] == (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
    )
    assert client.calls[1][1]["params"] == {"cveId": "CVE-2024-45296"}
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
