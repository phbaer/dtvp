"""Read-only provider ports. Matching and advisory enrichment are separate operations."""

import copy
import json
import re
from typing import Protocol
from urllib.parse import quote

import httpx
from packageurl import PackageURL


class Matcher(Protocol):
    def query(self, purl: str) -> dict: ...


class AdvisoryProvider(Protocol):
    def get(self, identifier: str) -> dict: ...


def read_json(client, method, url, *, missing_analysis=False, **kwargs):
    # Fixed deployment-controlled URLs, redirects disabled, bounded responses.
    with client.stream(method, url, **kwargs) as response:
        if missing_analysis and response.status_code == 404:
            response.read()
            if response.text.strip() == "No analysis exists.":
                return {}
        response.raise_for_status()
        raw = bytearray()
        for block in response.iter_bytes():
            raw.extend(block)
            if len(raw) > 32 * 1024 * 1024:
                raise ValueError("Provider response exceeds 32 MiB")
        return json.loads(raw)


def osv_advisory(value):
    ratings = []
    for severity in value.get("severity", []):
        if severity.get("type") in {"CVSS_V3", "CVSS_V4"}:
            ratings.append({"vector": severity["score"], "method": severity["type"]})
    return {
        "id": value["id"],
        "description": value.get("details", value.get("summary", "")),
        "aliases": [{"id": alias, "source": "OSV"} for alias in value.get("aliases", [])],
        "ratings": ratings,
        "references": value.get("references", []),
        "published": value.get("published"),
        "modified": value.get("modified"),
        "affected": value.get("affected", []),
        "upstream": value,
    }


class OSV:
    def __init__(self, client):
        self.client = client

    def query(self, purl):
        package = PackageURL.from_string(purl)
        if not package.version:
            return {"status": "unsupported", "reason": "Versioned PURL required", "advisories": []}
        if package.qualifiers or package.subpath:
            return {
                "status": "unsupported",
                "reason": "Qualified/artifact PURLs require a dedicated matcher",
                "advisories": [],
            }
        values, token = [], None
        for _ in range(20):
            request = {"package": {"purl": package.to_string()}}
            if token:
                request["page_token"] = token
            response = read_json(self.client, "POST", "https://api.osv.dev/v1/query", json=request)
            values.extend(osv_advisory(value) for value in response.get("vulns", []))
            token = response.get("next_page_token")
            if not token:
                return {
                    "status": "checked",
                    "advisories": values,
                    "method": "osv-package-version",
                    "purl": package.to_string(),
                }
        raise ValueError("OSV pagination limit reached; coverage is incomplete")


class NVD:
    def __init__(self, client):
        self.client = client

    def get(self, identifier):
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", identifier):
            return {"kind": "advisory", "status": "unsupported", "identifier": identifier}
        data = read_json(
            self.client,
            "GET",
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": identifier},
        )
        values = data.get("vulnerabilities", [])
        if not values:
            return {"kind": "advisory", "status": "not_found", "identifier": identifier}
        cve = values[0]["cve"]
        ratings = [
            {
                "vector": metric["cvssData"]["vectorString"],
                "score": metric["cvssData"]["baseScore"],
                "source": metric.get("source"),
            }
            for entries in cve.get("metrics", {}).values()
            for metric in entries
            if metric.get("cvssData")
        ]
        return {
            "kind": "advisory",
            "status": "found",
            "publisher": "NVD",
            "upstream": data,
            "advisory": {
                "id": identifier,
                "description": next(
                    (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
                ),
                "ratings": ratings,
                "references": cve.get("references", []),
                "modified": cve.get("lastModified"),
            },
        }


class CIRCL:
    def __init__(self, client):
        self.client = client

    def get(self, identifier):
        data = read_json(
            self.client,
            "GET",
            f"https://vulnerability.circl.lu/api/vulnerability/{quote(identifier, safe='')}",
        )
        if not data:
            return {"kind": "advisory", "status": "not_found", "identifier": identifier}
        # CVE 5 records retain publisher identity; mirrors are not independent confirmation.
        cna = data.get("containers", {}).get("cna", {})
        return {
            "kind": "advisory",
            "status": "found",
            "publisher": cna.get("providerMetadata", {}),
            "upstream": data,
            "advisory": {
                "id": identifier,
                "description": next(
                    (d["value"] for d in cna.get("descriptions", []) if d.get("lang") == "en"), ""
                ),
                "references": cna.get("references", []),
                "ratings": [
                    {"vector": metric[key]["vectorString"], "score": metric[key]["baseScore"]}
                    for metric in cna.get("metrics", [])
                    for key in ("cvssV3_0", "cvssV3_1", "cvssV4_0")
                    if key in metric
                ],
            },
        }


class DemoMatcher:
    """Synthetic offline adapter shared by interactive and automatic tests."""

    def __init__(self, client):
        pass

    def query(self, purl):
        advisories = []
        if purl == "pkg:npm/demo-utility@3.0.0":
            advisories = [
                {
                    "id": "CVE-2099-20003",
                    "description": "Synthetic locally matched utility finding.",
                    "ratings": [
                        {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "score": 7.5}
                    ],
                    "references": [{"url": "https://example.invalid/synthetic-advisory"}],
                }
            ]
        return {"status": "checked", "method": "synthetic-exact-purl", "advisories": advisories}


class DemoFailure(DemoMatcher):
    def query(self, purl):
        raise ValueError("Simulated source timeout; coverage remains unknown")


MATCHERS = {"osv": OSV, "demo": DemoMatcher, "demo-failure": DemoFailure}
ADVISORY_PROVIDERS = {"nvd": NVD, "circl": CIRCL}


def import_dt(client, base_url, key, project_id):
    prefix = base_url.rstrip("/") + "/api/v1"
    headers = {"X-Api-Key": key}
    bom = read_json(
        client,
        "GET",
        f"{prefix}/bom/cyclonedx/project/{quote(project_id, safe='')}",
        headers=headers,
    )
    bom = copy.deepcopy(bom)
    components = {}

    def visit(values):
        for component in values:
            components[component["bom-ref"]] = component
            visit(component.get("components", []))

    visit(bom.get("components", []))
    vulnerabilities = []
    for page in range(1, 1001):
        batch = read_json(
            client,
            "GET",
            f"{prefix}/finding/project/{quote(project_id, safe='')}",
            headers=headers,
            params={"suppressed": "true", "pageNumber": page, "pageSize": 100},
        )
        if not isinstance(batch, list):
            raise ValueError("Unexpected DT finding response")
        for item in batch:
            component, advisory = item["component"], item["vulnerability"]
            ref = component.get("bomRef") or component.get("uuid")
            if ref not in components:
                purl = component.get("purl")
                matches = [
                    ref
                    for ref, candidate in components.items()
                    if purl and candidate.get("purl") == purl
                ]
                if len(matches) != 1:
                    raise ValueError("DT finding cannot be bound uniquely to exported SBOM")
                ref = matches[0]
            analysis = read_json(
                client,
                "GET",
                f"{prefix}/analysis",
                headers=headers,
                params={
                    "project": project_id,
                    "component": component["uuid"],
                    "vulnerability": advisory["uuid"],
                },
                missing_analysis=True,
            )
            item = {**item, "analysis": analysis or item.get("analysis", {})}
            normalized = analysis.get("analysis", analysis) if analysis else item["analysis"]
            rating = {
                "vector": advisory.get("cvssV3Vector") or advisory.get("cvssV4Vector") or "",
                "score": advisory.get("cvssV3BaseScore", advisory.get("cvssV4Score")),
            }
            rating = {field: value for field, value in rating.items() if value is not None}
            from dtvp.legacy_dt import STATES

            state = STATES.get(normalized.get("analysisState"))
            state = {"under_investigation": "in_triage", "fixed": "resolved"}.get(state, state)
            vulnerabilities.append(
                {
                    "id": advisory["vulnId"],
                    "source": {"name": advisory.get("source", "DT")},
                    "description": advisory.get("description", ""),
                    "ratings": [rating],
                    "affects": [{"ref": ref}],
                    "analysis": {
                        "detail": normalized.get("analysisDetails", ""),
                        **({"state": state} if state else {}),
                    },
                    "properties": [
                        {"name": "dtvp:dt-source", "value": json.dumps(item)},
                        {"name": "dtvp:dt-analysis", "value": json.dumps(item["analysis"])},
                    ],
                }
            )
        if len(batch) < 100:
            break
    else:
        raise ValueError("DT pagination limit reached")
    bom["vulnerabilities"] = vulnerabilities
    return bom


def client():
    return httpx.Client(timeout=30, follow_redirects=False)
