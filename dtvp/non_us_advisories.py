"""Exact-ID EUVD and MyJVN adapters; no alias search or package matching."""

import math
import re

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

EUVD_URL = "https://euvdservices.enisa.europa.eu/api/enisaid"
JVN_URL = "https://jvndb.jvn.jp/myjvn"
IDENTIFIER_FORMATS = {
    "nvd": ["CVE"],
    "circl": ["CVE"],
    "euvd": ["CVE", "EUVD"],
    "jvn": ["JVNDB"],
}
PATTERNS = {
    "CVE": r"CVE-\d{4}-\d{4,194}",
    "EUVD": r"EUVD-\d{4}-\d{1,190}",
    "JVNDB": r"JVNDB-\d{4}-\d{6}",
}


def supports_identifier(provider, identifier):
    return (
        isinstance(identifier, str)
        and len(identifier) <= 200
        and any(
            re.fullmatch(PATTERNS[kind], identifier)
            for kind in IDENTIFIER_FORMATS.get(provider, [])
        )
    )


def request_parameters(provider, identifier):
    if provider == "euvd":
        return {"id": identifier}
    if provider == "jvn":
        return {
            "method": "getVulnDetailInfo",
            "feed": "hnd",
            "vulnId": identifier,
            "lang": "en",
            "maxCountItem": "1",
        }
    return {"cveId": identifier} if provider == "nvd" else {}


def _missing(identifier):
    return {"kind": "advisory", "status": "not_found", "identifier": identifier}


def _lines(value):
    if not isinstance(value, str):
        raise ValueError("EUVD aliases and references must be text")
    return sorted(set(part.strip() for part in re.split(r"(?:\\n|\r?\n)", value) if part.strip()))


def euvd_result(identifier, body, status=200):
    if status == 204:
        if body is not None:
            raise ValueError("EUVD no-content response contains a body")
        return _missing(identifier)
    if (
        not isinstance(body, dict)
        or not supports_identifier("euvd", body.get("id"))
        or not body["id"].startswith("EUVD-")
    ):
        raise ValueError("EUVD requires an exact identified record")
    aliases = _lines(body.get("aliases", ""))
    # A returned alias is evidence binding this exact request, never a new finding.
    if identifier != body["id"] and identifier not in aliases:
        raise ValueError("EUVD upstream identifier differs from requested identifier")
    score = body.get("baseScore")
    if score is not None and (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not math.isfinite(score)
        or not 0 <= score <= 10
    ):
        raise ValueError("EUVD score must be finite and between zero and ten")
    if identifier.startswith("CVE-"):
        linked = body.get("enisaIdVulnerability", [])
        if not isinstance(linked, list) or any(
            not isinstance(item, dict)
            or not isinstance(item.get("vulnerability"), dict)
            or not isinstance(item["vulnerability"].get("id"), str)
            for item in linked
        ):
            raise ValueError(
                "EUVD vulnerability relationships must identify their upstream records"
            )
        cves = {value for value in aliases if supports_identifier("nvd", value)}
        cves.update(
            item["vulnerability"]["id"]
            for item in linked
            if supports_identifier("nvd", item["vulnerability"]["id"])
        )
        if cves != {identifier}:
            raise ValueError(
                "EUVD aggregate covers multiple or contradictory CVE identifiers; exact CVE enrichment is ambiguous"
            )
    ratings = []
    if body.get("baseScore") is not None or body.get("baseScoreVector"):
        ratings = [
            {
                key: value
                for key, value in {
                    "score": body.get("baseScore"),
                    "vector": body.get("baseScoreVector"),
                    "source": "EUVD",
                    "method": body.get("baseScoreVersion"),
                }.items()
                if value is not None
            }
        ]
    return {
        "kind": "advisory",
        "status": "found",
        "publisher": "ENISA EUVD",
        "upstream": body,
        "advisory": {
            "id": identifier,
            "source": {"name": "ENISA EUVD"},
            "description": body.get("description", ""),
            "ratings": ratings,
            "aliases": [
                {"id": value, "source": "EUVD"}
                for value in sorted(set([body["id"], *aliases]) - {identifier})
            ],
            "references": [{"url": value} for value in _lines(body.get("references", ""))],
            "published": body.get("datePublished"),
            "modified": body.get("dateUpdated"),
        },
    }


def jvn_result(identifier, body):
    if not isinstance(body, dict) or set(body) != {"xml"} or not isinstance(body["xml"], str):
        raise ValueError("JVN requires its original XML representation")
    try:
        root = ElementTree.fromstring(
            body["xml"], forbid_dtd=True, forbid_entities=True, forbid_external=True
        )
    except (ElementTree.ParseError, DefusedXmlException) as error:
        raise ValueError("Malformed or unsafe MyJVN XML") from error
    namespaces = {"http://jvn.jp/vuldef/", "https://jvn.jp/vuldef/"}
    namespace = next((ns for ns in namespaces if root.tag == "{" + ns + "}VULDEF-Document"), None)
    if namespace is None or root.get("version") not in {"3.1", "3.2"}:
        raise ValueError("Unsupported MyJVN XML root")
    pending, count = [(root, 0)], 0
    while pending:
        element, depth = pending.pop()
        count += 1
        if depth > 64 or count > 100_000:
            raise ValueError("MyJVN XML exceeds supported structural bounds")
        pending.extend((child, depth + 1) for child in element)
    ns = {"v": namespace}
    statuses = root.findall("{http://jvndb.jvn.jp/myjvn/Status}Status")
    if len(statuses) != 1:
        raise ValueError("MyJVN requires one successful status")
    status = statuses[0].attrib
    if (
        any(
            status.get(key) != value
            for key, value in {
                "method": "getVulnDetailInfo",
                "feed": "hnd",
                "retCd": "0",
                "vulnId": identifier,
            }.items()
        )
        or status.get("errCd", "")
        or status.get("errMsg", "")
    ):
        raise ValueError("MyJVN status failed or differs from the exact request")
    values = root.findall("v:Vulinfo", ns)
    if (
        len(values) > 1
        or status.get("totalRes") != str(len(values))
        or status.get("totalResRet") != str(len(values))
    ):
        raise ValueError("MyJVN exact lookup count differs or is incomplete")
    if not values:
        return _missing(identifier)
    item = values[0]
    if item.findtext("v:VulinfoID", namespaces=ns) != identifier:
        raise ValueError("MyJVN upstream identifier differs from requested identifier")
    data = item.find("v:VulinfoData", ns)
    if data is None:
        raise ValueError("MyJVN record lacks vulnerability data")
    aliases, references, cwes = [], [], []
    for related in data.findall("v:Related/v:RelatedItem", ns):
        value = related.findtext("v:VulinfoID", namespaces=ns)
        url = related.findtext("v:URL", namespaces=ns)
        if value and supports_identifier("nvd", value):
            aliases.append({"id": value, "source": "MyJVN"})
        if value and related.get("type") == "cwe":
            cwes.append(value)
        if url:
            references.append({"url": url})
    ratings = []
    for metric in data.findall("v:Impact/v:Cvss", ns):
        score = metric.findtext("v:Base", namespaces=ns)
        vector = metric.findtext("v:Vector", namespaces=ns)
        rating = {"source": "MyJVN", "method": metric.get("version")}
        if score:
            try:
                rating["score"] = float(score)
                if not math.isfinite(rating["score"]) or not 0 <= rating["score"] <= 10:
                    raise ValueError("MyJVN score is outside its supported range")
            except ValueError as error:
                raise ValueError("MyJVN score must be numeric") from error
        if vector:
            rating["vector"] = vector
        if score or vector:
            ratings.append(rating)
    return {
        "kind": "advisory",
        "status": "found",
        "publisher": "MyJVN API (IPA/JVN iPedia)",
        "upstream": body,
        "advisory": {
            "id": identifier,
            "source": {"name": "MyJVN API (IPA/JVN iPedia)"},
            "description": data.findtext(
                "v:VulinfoDescription/v:Overview", default="", namespaces=ns
            ),
            "ratings": ratings,
            "references": references,
            "aliases": aliases,
            "cwes": cwes,
            "published": data.findtext("v:DateFirstPublished", namespaces=ns),
            "modified": data.findtext("v:DateLastUpdated", namespaces=ns),
        },
    }


def read_body(client, url, params):
    with client.stream(
        "GET", url, params=params, headers={"User-Agent": "DTVP/knowledge-advisory"}
    ) as response:
        response.raise_for_status()
        raw = bytearray()
        for block in response.iter_bytes():
            raw.extend(block)
            if len(raw) > 4 * 1024 * 1024:
                raise ValueError("Advisory response exceeds 4 MiB")
        return response.status_code, bytes(raw)


class EUVD:
    def __init__(self, client):
        self.client = client

    def get(self, identifier):
        from dtvp.knowledge.advisory_sources import _json

        status, raw = read_body(self.client, EUVD_URL, request_parameters("euvd", identifier))
        return euvd_result(identifier, None if status == 204 and not raw else _json(raw), status)


class JVN:
    def __init__(self, client):
        self.client = client

    def get(self, identifier):
        _, raw = read_body(self.client, JVN_URL, request_parameters("jvn", identifier))
        return jvn_result(identifier, {"xml": raw.decode("utf-8")})
