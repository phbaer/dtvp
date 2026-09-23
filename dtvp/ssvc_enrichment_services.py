"""Bounded, shared official-source cache. Fetching never writes assessments."""

import asyncio
import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
import time
from contextlib import closing
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

import httpx
from jose import JWTError, jwt


logger = logging.getLogger(__name__)
CVE = re.compile(r"CVE-\d{4}-\d{4,19}\Z")
SOURCES = json.loads((Path(__file__).parent / "resources/ssvc-sources.json").read_text())
COOLDOWN = 60
MAX_CACHE_ENTRIES = 4096


def enabled() -> bool:
    return os.getenv("DTVP_SSVC_ENRICHMENT_ENABLED", "true").lower() in {"true", "1", "yes"}


def timestamp(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, UTC).isoformat()


def parse_date(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed


def sign_evidence(evidence: dict) -> str:
    from .auth import auth_settings
    return jwt.encode({"purpose": "ssvc-exploitation", "evidence": evidence}, auth_settings.SESSION_SECRET_KEY, algorithm="HS256")


def verify_evidence(token: str, answers: dict[str, str]) -> dict:
    from .auth import auth_settings
    try:
        claims = jwt.decode(token, auth_settings.SESSION_SECRET_KEY, algorithms=["HS256"])
        evidence = claims["evidence"]
        if claims.get("purpose") != "ssvc-exploitation" or evidence["value"] != answers.get(SOURCES["exploitation_point"]):
            raise ValueError("Evidence does not match Exploitation")
        return evidence
    except (JWTError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("Invalid SSVC source evidence; refresh or manually select Exploitation") from exc


def parse_kev(document: dict) -> dict:
    rows = document["vulnerabilities"]
    if not isinstance(rows, list) or not rows or document.get("count") != len(rows):
        raise ValueError("Invalid KEV catalog")
    result = {}
    for row in rows:
        cve = row["cveID"]
        if not CVE.fullmatch(cve) or cve in result:
            raise ValueError("Invalid KEV identifier")
        parse_date(row["dateAdded"])
        result[cve] = {"value": SOURCES["kev"]["value"], "assessed_at": row["dateAdded"]}
    return result


def parse_vulnrichment(document: dict, cve: str) -> dict | None:
    if document["cveMetadata"]["cveId"] != cve:
        raise ValueError("Mismatched CVE record")
    if document["cveMetadata"].get("state") == "REJECTED":
        return None
    candidates = []
    for container in document.get("containers", {}).get("adp", []):
        if container.get("providerMetadata", {}).get("orgId") != SOURCES["vulnrichment"]["provider"]:
            continue
        for metric in container.get("metrics", []):
            other = metric.get("other", {})
            if other.get("type") != "ssvc":
                continue
            content = other["content"]
            if content.get("id") != cve or content.get("version") not in SOURCES["vulnrichment"]["versions"]:
                raise ValueError("Unsupported CISA SSVC record")
            options = [option["Exploitation"] for option in content["options"] if "Exploitation" in option]
            if len(options) != 1 or options[0] not in SOURCES["vulnrichment"]["values"]:
                raise ValueError("Invalid CISA Exploitation value")
            date = content["timestamp"]
            parse_date(date)
            candidates.append({"value": SOURCES["vulnrichment"]["values"][options[0]], "assessed_at": date, "source_version": content["version"]})
    if not candidates:
        return None
    candidates.sort(key=lambda item: parse_date(item["assessed_at"]), reverse=True)
    if any(item["value"] != candidates[0]["value"] and parse_date(item["assessed_at"]) == parse_date(candidates[0]["assessed_at"]) for item in candidates[1:]):
        raise ValueError("Conflicting CISA assessments")
    return candidates[0]


class SsvcEnrichmentService:
    def __init__(self, path: str, *, transport=None, clock=time.time):
        self.path = path
        self.transport = transport
        self.clock = clock
        self.locks = [asyncio.Lock() for _ in range(32)]
        self.network_slots = asyncio.Semaphore(4)
        self.snapshot_lock = threading.RLock()
        self.snapshot_cache = None

    def filter_snapshot(self) -> dict:
        """Read-only, shared snapshot for list filters; never fetch on a query."""
        with self.snapshot_lock:
            now = self.clock()
            unavailable = False
            try:
                stat = Path(self.path).stat()
                stamp = (stat.st_mtime_ns, stat.st_size)
            except FileNotFoundError:
                stamp = None
            except OSError:
                stamp = ("unavailable",)
                unavailable = True
            cached = self.snapshot_cache
            if cached and cached["stamp"] == stamp and now < cached["expires"]:
                return cached
            entries = {}
            if stamp is not None and not unavailable:
                try:
                    uri = Path(self.path).absolute().as_uri() + "?mode=ro"
                    with closing(sqlite3.connect(uri, uri=True, timeout=5)) as connection:
                        entries = {key: json.loads(value) for key, value in connection.execute("SELECT key, value FROM entries")}
                        if any(not isinstance(entry, dict) for entry in entries.values()):
                            raise ValueError("Invalid source cache")
                        if any("checked" in entry and not isinstance(entry["checked"], (int, float)) for entry in entries.values()):
                            raise ValueError("Invalid source cache timestamp")
                except (sqlite3.Error, ValueError, OSError):
                    entries = {}
                    unavailable = True
                    logger.warning("SSVC evidence cache unavailable for filtering")
            expiries = [entry["checked"] + SOURCES["kev" if key == "kev" else "vulnrichment"]["ttl_seconds"]
                        for key, entry in entries.items() if "checked" in entry]
            expires = min([expiry for expiry in expiries if expiry > now] + [now + 60 if unavailable else float("inf")])
            self.snapshot_cache = {
                "stamp": stamp, "expires": expires, "entries": entries, "now": now,
                "unavailable": unavailable,
                "revision": (self.path, stamp, now),
            }
            return self.snapshot_cache

    def _cache(self, key: str, value: dict | None = None) -> dict:
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path, timeout=10)) as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS entries (key TEXT PRIMARY KEY, value TEXT NOT NULL, touched REAL NOT NULL)")
            if value is not None:
                connection.execute("INSERT OR REPLACE INTO entries VALUES (?, ?, ?)", (key, json.dumps(value), self.clock()))
                connection.execute("DELETE FROM entries WHERE key IN (SELECT key FROM entries WHERE key != 'kev' ORDER BY touched DESC LIMIT -1 OFFSET ?)", (MAX_CACHE_ENTRIES,))
                connection.commit()
                return value
            row = connection.execute("SELECT value FROM entries WHERE key = ?", (key,)).fetchone()
            return json.loads(row[0]) if row else {}

    async def _fetch(self, key: str, url: str, source: str, force: bool) -> dict:
        lock = self.locks[int.from_bytes(hashlib.sha256(key.encode()).digest()[:2]) % len(self.locks)]
        async with lock:
            entry = await asyncio.to_thread(self._cache, key)
            now = self.clock()
            if "attempted" in entry and now - entry["attempted"] < COOLDOWN:
                return entry
            if not force and "checked" in entry and not entry.get("error") and now - entry["checked"] < SOURCES[source]["ttl_seconds"]:
                return entry
            entry = {**entry, "attempted": now}
            try:
                headers = {"Accept": "application/json", "User-Agent": "DTVP-SSVC/1.0"}
                if entry.get("etag"):
                    headers["If-None-Match"] = entry["etag"]
                async with self.network_slots, httpx.AsyncClient(transport=self.transport, timeout=15, follow_redirects=False) as client:
                    async with client.stream("GET", url, headers=headers) as response:
                        if response.status_code == 304 and "data" in entry:
                            data = entry["data"]
                        elif source == "vulnrichment" and response.status_code == 404:
                            data = None
                        else:
                            response.raise_for_status()
                            content = bytearray()
                            limit = 8_000_000 if source == "kev" else 1_000_000
                            async for chunk in response.aiter_bytes():
                                content.extend(chunk)
                                if len(content) > limit:
                                    raise ValueError("Source response too large")
                            document = json.loads(content)
                            data = parse_kev(document) if source == "kev" else parse_vulnrichment(document, key)
                        entry.update(data=data, checked=now, error=None, etag=response.headers.get("etag", entry.get("etag") if response.status_code == 304 else None))
            except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError) as exc:
                # Retain the last good snapshot, including its original check time.
                entry["error"] = "Official source unavailable or invalid; cached evidence may be stale."
                logger.warning("SSVC %s refresh failed: %s", source, type(exc).__name__)
            await asyncio.to_thread(self._cache, key, entry)
            return entry

    async def refresh_kev(self, force=False) -> dict:
        return await self._fetch("kev", SOURCES["kev"]["url"], "kev", force)

    async def lookup(self, cves: list[str], *, force=False) -> dict:
        cves = sorted(set(cve.strip().upper() for cve in cves))
        if len(cves) > 20 or any(not CVE.fullmatch(cve) for cve in cves):
            raise ValueError("Provide up to 20 valid CVE identifiers")
        if not enabled() or not cves:
            return {"sources": [], "suggestion": None, "auto_fill": False, "enabled": enabled(), "retry_after": 0}
        async def fetch_cve(cve):
            _, year, number = cve.split("-")
            url = SOURCES["vulnrichment"]["url"].format(year=year, bucket=f"{int(number) // 1000}xxx", cve=cve)
            return cve, url, await self._fetch(cve, url, "vulnrichment", force)
        kev, rows = await asyncio.gather(self.refresh_kev(force), asyncio.gather(*(fetch_cve(cve) for cve in cves)))
        sources, candidates = [], []
        for cve, url, entry in rows:
            for source, cache, result, reference in (
                ("kev", kev, (kev.get("data") or {}).get(cve), SOURCES["kev"]["reference"] + cve),
                ("vulnrichment", entry, entry.get("data"), url),
            ):
                stale = bool(cache.get("error")) or self.clock() - cache.get("checked", 0) >= SOURCES[source]["ttl_seconds"]
                status = "unavailable" if "data" not in cache else "stale" if stale else "ok" if result else "not_found"
                info = {"source": SOURCES[source]["name"], "cve": cve, "url": reference, "status": status,
                        "checked_at": timestamp(cache["checked"]) if cache.get("checked") else None,
                        "last_attempt": timestamp(cache["attempted"]) if cache.get("attempted") else None,
                        "error": cache.get("error"), "retry_after": max(0, int(COOLDOWN - (self.clock() - cache.get("attempted", 0))))}
                if result:
                    evidence = {**result, "source": info["source"], "cve": cve, "url": reference, "checked_at": info["checked_at"], "stale": stale}
                    candidates.append({**evidence, "token": sign_evidence(evidence)})
                    info.update(result)
                sources.append(info)
        # Positive evidence wins. Absence from KEV never manufactures "None".
        candidates.sort(key=lambda item: ({"A": 0, "P": 1, "N": 2}[item["value"]], item["stale"], item["source"] != SOURCES["kev"]["name"]))
        suggestion = candidates[0] if candidates else None
        if suggestion and suggestion["value"] == "N" and len({item["cve"] for item in candidates}) != len(cves):
            suggestion = None
        healthy = all(item["status"] in {"ok", "not_found"} for item in sources)
        return {"sources": sources, "suggestion": suggestion, "enabled": True,
                "auto_fill": bool(suggestion and not suggestion["stale"] and (suggestion["value"] == "A" or healthy)),
                "retry_after": max((item["retry_after"] for item in sources), default=0)}


@lru_cache(maxsize=1)
def _service(path: str) -> SsvcEnrichmentService:
    return SsvcEnrichmentService(path)


def get_service() -> SsvcEnrichmentService:
    path = os.getenv("DTVP_SSVC_CACHE_PATH") or str(Path(os.getenv("DTVP_DT_CACHE_PATH", "data/dt_cache")) / "ssvc_enrichment.sqlite3")
    return _service(path)


async def run_kev_refresh_loop() -> None:
    while enabled():
        try:
            await get_service().refresh_kev()
        except Exception:
            logger.exception("SSVC KEV cache refresh failed")
        await asyncio.sleep(60)  # Cache TTL controls downloads; failures retry after cooldown.
