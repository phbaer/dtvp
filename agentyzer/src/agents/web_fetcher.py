import logging
import re
from typing import Any, Dict, List
from urllib.parse import quote

from src.http import async_client

logger = logging.getLogger(__name__)

# Map manifest/lock file patterns → OSV ecosystem names.
_ECOSYSTEM_HINTS: dict[str, str] = {
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "requirements.txt": "PyPI",
    "requirements.lock": "PyPI",
    "Pipfile": "PyPI",
    "Pipfile.lock": "PyPI",
    "setup.py": "PyPI",
    "pyproject.toml": "PyPI",
    "uv.lock": "PyPI",
    "pom.xml": "Maven",
    "build.gradle": "Maven",
    "go.mod": "Go",
    "go.sum": "Go",
    "Cargo.toml": "crates.io",
    "Cargo.lock": "crates.io",
    "Gemfile": "RubyGems",
    "Gemfile.lock": "RubyGems",
    "composer.json": "Packagist",
    "composer.lock": "Packagist",
    "*.csproj": "NuGet",
    "packages.config": "NuGet",
}


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _text(value: Any) -> str:
    if value is None:
        return ""
    return value if isinstance(value, str) else str(value)


def guess_ecosystem(
    component_name: str,
    dep_info: Dict[str, Any] | None = None,
) -> str | None:
    """Best-effort guess of the OSV ecosystem for a component.

    Uses dependency scanner results (``dep_info``) when available —
    checking which manifest/lock files declared the component — then
    falls back to naming heuristics.
    """
    if dep_info:
        # Check declared_in manifests / lock files
        for f in dep_info.get("declared_in", []) + dep_info.get("lock_files", []):
            base = f.rsplit("/", 1)[-1]
            eco = _ECOSYSTEM_HINTS.get(base)
            if eco:
                return eco

    # Naming heuristics
    name = component_name
    if name.startswith("@") or "/" in name:
        return "npm"  # scoped npm package
    if "." in name and not name.endswith(".py"):
        parts = name.split(".")
        if len(parts) >= 3:
            return "Maven"  # e.g. com.google.guava
    return None


async def discover_vulnerabilities(
    package_name: str,
    ecosystem: str | None = None,
) -> List[Dict[str, Any]]:
    """Query OSV for all known vulnerabilities affecting *package_name*.

    Returns a list of lightweight vuln dicts sorted by severity
    (worst first), each with at minimum ``id``, ``summary``, and
    ``severity_score``.
    """
    if not ecosystem:
        logger.warning(
            "discover_vulnerabilities: no ecosystem for '%s', skipping",
            package_name,
        )
        return []

    payload: dict[str, Any] = {
        "package": {"name": package_name, "ecosystem": ecosystem},
    }
    vulns: list[dict[str, Any]] = []

    async with async_client(timeout=30) as client:
        page_token: str | None = None
        for _ in range(5):  # cap pagination rounds
            body = {**payload}
            if page_token:
                body["page_token"] = page_token
            try:
                resp = await client.post(
                    "https://api.osv.dev/v1/query",
                    json=body,
                )
                if resp.status_code != 200:
                    logger.warning(
                        "OSV query for %s/%s returned HTTP %d",
                        ecosystem,
                        package_name,
                        resp.status_code,
                    )
                    break
                data = resp.json()
            except Exception as e:
                logger.warning(
                    "OSV query failed for %s/%s: %s", ecosystem, package_name, e
                )
                break

            if not isinstance(data, dict):
                logger.warning(
                    "OSV query for %s/%s returned a non-object payload",
                    ecosystem,
                    package_name,
                )
                break

            response_vulns = data.get("vulns", [])
            if not isinstance(response_vulns, list):
                logger.warning(
                    "OSV query for %s/%s returned an invalid vulnerabilities list",
                    ecosystem,
                    package_name,
                )
                break
            for v in response_vulns:
                if isinstance(v, dict):
                    vulns.append(_summarise_vuln(v))

            page_token = data.get("next_page_token")
            if not isinstance(page_token, str) or not page_token:
                break

    # Sort: highest severity first, then by ID for stability.
    vulns.sort(key=lambda v: (-v.get("severity_score", 0), v.get("id", "")))
    logger.info(
        "Discovered %d vulnerabilities for %s/%s",
        len(vulns),
        ecosystem,
        package_name,
    )
    return vulns


def _summarise_vuln(v: Dict[str, Any]) -> Dict[str, Any]:
    """Extract a compact summary from an OSV vuln record."""
    vuln_id = v.get("id", "")
    summary = _text(v.get("summary"))
    aliases = v.get("aliases", [])
    if not isinstance(aliases, list):
        aliases = []

    # Extract best CVSS score available.
    score = _extract_best_cvss(v)

    # CWEs
    cwes: list[str] = []
    dbs = v.get("database_specific", {})
    if isinstance(dbs, dict):
        for c in dbs.get("cwe_ids", []):
            if isinstance(c, str) and c.startswith("CWE-"):
                cwes.append(c)
    # Fallback: text scan
    if not cwes:
        details = _text(v.get("details"))
        for m in re.findall(r"CWE-\d+", summary + " " + details):
            if m not in cwes:
                cwes.append(m)

    return {
        "id": vuln_id,
        "aliases": aliases,
        "summary": summary,
        "severity_score": score,
        "cwes": cwes,
    }


def _extract_best_cvss(v: Dict[str, Any]) -> float:
    """Return the highest numeric CVSS score from an OSV record."""
    best = 0.0
    # severity array (CVSS vectors)
    for sev in _dict_list(v.get("severity")):
        vec = sev.get("score", "")
        parsed = _score_from_vector(vec)
        if parsed > best:
            best = parsed
    # database_specific.cvss (sometimes a float)
    dbs = v.get("database_specific", {})
    if isinstance(dbs, dict):
        cs = dbs.get("cvss")
        if isinstance(cs, (int, float)) and cs > best:
            best = float(cs)
    return best


def _score_from_vector(vector: str) -> float:
    """Compute a numeric CVSS score from a vector string.

    Delegates to the full CVSS scoring engine (``cvss_scoring``) which
    handles v2.0, v3.x and v4.0.
    """
    from src.agents.cvss_scoring import score_vector

    if not vector:
        return 0.0
    result = score_vector(vector)
    return result if result is not None else 0.0


async def fetch_advisory(vuln_id: str) -> Dict[str, Any]:
    """Fetch advisory data from OSV and NVD (best-effort).

    Returns a normalized dict with keys used by the analyzer:
      - id, sources, affected_packages, affected_ranges, fixed_versions,
        cvss (list), cwe (list), vulnerable_symbols, raw
    """
    results: Dict[str, Any] = {}
    encoded_vuln_id = quote(vuln_id, safe="")
    async with async_client(timeout=20) as client:
        # OSV
        try:
            logger.debug("Querying OSV for %s", vuln_id)
            r = await client.get(f"https://api.osv.dev/v1/vulns/{encoded_vuln_id}")
            if r.status_code == 200:
                results["osv"] = r.json()
                logger.info("OSV: found advisory for %s", vuln_id)
            else:
                results["osv_status"] = r.status_code
                logger.info("OSV: %s returned HTTP %d", vuln_id, r.status_code)
        except Exception as e:
            results["osv_error"] = str(e)
            logger.warning("OSV error for %s: %s", vuln_id, e)

        # If the OSV entry has GHSA aliases but lacks ecosystem-specific
        # (SEMVER/ECOSYSTEM) ranges, also fetch the GHSA entry which often
        # has proper npm/pypi/etc. ranges.
        osv_data = results.get("osv")
        if isinstance(osv_data, dict):
            aliases = osv_data.get("aliases", [])
            if not isinstance(aliases, list):
                aliases = []
            has_semver = any(
                advisory_range.get("type") in ("SEMVER", "ECOSYSTEM")
                for affected in _dict_list(osv_data.get("affected"))
                for advisory_range in _dict_list(affected.get("ranges"))
            )
            if not has_semver:
                for alias in aliases:
                    if isinstance(alias, str) and alias.upper().startswith("GHSA-"):
                        try:
                            logger.debug(
                                "Fetching GHSA alias %s (no SEMVER ranges in %s)",
                                alias,
                                vuln_id,
                            )
                            gr = await client.get(
                                "https://api.osv.dev/v1/vulns/"
                                f"{quote(alias, safe='')}"
                            )
                            if gr.status_code == 200:
                                results["osv_ghsa"] = gr.json()
                                logger.info(
                                    "OSV: found GHSA alias %s for %s",
                                    alias,
                                    vuln_id,
                                )
                        except Exception as e:
                            logger.warning("OSV GHSA alias %s error: %s", alias, e)
                        break  # only fetch the first GHSA alias

        # NVD 2.0 JSON API (best-effort)
        try:
            r2 = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": vuln_id},
            )
            if r2.status_code == 200:
                results["nvd"] = r2.json()
            else:
                results["nvd_status"] = r2.status_code
        except Exception as e:
            results["nvd_error"] = str(e)

        # GitHub Advisory (structured endpoint) for GHSA IDs.
        ghsa_ids: list[str] = []
        if vuln_id.upper().startswith("GHSA-"):
            ghsa_ids.append(vuln_id)
        osv_for_aliases = results.get("osv")
        if isinstance(osv_for_aliases, dict):
            for alias in osv_for_aliases.get("aliases", []) or []:
                if isinstance(alias, str) and alias.upper().startswith("GHSA-"):
                    ghsa_ids.append(alias)

        # De-duplicate while preserving order.
        ghsa_ids = list(dict.fromkeys(ghsa_ids))

        for ghsa_id in ghsa_ids:
            try:
                ga = await client.get(
                    "https://api.github.com/advisories/"
                    f"{quote(ghsa_id, safe='')}",
                    headers={"Accept": "application/vnd.github+json"},
                )
                if ga.status_code == 200:
                    results["github_advisory"] = ga.json()
                    logger.info("GitHub Advisory: found structured data for %s", ghsa_id)
                    break
                logger.info(
                    "GitHub Advisory: %s returned HTTP %d",
                    ghsa_id,
                    ga.status_code,
                )
            except Exception as e:
                logger.warning("GitHub Advisory error for %s: %s", ghsa_id, e)

        # GitHub Advisory search fallback (rate-limited).
        try:
            gh = await client.get(
                "https://api.github.com/search/issues",
                params={"q": vuln_id},
            )
            if gh.status_code == 200:
                results["github_search"] = gh.json()
            else:
                results["github_status"] = gh.status_code
        except Exception as e:
            results["github_error"] = str(e)

    # Normalize
    normalized: Dict[str, Any] = {
        "id": vuln_id,
        "summary": "",
        "sources": list(results.keys()),
        "affected_packages": [],
        "affected_ranges": [],
        "affected_versions": [],
        "fixed_versions": [],
        "cpe_entries": [],  # rich CPE data: {"part", "vendor", "product", "cpe"}
        "cvss": [],
        "cwe": [],
        "vulnerable_symbols": [],
        "exploit_preconditions": [],
        "data_warnings": [],
        "raw": results,
    }

    def _parse_osv_affected(
        osv: Dict[str, Any],
        source_label: str,
    ) -> None:
        """Extract package, range, and version info from an OSV affected block."""
        for a in _dict_list(osv.get("affected")):
            pkg = a.get("package", {})
            if not isinstance(pkg, dict):
                pkg = {}
            if pkg and (pkg.get("name") or pkg.get("ecosystem")):
                ecosystem = pkg.get("ecosystem")
                name = pkg.get("name")
                entry = f"{ecosystem}:{name}"
                if entry not in normalized["affected_packages"]:
                    normalized["affected_packages"].append(entry)

            # Pair introduced/fixed events within each range
            for r in _dict_list(a.get("ranges")):
                typ = r.get("type")
                events = _dict_list(r.get("events"))
                i = 0
                while i < len(events):
                    ev = events[i]
                    if "introduced" in ev:
                        intro = ev["introduced"]
                        fixed = None
                        # Look ahead for a paired "fixed" event
                        if i + 1 < len(events) and "fixed" in events[i + 1]:
                            fixed = events[i + 1]["fixed"]
                            i += 1
                        combined = {"introduced": intro}
                        if fixed:
                            combined["fixed"] = fixed
                        normalized["affected_ranges"].append(
                            {"type": typ, "event": combined, "source": source_label}
                        )
                    elif "fixed" in ev:
                        # Orphan fixed event (no preceding introduced)
                        normalized["fixed_versions"].append(ev["fixed"])
                    i += 1

            # Explicit affected versions list
            versions = a.get("versions")
            if not isinstance(versions, list):
                versions = []
            for v in versions:
                if not isinstance(v, str):
                    continue
                # Strip leading "v" for consistency
                clean = v.lstrip("v") if v.startswith("v") else v
                if clean and clean not in normalized["affected_versions"]:
                    normalized["affected_versions"].append(clean)

    # Parse OSV (primary)
    osv_result = results.get("osv")
    osv = osv_result if isinstance(osv_result, dict) else None
    if osv:
        _parse_osv_affected(osv, "osv")

    # Parse GHSA alias (may have ecosystem-specific SEMVER ranges)
    osv_ghsa_result = results.get("osv_ghsa")
    osv_ghsa = osv_ghsa_result if isinstance(osv_ghsa_result, dict) else None
    if osv_ghsa:
        _parse_osv_affected(osv_ghsa, "osv_ghsa")

    # ---- Helper: collect CWE ids from a database_specific dict ----
    def _collect_cwes(dbs: Any) -> None:
        if not isinstance(dbs, dict):
            return
        cwe_ids = dbs.get("cwe_ids")
        if not isinstance(cwe_ids, list):
            return
        for cwe_id in cwe_ids:
            if (
                isinstance(cwe_id, str)
                and cwe_id.startswith("CWE-")
                and cwe_id not in normalized["cwe"]
            ):
                normalized["cwe"].append(cwe_id)

    # ---- Extract CWE + CVSS from OSV / GHSA ----
    for osv_entry in (osv, osv_ghsa):
        if not osv_entry:
            continue
        # Top-level database_specific (where OSV/GHSA store cwe_ids)
        _collect_cwes(osv_entry.get("database_specific"))
        # Per-affected database_specific entries
        for aff in _dict_list(osv_entry.get("affected")):
            _collect_cwes(aff.get("database_specific"))

        # CVSS from top-level database_specific
        dbs = osv_entry.get("database_specific", {})
        if isinstance(dbs, dict):
            cvss_raw = dbs.get("cvss")
            if isinstance(cvss_raw, dict):
                # GHSA/OSV sometimes stores {"vectorString": "...", "baseScore": ...}
                vec = cvss_raw.get("vectorString") or cvss_raw.get("vector_string", "")
                if vec and vec not in normalized["cvss"]:
                    normalized["cvss"].append(vec)
                elif not vec:
                    bs = cvss_raw.get("baseScore") or cvss_raw.get("score")
                    if bs and bs not in normalized["cvss"]:
                        normalized["cvss"].append(bs)
            elif isinstance(cvss_raw, str) and cvss_raw.startswith("CVSS:"):
                if cvss_raw not in normalized["cvss"]:
                    normalized["cvss"].append(cvss_raw)
            elif isinstance(cvss_raw, (int, float)):
                # Bare numeric score — only add if no vector is available
                if cvss_raw and cvss_raw not in normalized["cvss"]:
                    normalized["cvss"].append(cvss_raw)

        # CVSS from OSV severity array (CVSS_V3 / CVSS_V4 vectors)
        for sev in _dict_list(osv_entry.get("severity")):
            vec = sev.get("score", "")
            # Extract baseScore from the CVSS vector string if present
            if vec.startswith("CVSS:"):
                # The numeric score is not in the vector; record the vector
                # for context — and extract any /AV: for attack surface info.
                if vec not in normalized["cvss"]:
                    normalized["cvss"].append(vec)

    # ---- Parse GitHub Advisory API (structured GHSA source) ----
    gh_adv = results.get("github_advisory")
    if isinstance(gh_adv, dict):
        if not normalized["summary"]:
            normalized["summary"] = _text(
                gh_adv.get("summary") or gh_adv.get("description")
            ).strip()

        for vuln in _dict_list(gh_adv.get("vulnerabilities")):
            pkg = vuln.get("package") or {}
            if not isinstance(pkg, dict):
                pkg = {}
            ecosystem = pkg.get("ecosystem")
            name = pkg.get("name")
            if ecosystem and name:
                entry = f"{ecosystem}:{name}"
                if entry not in normalized["affected_packages"]:
                    normalized["affected_packages"].append(entry)

            vuln_range = _text(vuln.get("vulnerable_version_range")).strip()
            if vuln_range:
                normalized["affected_ranges"].append(
                    {
                        "type": "ECOSYSTEM",
                        "event": {"range": vuln_range},
                        "source": "github_advisory",
                    }
                )

            fixed = _text(vuln.get("first_patched_version")).strip()
            if fixed:
                fixed = fixed.lstrip("=")
                if fixed not in normalized["fixed_versions"]:
                    normalized["fixed_versions"].append(fixed)

            vulnerable_functions = vuln.get("vulnerable_functions")
            if not isinstance(vulnerable_functions, list):
                vulnerable_functions = []
            for fn_name in vulnerable_functions:
                if fn_name and fn_name not in normalized["vulnerable_symbols"]:
                    normalized["vulnerable_symbols"].append(fn_name)

        cvss = gh_adv.get("cvss") or {}
        vector = cvss.get("vector_string")
        if vector and vector not in normalized["cvss"]:
            normalized["cvss"].append(vector)
        elif cvss.get("score") is not None:
            score = cvss.get("score")
            if score not in normalized["cvss"]:
                normalized["cvss"].append(score)

        for cwe in _dict_list(gh_adv.get("cwes")):
            cwe_id = cwe.get("cwe_id")
            if cwe_id and cwe_id not in normalized["cwe"]:
                normalized["cwe"].append(cwe_id)

    # ---- Parse NVD 2.0 ----
    nvd = results.get("nvd")
    if nvd:
        try:
            for vuln in nvd.get("vulnerabilities", []):
                cve_obj = vuln.get("cve", {})

                # CVSS scores (v4.0, v3.1, v3.0, v2.0)
                metrics = cve_obj.get("metrics", {})
                for metric_key in (
                    "cvssMetricV40",
                    "cvssMetricV31",
                    "cvssMetricV30",
                    "cvssMetricV2",
                ):
                    for entry in metrics.get(metric_key, []):
                        cvss_data = entry.get("cvssData", {})
                        # Prefer the vector string over the bare numeric score.
                        vec = cvss_data.get("vectorString", "")
                        if vec and vec not in normalized["cvss"]:
                            normalized["cvss"].append(vec)
                        elif not vec:
                            score = cvss_data.get("baseScore")
                            if score and score not in normalized["cvss"]:
                                normalized["cvss"].append(score)

                # CWEs from weaknesses
                for weakness in cve_obj.get("weaknesses", []):
                    for desc in weakness.get("description", []):
                        v = desc.get("value")
                        if v and v.startswith("CWE-") and v not in normalized["cwe"]:
                            normalized["cwe"].append(v)

                # Extract affected product names from NVD CPE configurations.
                # CPE 2.3 format: cpe:2.3:part:vendor:product:version:...
                # part: a=application, o=OS, h=hardware
                # We extract the product field (index 4) as the package name
                # and store full CPE entries for relevance filtering.
                for config in cve_obj.get("configurations", []):
                    for node in config.get("nodes", []):
                        for match in node.get("cpeMatch", []):
                            cpe_uri = match.get("criteria", "")
                            if not cpe_uri.startswith("cpe:2.3:"):
                                continue
                            parts = cpe_uri.split(":")
                            if len(parts) >= 5:
                                cpe_part = parts[2]  # a/o/h
                                vendor = parts[3]
                                product = parts[4]
                                if product and product != "*":
                                    entry = f"NVD:{product}"
                                    if entry not in normalized["affected_packages"]:
                                        normalized["affected_packages"].append(entry)
                                    cpe_entry = {
                                        "part": cpe_part,
                                        "vendor": vendor,
                                        "product": product,
                                        "cpe": cpe_uri,
                                    }
                                    if cpe_entry not in normalized["cpe_entries"]:
                                        normalized["cpe_entries"].append(cpe_entry)
                                    logger.info(
                                        "NVD CPE: part=%s vendor=%s product=%s",
                                        cpe_part,
                                        vendor,
                                        product,
                                    )
        except Exception:
            pass

    # Try to extract vulnerable symbols from text in OSV or GitHub search results
    def extract_symbols(text: str) -> List[str]:
        if not isinstance(text, str) or not text:
            return []
        # crude heuristic: look for word-like tokens with parentheses or dot notation
        syms = set()
        for m in re.findall(
            r"[A-Za-z_][A-Za-z0-9_\.]+\(|[A-Za-z_][A-Za-z0-9_\.]+::[A-Za-z_][A-Za-z0-9_]+",
            text,
        ):
            syms.add(m.strip("("))
        return list(syms)

    if osv:
        # Prefer the short OSV summary; fall back to the first paragraph of details.
        osv_summary = _text(osv.get("summary"))
        osv_details = _text(osv.get("details"))
        if not osv_summary and osv_details:
            # Take first paragraph (up to blank line) as the summary.
            osv_summary = osv_details.split("\n\n")[0].strip()
        normalized["summary"] = osv_summary

        desc = osv_summary or osv_details
        normalized["vulnerable_symbols"].extend(extract_symbols(desc))

    # Fallback: use NVD description when OSV had nothing
    if not normalized["summary"] and nvd:
        try:
            for vuln in nvd.get("vulnerabilities", []):
                for d in vuln.get("cve", {}).get("descriptions", []):
                    if d.get("lang", "en") == "en" and d.get("value"):
                        normalized["summary"] = d["value"]
                        break
                if normalized["summary"]:
                    break
        except Exception:
            pass

    gh_result = results.get("github_search")
    gh = gh_result if isinstance(gh_result, dict) else None
    if gh:
        items = _dict_list(gh.get("items"))
        for it in items:
            t = it.get("title", "") + "\n" + (it.get("body", "") or "")
            normalized["vulnerable_symbols"].extend(extract_symbols(t))

    # ---- Fallback: extract CWE mentions from advisory text ----
    if not normalized["cwe"]:
        # Scan all available text for CWE-XXXX patterns.
        text_sources: list[str] = [normalized.get("summary", "")]
        if osv:
            text_sources.append(osv.get("details", "") or "")
        if gh:
            for it in _dict_list(gh.get("items")):
                text_sources.append(it.get("title", ""))
                text_sources.append(it.get("body", "") or "")
        combined_text = "\n".join(text_sources)
        for m in re.findall(r"CWE-\d+", combined_text):
            if m not in normalized["cwe"]:
                normalized["cwe"].append(m)

    # Deduplicate lists
    for k in (
        "affected_packages",
        "vulnerable_symbols",
        "cvss",
        "cwe",
        "fixed_versions",
    ):
        normalized[k] = list(dict.fromkeys(normalized.get(k, [])))

    # Data-quality warnings based on final normalized content.
    has_semver_or_eco = any(
        r.get("type") in ("SEMVER", "ECOSYSTEM") for r in normalized["affected_ranges"]
    )
    has_git_only_ranges = bool(normalized["affected_ranges"]) and not has_semver_or_eco
    if has_git_only_ranges:
        normalized["data_warnings"].append(
            "Advisory has only GIT-type ranges (commit hashes) — "
            "version comparison may be unreliable"
        )
    if not normalized["affected_packages"]:
        normalized["data_warnings"].append(
            "Advisory has no ecosystem/package information — "
            "affected package identification relies on the component name"
        )
    if not normalized["affected_ranges"] and not normalized["affected_versions"]:
        normalized["data_warnings"].append(
            "Advisory has no affected ranges or explicit version lists"
        )
    normalized["data_warnings"] = list(dict.fromkeys(normalized["data_warnings"]))

    return normalized
