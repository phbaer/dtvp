"""Official-source availability facets, independent of saved SSVC decisions."""

from .ssvc_enrichment_services import CVE, SOURCES

FILTER_VALUES = ("KEV", "CISA_SSVC", "NOT_CHECKED", "NO_DATA", "STALE", "UNAVAILABLE", "NO_CVE")


def evidence_sources(group: dict, snapshot: dict) -> list[str]:
    cves = {str(value).strip().upper() for value in [group.get("id", ""), *(group.get("aliases") or [])]}
    cves = {cve for cve in cves if CVE.fullmatch(cve)}
    if not cves:
        return ["NO_CVE"]
    if snapshot.get("unavailable"):
        return ["UNAVAILABLE"]
    entries = snapshot["entries"]
    kev = entries.get("kev", {})
    flags = set()
    for cve in cves:
        for key, entry, result in (
            ("kev", kev, (kev.get("data") or {}).get(cve)),
            ("vulnrichment", entries.get(cve, {}), entries.get(cve, {}).get("data")),
        ):
            if result:
                flags.add("KEV" if key == "kev" else "CISA_SSVC")
            if entry.get("error"):
                flags.add("UNAVAILABLE")
            if "data" not in entry:
                if not entry.get("error"):
                    flags.add("NOT_CHECKED")
            elif entry.get("error") or snapshot["now"] - entry.get("checked", 0) >= SOURCES[key]["ttl_seconds"]:
                flags.add("STALE")
    # Only complete, fresh negative coverage can mean no data.
    if not flags:
        flags.add("NO_DATA")
    return [value for value in FILTER_VALUES if value in flags]


def evidence_counts(rows: list[dict], snapshot: dict) -> dict[str, int]:
    counts = dict.fromkeys(FILTER_VALUES, 0)
    for row in rows:
        for value in evidence_sources(row["fields"], snapshot):
            counts[value] += 1
    return counts
