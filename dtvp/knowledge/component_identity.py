"""Conservative, source-independent package markers; never approval equivalence.

Caller supplies product/part scope. Repeated occurrences remain distinct: neither
reference spelling nor a many-to-one marker establishes cross-import continuity.
"""

import re
from collections import defaultdict

from packageurl import PackageURL

MAX_DIAGNOSTICS = 200
_STRONG = {
    "SHA-256": 64,
    "SHA-384": 96,
    "SHA-512": 128,
    "SHA3-256": 64,
    "SHA3-384": 96,
    "SHA3-512": 128,
    "BLAKE2B-256": 64,
    "BLAKE2B-384": 96,
    "BLAKE2B-512": 128,
    "BLAKE3": 64,
}
_ALIASES = {
    alias: algorithm for algorithm in _STRONG for alias in (algorithm, algorithm.replace("-", ""))
}


def _text(value):
    return value if isinstance(value, str) and value else None


def markers(component):
    """Extract optional markers. Invalid optional input becomes a diagnostic.

    Full PURL qualifiers/subpath stay significant. Component hashes describe the
    component artifact, not an enclosing image, delivery part or source file.
    """
    component = component if isinstance(component, dict) else {}
    candidate = {key: _text(component.get(key)) for key in ("type", "name", "group", "version")}
    conflicts, exact, family = [], None, None
    purl = component.get("purl")
    if purl:
        try:
            if not isinstance(purl, str):
                raise ValueError("Invalid PURL")
            package = PackageURL.from_string(purl)
            if candidate["version"] and package.version and candidate["version"] != package.version:
                conflicts.append("component_version_coordinate_conflict")
            if package.version:
                exact = package.to_string()
            family = PackageURL(
                type=package.type,
                namespace=package.namespace,
                name=package.name,
                qualifiers=package.qualifiers,
                subpath=package.subpath,
            ).to_string()
            candidate["version"] = candidate["version"] or package.version
        except ValueError, TypeError, AttributeError:
            conflicts.append("invalid_package_url")
    hashes = {}
    entries = component.get("hashes", [])
    if not isinstance(entries, list):
        conflicts.append("invalid_artifact_hashes")
        entries = []
    for item in entries:
        if not isinstance(item, dict) or not isinstance(item.get("alg"), str):
            conflicts.append("invalid_artifact_hash")
            continue
        algorithm = _ALIASES.get(item["alg"].upper())
        if algorithm is None:
            continue  # Weak/unsupported digests never establish continuity.
        value = item.get("content")
        if not isinstance(value, str) or not re.fullmatch(
            "[a-fA-F0-9]{" + str(_STRONG[algorithm]) + "}", value
        ):
            conflicts.append("invalid_artifact_hash")
            continue
        value = value.lower()
        if algorithm in hashes and hashes[algorithm] != value:
            conflicts.append("contradictory_artifact_hashes")
        hashes[algorithm] = value
    # Name/type/version provide a deliberately strict artifact scope. Unknown
    # metadata does not act as a wildcard in digest-only matching.
    scope = tuple(candidate[key] for key in ("type", "group", "name", "version"))
    digest_keys = [
        (algorithm, value, *scope)
        for algorithm, value in sorted(hashes.items())
        if all(candidate[key] for key in ("type", "name", "version"))
    ]
    return {
        "exact_key": exact,
        "family_key": family,
        "strong_hashes": hashes,
        "candidate": candidate,
        "conflicts": sorted(set(conflicts)),
        "digest_keys": digest_keys,
    }


def _compatible(left, right):
    if left["conflicts"] or right["conflicts"]:
        return False
    if left["family_key"] and right["family_key"] and left["family_key"] != right["family_key"]:
        return False
    if left["exact_key"] and right["exact_key"] and left["exact_key"] != right["exact_key"]:
        return False
    for key in ("type", "group", "version"):
        a, b = left["candidate"][key], right["candidate"][key]
        if a is not None and b is not None and a != b:
            return False
    return not any(
        left["strong_hashes"][key] != right["strong_hashes"][key]
        for key in left["strong_hashes"].keys() & right["strong_hashes"].keys()
    )


def reconcile_components(previous, current):
    """Return unique compatible one-to-one exact package/artifact pairs.

    Index marker buckets rather than creating a duplicate-occurrence Cartesian
    product. Ambiguous buckets are deliberately unresolved, even if incidental
    metadata could select one member. Source refs are never portable identity.
    """
    old = {ref: markers(component) for ref, component in previous.items()}
    new = {ref: markers(component) for ref, component in current.items()}
    indexes = []
    for items in (old, new):
        index = defaultdict(list)
        for ref, item in items.items():
            if item["exact_key"]:
                index[("purl", item["exact_key"])].append(ref)
            for key in item["digest_keys"]:
                index[("digest", *key)].append(ref)
        indexes.append(index)
    proposals, blocked, diagnostics = defaultdict(dict), set(), defaultdict(set)
    for key in indexes[0].keys() & indexes[1].keys():
        left, right = indexes[0][key], indexes[1][key]
        if len(left) != 1 or len(right) != 1:
            blocked.update(right)
            for ref in right:
                diagnostics[ref].add("ambiguous_occurrences")
            continue
        a, b = left[0], right[0]
        if _compatible(old[a], new[b]):
            basis = "exact_purl" if key[0] == "purl" else "scoped_strong_digest"
            if proposals[b].get(a) != "exact_purl":
                proposals[b][a] = basis
        else:
            blocked.add(b)
            diagnostics[b].add("conflicting_identity_markers")
    reverse = defaultdict(set)
    for ref, candidates in proposals.items():
        for prior in candidates:
            reverse[prior].add(ref)
    pairs, unresolved = [], []
    for ref in sorted(new):
        item, candidates = new[ref], proposals.get(ref, {})
        if ref not in blocked and len(candidates) == 1:
            prior = next(iter(candidates))
            if len(reverse[prior]) == 1:
                pairs.append(
                    {"previous_ref": prior, "current_ref": ref, "basis": candidates[prior]}
                )
                continue
        reason = (
            "invalid_identity_markers"
            if item["conflicts"]
            else "conflicting_identity_markers"
            if "conflicting_identity_markers" in diagnostics[ref]
            else "ambiguous_occurrences"
            if "ambiguous_occurrences" in diagnostics[ref] or candidates
            else "no_unambiguous_strong_match"
        )
        if len(unresolved) < MAX_DIAGNOSTICS:
            unresolved.append(
                {
                    "current_ref": ref,
                    "reason": reason,
                    "conflicts": item["conflicts"],
                    "candidate_count": len(candidates),
                }
            )
    return {
        "pairs": pairs,
        "unresolved": unresolved,
        "summary": {
            "previous": len(old),
            "current": len(new),
            "matched": len(pairs),
            "unresolved": len(new) - len(pairs),
        },
        "diagnostics_truncated": len(new) - len(pairs) > MAX_DIAGNOSTICS,
    }
