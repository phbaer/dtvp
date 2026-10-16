"""Offline Git SHA-1 commit-object hash/parent-path consistency, never origin trust."""

import base64
import binascii
import hashlib
import re
from collections import deque

from dtvp.storage import digest

MAX_OBJECTS = 1000
MAX_OBJECT_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
SHA1 = re.compile(rb"[a-f0-9]{40}")
LIMITATIONS = [
    "Git SHA-1 compatibility and parent-path consistency do not authenticate repository membership, signatures, hosting, producer identity or source contents.",
    "Tree/blob objects, build execution and artifact-to-source correspondence are not verified.",
    "Integration kind remains a producer claim; ancestry does not verify a cherry-pick, squash, backport or patch equivalence.",
    "All supplied raw commit-object bytes are retained for project readers; no repository is fetched or executed.",
]


def verify_objects(objects, source_commit, target_commit):
    if not isinstance(objects, dict) or len(objects) > MAX_OBJECTS:
        raise ValueError("Git proof exceeds the commit-object limit")
    if not objects:
        return {
            "status": "not_provided",
            "verification": "producer_declaration_only",
            "limitations": LIMITATIONS,
        }, {}
    decoded, parents, total = {}, {}, 0
    for identity, encoded in objects.items():
        if not isinstance(identity, str) or not SHA1.fullmatch(
            identity.encode("ascii", errors="replace")
        ):
            raise ValueError("Git proof object IDs must be lowercase SHA-1 commit IDs")
        if not isinstance(encoded, str) or len(encoded) > ((MAX_OBJECT_BYTES + 2) // 3) * 4:
            raise ValueError("Git proof commit object exceeds its encoded bound")
        # Admit the complete encoded byte budget before allocating decoded bytes.
        estimate = len(encoded) // 4 * 3 - (
            2 if encoded.endswith("==") else 1 if encoded.endswith("=") else 0
        )
        if estimate < 0 or total + estimate > MAX_TOTAL_BYTES:
            raise ValueError("Git proof exceeds its decoded byte budget")
        try:
            raw = base64.b64decode(encoded.encode("ascii"), validate=True)
        except ValueError, UnicodeError, binascii.Error:
            raise ValueError("Git proof commit bytes must be strict base64") from None
        if len(raw) > MAX_OBJECT_BYTES or total + len(raw) > MAX_TOTAL_BYTES:
            raise ValueError("Git proof exceeds its decoded byte budget")
        total += len(raw)
        actual = hashlib.sha1(b"commit " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if actual != identity:
            raise ValueError("Git commit-object hash differs from its declared identity")
        header, separator, _ = raw.partition(b"\n\n")
        lines = header.split(b"\n")
        if (
            not separator
            or b"\0" in raw
            or not lines
            or not lines[0].startswith(b"tree ")
            or not SHA1.fullmatch(lines[0][5:])
        ):
            raise ValueError("Git proof requires bounded commit-object headers")
        ancestry, parent_seen, authors, committers, previous = [], set(), 0, 0, None
        for line in lines[1:]:
            if line.startswith(b" "):
                if previous not in {b"gpgsig", b"gpgsig-sha256", b"mergetag"}:
                    raise ValueError("Invalid Git commit header continuation")
                continue
            key, space, value = line.partition(b" ")
            if not space or not value or key == b"tree":
                raise ValueError("Invalid Git commit-object header")
            if key == b"parent":
                if not SHA1.fullmatch(value) or value in parent_seen:
                    raise ValueError("Invalid or repeated Git parent reference")
                parent_seen.add(value)
                ancestry.append(value.decode())
            authors += key == b"author"
            committers += key == b"committer"
            previous = key
        if authors != 1 or committers != 1:
            raise ValueError(
                "Git proof requires one author and committer header; identities remain unverified"
            )
        decoded[identity], parents[identity] = raw, ancestry
    if source_commit not in parents or target_commit not in parents:
        raise ValueError("Git proof must include both exact qualified endpoint commits")
    pending, seen, next_towards_target = deque([target_commit]), {target_commit}, {}
    while pending:
        current = pending.popleft()
        if current == source_commit:
            break
        for parent in parents.get(current, []):
            if parent not in seen and parent in parents:
                seen.add(parent)
                next_towards_target[parent] = current
                pending.append(parent)
    else:
        raise ValueError(
            "Supplied Git proof does not establish the exact source-to-target parent path"
        )
    path, current = [source_commit], source_commit
    while current != target_commit:
        current = next_towards_target[current]
        path.append(current)
    return {
        "status": "verified_commit_object_ancestry",
        "verification": "git_sha1_object_hash_and_explicit_parent_path_consistency_only",
        "relation": "same_commit" if source_commit == target_commit else "ancestor",
        "path": path,
        "object_count": len(decoded),
        "decoded_bytes": total,
        "objects": {identity: digest(raw) for identity, raw in sorted(decoded.items())},
        "limitations": LIMITATIONS,
    }, decoded
