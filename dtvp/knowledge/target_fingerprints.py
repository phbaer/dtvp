"""Request-local fingerprint construction for one unchanged immutable state.

Only repeated encoding/traversal is cached. The canonical assessment-target/1
JSON bytes, source-local scope and conservative evidence semantics stay exact.
Never retain this builder across edits or requests; it is not an authority cache.
"""

from collections import OrderedDict
from hashlib import sha256

from dtvp.storage import canonical

DEFAULT_CACHE_BYTES = 32 * 1024 * 1024


def _array(values):
    return b"[" + b",".join(values) + b"]"


def _object(values):
    return b"{" + b",".join(key + b":" + value for key, value in values) + b"}"


class TargetFingerprintBuilder:
    """Index once; retain immutable canonical root fields in a bounded byte LRU."""

    def __init__(self, sections, version, *, max_cache_bytes=DEFAULT_CACHE_BYTES):
        if not isinstance(max_cache_bytes, int) or max_cache_bytes < 0:
            raise ValueError("Fingerprint cache budget must be a nonnegative integer")
        # Keep these helpers shared with legacy callers; local import avoids a
        # module cycle when the compatibility wrapper creates this builder.
        from dtvp.knowledge.assessments import collection_scope, semantic
        from dtvp.knowledge.metadata import FORMAT, identity_fingerprint, metadata_key

        self._contexts = sections["ownership"]
        self._max_cache_bytes = max_cache_bytes
        self._cache = OrderedDict()
        self._cache_bytes = 0
        inventory = sections["inventory"]
        components = {
            item["bom-ref"]: item
            for key, item in inventory.items()
            if key.startswith("component:") and item.get("bom-ref")
        }
        root = inventory.get("root", {})
        if root.get("bom-ref"):
            components.setdefault(root["bom-ref"], root)
        self._graph = {ref: set() for ref in components}
        for edge in inventory.get("dependencies", {}).get("edges", []):
            if edge["ref"] in self._graph:
                self._graph[edge["ref"]].update(edge.get("dependsOn", []))
        self._components = {ref: canonical(semantic(item)) for ref, item in components.items()}
        pipeline = inventory.get("pipeline_configuration", {})
        self._pipeline_configuration = (
            pipeline.get("configuration") if pipeline.get("state") else None
        )
        self._pipeline_sections = sections
        self._pipeline_components = components
        self._pipeline_contexts = {}
        self._part_ids = {
            ref: item.get("dtvp_origin", {}).get("part_id") for ref, item in components.items()
        }
        self._claims = {}
        for item in sections["vulnerabilities"].values():
            key = item.get("ref"), item.get("identifier")
            self._claims.setdefault(key, []).append(canonical(semantic(item)))
        self._claims = {key: _array(sorted(values)) for key, values in self._claims.items()}
        self._relationships, self._relationship_index = [], {}
        for index, item in enumerate(inventory.get("relationships", {}).get("items", [])):
            self._relationships.append(canonical(semantic(item)))
            for key in ("from", "to"):
                self._relationship_index.setdefault(item.get(key), set()).add(index)
        self._scope = canonical(collection_scope(inventory.get("baseline", {})))
        self._parts = [
            (
                part["part_id"],
                canonical(
                    {
                        "part_id": part["part_id"],
                        "scope": collection_scope(part.get("baseline", {})),
                    }
                ),
            )
            for part in inventory.get("assembly", {}).get("parts", [])
            if part.get("part_id") is not None
        ]
        self._curated = {}
        if any(key.startswith("metadata:") for key in sections["history"]):
            refs = set(components)
            for children in self._graph.values():
                refs.update(children)
            for ref in refs:
                record = sections["history"].get(metadata_key(ref), {})
                metadata = record.get("payload", {})
                if (
                    record.get("format") == FORMAT
                    and metadata.get("version") == version
                    and metadata.get("identity_fingerprint")
                    == identity_fingerprint(components.get(ref))
                ):
                    self._curated[ref] = canonical(
                        {key: metadata[key] for key in ("annotations", "provenance")}
                    )

    @property
    def cache_bytes(self):
        """Conservative encoded root/key byte usage; never exposes mutable state."""
        return self._cache_bytes

    @property
    def cached_roots(self):
        return len(self._cache)

    def _root_fields(self, root):
        cached = self._cache.get(root)
        if cached is not None:
            self._cache.move_to_end(root)
            return cached[0]
        seen, pending = set(), [root]
        while pending:
            ref = pending.pop()
            if ref in seen:
                continue
            seen.add(ref)
            pending.extend(self._graph.get(ref, set()) - seen)
        refs = sorted(seen)
        relationships = set()
        for ref in refs:
            relationships.update(self._relationship_index.get(ref, ()))
        part_ids = {self._part_ids.get(ref) for ref in seen}
        fields = {
            "components": _object(
                (canonical(ref), self._components.get(ref, b"{}")) for ref in refs
            ),
            "edges": _object(
                (canonical(ref), canonical(sorted(self._graph.get(ref, set())))) for ref in refs
            ),
            "relationships": _array(sorted(self._relationships[index] for index in relationships)),
            "scope": self._scope,
            "parts": _array(sorted(value for part_id, value in self._parts if part_id in part_ids)),
        }
        curated = [(canonical(ref), self._curated[ref]) for ref in refs if ref in self._curated]
        if curated:
            fields["curated_metadata"] = _object(curated)
        encoded = tuple((key, value) for key, value in sorted(fields.items()))
        size = (
            len(canonical(root))
            + 2
            + sum(len(canonical(key)) + len(value) + 2 for key, value in encoded)
        )
        # A root larger than the budget is evaluated normally without retention.
        if size <= self._max_cache_bytes:
            while self._cache and self._cache_bytes + size > self._max_cache_bytes:
                _, (_, evicted) = self._cache.popitem(last=False)
                self._cache_bytes -= evicted
            self._cache[root] = encoded, size
            self._cache_bytes += size
        return encoded

    def fingerprint(self, context_id, vulnerability_id):
        context = self._contexts.get("context:" + context_id)
        if not context:
            return None
        root, ref = context["root_ref"], context["component_ref"]
        if root not in self._graph or ref not in self._graph:
            return None
        claims = self._claims.get((ref, vulnerability_id))
        if claims is None:
            return None
        fields = dict(self._root_fields(root))
        fields.update(
            {
                "format": canonical("dtvp.assessment-target/1"),
                "context_id": canonical(context_id),
                "component_ref": canonical(ref),
                "root_ref": canonical(root),
                "root_basis": canonical(context["root_basis"]),
                "dependency_graph": canonical(context["dependency_graph"]),
                "claims": claims,
            }
        )
        if self._pipeline_configuration is not None:
            if context_id not in self._pipeline_contexts:
                from dtvp.knowledge.pipeline_config import context_material

                self._pipeline_contexts[context_id] = context_material(
                    self._pipeline_configuration,
                    self._pipeline_sections,
                    context,
                    components=self._pipeline_components,
                )
            material = self._pipeline_contexts[context_id]
            if material:
                fields["pipeline_context"] = canonical(material)
        result = sha256()
        result.update(b"{")
        for index, (key, value) in enumerate(sorted(fields.items())):
            if index:
                result.update(b",")
            result.update(canonical(key))
            result.update(b":")
            result.update(value)
        result.update(b"}")
        return result.hexdigest()
