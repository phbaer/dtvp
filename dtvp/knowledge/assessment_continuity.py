"""Conservative read-time approval bridges; immutable /1 targets stay untouched.

Identity is necessary, never sufficient. Only schema-known reference positions
are renamed; arbitrary claim/component fields remain exact. Unproven continuity
(including an incomplete retained predecessor chain) leaves coverage unchanged.
"""

from collections import ChainMap
from copy import deepcopy

from dtvp.knowledge.assembly_lineages import FORMAT as ASSEMBLY_FORMAT
from dtvp.knowledge.component_lineages import (
    FORMAT,
    POLICY,
    _components,
    _scope,
    _validate_prior,
    reconcile_lineages,
)
from dtvp.knowledge.journal import Ref
from dtvp.storage import canonical, digest

MAX_PREDECESSORS = 64
MAX_REVIEWS = 256
MAX_HISTORY_BYTES = 32 * 1024 * 1024


def _ledger(inventory, project_id, version):
    ledger = inventory.get("identity")
    if ledger is None:
        if not inventory.get("baseline", {}).get("artifact_sha"):
            return None
        ledger = reconcile_lineages({}, inventory, project_id=project_id, version=version)
    if ledger.get("format") == ASSEMBLY_FORMAT:
        if ledger.get("project_id") != project_id or ledger.get("version") != version:
            return None
        groups = {"root": {}, "component": {}}
        roots = {
            item.get("bom-ref") for key, item in inventory.items() if key.startswith("part-root:")
        }
        for key, item in inventory.items():
            if key.startswith("component:") and item.get("bom-ref"):
                ref = item["bom-ref"]
                groups["root" if ref in roots else "component"][ref] = item
        if any(
            not isinstance(entry.get("source"), dict)
            for entry in ledger.get("entries", {}).values()
        ):
            return None
    elif ledger.get("format") == FORMAT and ledger.get("scope") == _scope(
        inventory, project_id, version
    ):
        groups = _components(inventory)
    else:
        return None
    if ledger.get("policy") != POLICY:
        return None
    _validate_prior(ledger, groups)
    return ledger


class _ReferenceMap(dict):
    def __init__(self, ledger):
        super().__init__((ref, item["lineage_id"]) for ref, item in ledger["entries"].items())
        parts = {}
        for entry in ledger["entries"].values():
            source = entry.get("source", {})
            if source.get("part_id"):
                parts.setdefault(source["part_id"], {})[source["ref"]] = entry["lineage_id"]
        self.parts = {part: ChainMap(refs, self) for part, refs in parts.items()}


def _local_mapping(mapping, ledger, part_id):
    return mapping.parts.get(part_id, mapping)


def _reference(value, mapping):
    return mapping.get(value, value) if isinstance(value, str) else value


def _component(value, mapping, ledger):
    result = deepcopy(value)
    local = _local_mapping(mapping, ledger, result.get("dtvp_origin", {}).get("part_id"))
    if "bom-ref" in result:
        result["bom-ref"] = _reference(result["bom-ref"], mapping)
    if isinstance(result.get("dtvp_origin"), dict):
        origin = result["dtvp_origin"]
        if "ref" in origin:
            origin["ref"] = _reference(origin["ref"], local)
    if isinstance(result.get("components"), list):
        result["components"] = [_component(item, mapping, ledger) for item in result["components"]]
    return result


def _claim(value, mapping, ledger):
    result = deepcopy(value)
    result["ref"] = _reference(result.get("ref"), mapping)
    local = _local_mapping(mapping, ledger, result.get("dtvp_origin", {}).get("part_id"))
    if isinstance(result.get("dtvp_origin"), dict) and "ref" in result["dtvp_origin"]:
        result["dtvp_origin"]["ref"] = _reference(result["dtvp_origin"]["ref"], local)
    if isinstance(result.get("match"), dict) and "ref" in result["match"]:
        result["match"]["ref"] = _reference(result["match"]["ref"], mapping)
    # CycloneDX's embedded advisory affects are typed document references. Other
    # nested data (including arbitrary fields named ref) remains byte-semantic.
    advisory = result.get("advisory")
    if isinstance(advisory, dict) and isinstance(advisory.get("affects"), list):
        for affected in advisory["affects"]:
            if isinstance(affected, dict) and "ref" in affected:
                affected["ref"] = _reference(affected["ref"], local)
    return result


def _context(value, mapping):
    if value.get("status") != "resolved" or any(
        value.get(key) not in mapping for key in ("root_ref", "component_ref")
    ):
        return None
    result = deepcopy(value)
    for key in ("root_ref", "component_ref"):
        result[key] = mapping[value[key]]
    result["incoming_refs"] = sorted(
        _reference(ref, mapping) for ref in value.get("incoming_refs", [])
    )
    result["id"] = digest(canonical([result["root_ref"], result["component_ref"]]))
    result.pop("component_fingerprint", None)
    # Resolver-owned assignment fields are not usage/security evidence. A team
    # change keeps the existing decision and its historical reviewing team.
    for key in (
        "team_id",
        "team_scope",
        "root_team_id",
        "candidate_teams",
        "owner_boundaries",
        "matched_rules",
        "aliases",
        "delegated",
        "assignment",
    ):
        result.pop(key, None)
    return result


class _NormalizedState:
    """Prepare schema-known reference substitutions once per immutable state."""

    def __init__(self, sections, version, ledger):
        from dtvp.knowledge.metadata import FORMAT as METADATA_FORMAT
        from dtvp.knowledge.metadata import identity_fingerprint, metadata_key
        from dtvp.knowledge.target_fingerprints import TargetFingerprintBuilder

        self.sections = sections
        self.mapping = mapping = _ReferenceMap(ledger)
        inventory = sections["inventory"]
        components = {
            item["bom-ref"]: item
            for key, item in inventory.items()
            if (key == "root" or key.startswith("component:")) and item.get("bom-ref")
        }
        self.graph = {ref: set() for ref in components}
        self.valid_refs = components.keys() & mapping.keys()
        self.root_validity = {}
        self._retained_root_refs = 0
        for edge in inventory.get("dependencies", {}).get("edges", []):
            self.graph.setdefault(edge["ref"], set()).update(edge.get("dependsOn", []))
        self.invalid_relationship_nodes = set()
        for edge in inventory.get("relationships", {}).get("items", []):
            if any(edge.get(key) not in mapping for key in ("from", "to")):
                self.invalid_relationship_nodes.update((edge.get("from"), edge.get("to")))
        transformed = {"inventory": deepcopy(inventory), "history": {}, "ownership": {}}
        normalized_inventory = transformed["inventory"]
        for key, item in list(normalized_inventory.items()):
            if key == "root" or key.startswith("component:"):
                normalized_inventory.pop(key)
                mapped = _component(item, mapping, ledger)
                normalized_inventory[
                    "root" if key == "root" else "component:" + mapped["bom-ref"]
                ] = mapped
        for edge in normalized_inventory.get("dependencies", {}).get("edges", []):
            edge["ref"] = _reference(edge["ref"], mapping)
            edge["dependsOn"] = [_reference(ref, mapping) for ref in edge.get("dependsOn", [])]
        for edge in normalized_inventory.get("relationships", {}).get("items", []):
            for key in ("from", "to"):
                if key in edge:
                    edge[key] = _reference(edge[key], mapping)
        assertions = normalized_inventory.get("observation_assertions", {}).get("components")
        if assertions is not None:
            normalized_inventory["observation_assertions"]["components"] = {
                _reference(ref, mapping): values for ref, values in assertions.items()
            }
        transformed["vulnerabilities"] = {
            key: _claim(item, mapping, ledger) for key, item in sections["vulnerabilities"].items()
        }
        self.contexts = {}
        for key, value in sections["ownership"].items():
            if key.startswith("context:") and (normalized := _context(value, mapping)):
                self.contexts[value["id"]] = normalized
                transformed["ownership"]["context:" + normalized["id"]] = normalized
        # Validate curated material against original identities BEFORE replacing
        # refs. Only the builder's existing annotations/provenance scope is used.
        for ref, component in components.items():
            if ref not in mapping:
                continue
            record = sections["history"].get(metadata_key(ref), {})
            payload = record.get("payload", {})
            if (
                record.get("format") == METADATA_FORMAT
                and payload.get("version") == version
                and payload.get("identity_fingerprint") == identity_fingerprint(component)
            ):
                transformed["history"][metadata_key(mapping[ref])] = {
                    "format": METADATA_FORMAT,
                    "payload": {
                        "version": version,
                        "identity_fingerprint": identity_fingerprint(
                            _component(component, mapping, ledger)
                        ),
                        **{key: payload[key] for key in ("annotations", "provenance")},
                    },
                }
        self.builder = TargetFingerprintBuilder(transformed, version, max_cache_bytes=512 * 1024)

    def _valid_root(self, root):
        if root not in self.root_validity:
            seen, pending = set(), [root]
            while pending:
                ref = pending.pop()
                if ref in seen:
                    continue
                if ref not in self.valid_refs or ref in self.invalid_relationship_nodes:
                    self.root_validity[root] = False
                    return False
                seen.add(ref)
                pending.extend(self.graph.get(ref, set()) - seen)
            if self._retained_root_refs + len(seen) <= 100_000:
                self.root_validity[root] = seen
                self._retained_root_refs += len(seen)
            return seen
        return self.root_validity[root]

    def fingerprint(self, context_id, vulnerability_id):
        context = self.contexts.get(context_id)
        if not context:
            return None
        original = self.sections["ownership"]["context:" + context_id]
        seen = self._valid_root(original["root_ref"])
        if not seen or original["component_ref"] not in seen:
            return None
        fingerprint = self.builder.fingerprint(context["id"], vulnerability_id)
        return digest(canonical([fingerprint, context])) if fingerprint else None


def normalized_target(sections, version, context_id, vulnerability_id, ledger):
    return _NormalizedState(sections, version, ledger).fingerprint(context_id, vulnerability_id)


class ApprovalContinuityResolver:
    """One immutable request scope; historical loads/ledger checks run once."""

    def __init__(self, journal, sections, version, *, state=None):
        self.journal, self.sections, self.version = journal, sections, version
        self.state = state
        self._previous = None
        self._current_ledger = None
        self._normalized = None
        self._indexes = {}
        self._exact = {}

    def _history(self):
        from dtvp.knowledge.assessments import load_sections

        inventory = self.sections["inventory"]
        identity = inventory.get("identity", {})
        project_id = identity.get("scope", {}).get("project_id") or identity.get("project_id")
        self._previous = []
        if not project_id:
            return
        ledger = _ledger(inventory, project_id, self.version)
        if ledger is None:
            return
        self._current_ledger = ledger
        # Actual product ancestry distinguishes assembled states from their part
        # sources. Inventory history additionally supports retained-state callers.
        state = self.state or self.journal.resolve(Ref(project_id=project_id, name=self.version))
        pending = [state] if state else []
        pending.extend(
            item["state"]
            for key, item in self.sections["history"].items()
            if key.startswith("inventory:") and item.get("state") == key.removeprefix("inventory:")
        )
        pending.extend(
            entry["previous_state"]
            for entry in ledger["entries"].values()
            if entry.get("previous_state")
        )
        visited, retained_bytes = set(), 0
        while pending and len(visited) < MAX_PREDECESSORS:
            candidate = pending.pop()
            if candidate in visited:
                continue
            visited.add(candidate)
            revision = self.journal.state(candidate)
            if revision.project_id != project_id or revision.version != self.version:
                continue
            previous = load_sections(self.journal, candidate)
            encoded_bytes = len(canonical(previous))
            if retained_bytes + encoded_bytes > MAX_HISTORY_BYTES:
                break
            old_ledger = _ledger(previous["inventory"], project_id, self.version)
            if old_ledger:
                self._previous.append((candidate, previous, old_ledger))
                retained_bytes += encoded_bytes
            # First parent is the target branch predecessor; other parents may
            # be constituent source inputs and must not crowd out product history.
            if revision.parents:
                pending.append(revision.parents[0])

    def __call__(self, context_id, vulnerability_id):
        from dtvp.knowledge.target_fingerprints import TargetFingerprintBuilder

        reviews = [
            review
            for review in self.sections["reviews"].values()
            if review.get("status") == "approved"
            and review.get("target", {}).get("version") == self.version
            and review.get("target", {}).get("vulnerability_id") == vulnerability_id
        ]
        if not reviews or len(reviews) > MAX_REVIEWS:
            return None
        if self._previous is None:
            self._history()
        if self._current_ledger is None:
            return None
        if self._normalized is None:
            self._normalized = _NormalizedState(self.sections, self.version, self._current_ledger)
        current = self._normalized.fingerprint(context_id, vulnerability_id)
        if current is None:
            return None
        matches, qualified_reviews = {}, set()
        for state, previous, old_ledger in self._previous:
            for review in reviews:
                covered = review["target"]
                old_id = covered["context_id"]
                if state not in self._exact:
                    self._exact[state] = TargetFingerprintBuilder(
                        previous, self.version, max_cache_bytes=512 * 1024
                    )
                if (
                    self._exact[state].fingerprint(old_id, vulnerability_id)
                    != covered["fingerprint"]
                ):
                    continue
                if review not in previous["reviews"].values():
                    continue
                identity = (review["assessment_id"], review["assessment_revision"], old_id)
                qualified_reviews.add(identity)
                if state not in self._indexes:
                    self._indexes[state] = _NormalizedState(previous, self.version, old_ledger)
                if self._indexes[state].fingerprint(old_id, vulnerability_id) != current:
                    continue
                matches[identity] = {
                    "review": review,
                    "source_state": state,
                    "source_context_id": old_id,
                    "basis": "stable_lineage_exact_reference_normalization",
                }
        # Unvisited candidate approvals beyond the history bound could establish
        # a second source. Incomplete disambiguation never selects one silently.
        return (
            next(iter(matches.values()))
            if len(matches) == 1 and len(qualified_reviews) == len(reviews)
            else None
        )


def approval_bridge(journal, sections, version, context_id, vulnerability_id):
    return ApprovalContinuityResolver(journal, sections, version)(context_id, vulnerability_id)
