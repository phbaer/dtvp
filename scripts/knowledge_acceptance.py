"""Read-only, manifest-driven verification of supplied DTVP acceptance evidence.

Never imports data, changes reviews, runs specialist tools or grants acceptance.
Exit 0 means all configured technical checks passed; deferred/attested gates remain explicit.
"""

import argparse
import json
import os
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urlsplit

import httpx

from dtvp.api_contract import API_PREFIX
from dtvp.parsers import parse
from dtvp.storage import canonical, digest

FORMAT = "dtvp.acceptance-input/1"
MAX_BYTES = 64 * 1024 * 1024
EXTERNAL_GATES = (
    "producer_completeness",
    "legacy_migration",
    "consumer_round_trips",
    "generator_document_parity",
    "oidc_permissions",
    "recovery_upgrade",
    "performance_concurrency",
)
LIMITATIONS = [
    "Technical verification is not customer acceptance, legal clearance or regulatory certification.",
    "SBOM completeness and delivered-artifact binding require producer evidence; parsing cannot establish them.",
    "External conclusions are supplied reviewer attestations, not independently reproduced checks.",
    "No server writes, specialist execution, human approvals or release decisions are performed.",
    "Not-run gates remain open even when every configured technical check passes.",
]


class InvalidEvidence(ValueError):
    """A safe operator-facing validation diagnostic."""


def _sha(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise InvalidEvidence("Expected a lowercase SHA-256 pin")
    return value


def _text(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 500:
        raise InvalidEvidence("Expected nonempty bounded text")
    return value


def _rows(value, maximum=100):
    if not isinstance(value, list) or len(value) > maximum:
        raise InvalidEvidence("Expected a bounded array")
    if any(not isinstance(row, dict) for row in value):
        raise InvalidEvidence("Array items must be objects")
    return value


def _file(root, relative, expected):
    path = Path(_text(relative))
    if path.is_absolute():
        raise InvalidEvidence("Evidence paths must be relative to the manifest")
    target = (root / path).resolve()
    if not target.is_relative_to(root.resolve()):
        raise InvalidEvidence("Evidence path escapes manifest directory")
    with target.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise InvalidEvidence("Evidence exceeds 64 MiB")
    if digest(raw) != _sha(expected):
        raise InvalidEvidence("Evidence checksum differs from manifest pin")
    return raw


def _get(client, path, params=None):
    # Paths are constructed locally. Never follow redirects or use manifest-supplied URLs.
    with client.stream("GET", path, params=params, follow_redirects=False) as response:
        response.raise_for_status()
        if response.is_redirect:
            raise InvalidEvidence("Redirected evidence is not accepted")
        raw = bytearray()
        for chunk in response.iter_bytes():
            raw.extend(chunk)
            if len(raw) > MAX_BYTES:
                raise InvalidEvidence("Remote evidence exceeds 64 MiB")
    return bytes(raw)


def verify(manifest, root, *, client=None):
    """Return independently checked technical results and clearly labeled attestations."""
    if not isinstance(manifest, dict) or manifest.get("format") != FORMAT:
        raise InvalidEvidence("Unsupported acceptance manifest format")
    scenario = _text(manifest.get("scenario"))
    gates = []
    fixtures = {}
    state_versions = {}
    total_bytes = 0

    def gate(name, check):
        try:
            facts = check()
            gates.append({"gate": name, "status": "pass", "assurance": "verified", **facts})
        except (ValueError, TypeError, KeyError, AttributeError, OSError, httpx.HTTPError) as error:
            # Response URLs/bodies and source contents can contain secrets. Never echo them.
            gates.append(
                {
                    "gate": name,
                    "status": "fail",
                    "assurance": "verification_failed",
                    "reason": str(error)
                    if isinstance(error, InvalidEvidence)
                    else "Evidence could not be read, parsed or retrieved through the authorized endpoint",
                }
            )

    fixture_rows = _rows(manifest.get("fixtures", []))
    if not fixture_rows:
        raise InvalidEvidence("At least one supplied SBOM fixture is required")
    fixture_ids = [_text(row.get("id")) for row in fixture_rows]
    if len(set(fixture_ids)) != len(fixture_ids):
        raise InvalidEvidence("Duplicate fixture identifiers")
    product_lines = set()
    for row in fixture_rows:
        name = _text(row.get("id"))

        def fixture_check(row=row, name=name):
            nonlocal total_bytes
            for key in ("producer", "product_line", "version", "part_id"):
                _text(row.get(key))
            declarations = row.get("coverage")
            if (
                not isinstance(declarations, dict)
                or set(declarations) != {"packages", "dependencies", "licenses"}
                or any(
                    value not in {"complete", "partial", "unknown"}
                    for value in declarations.values()
                )
            ):
                raise InvalidEvidence(
                    "Declare package, dependency and license coverage, including unknowns"
                )
            raw = _file(root, row.get("path"), row.get("sha256"))
            total_bytes += len(raw)
            if total_bytes > 256 * 1024 * 1024:
                raise InvalidEvidence("Fixture collection exceeds 256 MiB")
            normalized = parse(raw)
            expected = row.get("expected", {})
            if not isinstance(expected, dict) or set(expected) - {
                "components",
                "findings",
                "format",
            }:
                raise InvalidEvidence("Unsupported fixture expectation")
            facts = {
                "format": normalized["format"],
                "components": len(normalized["components"]),
                "findings": len(normalized["findings"]),
            }
            for key, value in expected.items():
                if type(value) is not type(facts[key]) or value != facts[key]:
                    raise InvalidEvidence("Parsed fixture differs from declared expectation")
            fixtures[name] = {**row, "raw": raw}
            product_lines.add(row["product_line"])
            return {
                "fixture_id": name,
                "scope": {
                    key: row[key] for key in ("producer", "product_line", "version", "part_id")
                },
                "sha256": digest(raw),
                "bytes": len(raw),
                "producer_declared_coverage": declarations,
                "parser": normalized["parser"],
                "observed": facts,
                "normalization_losses": normalized["losses"],
                "missing_purl": sum(
                    not component.get("purl") for component in normalized["components"]
                ),
                "missing_version": sum(
                    not component.get("version") for component in normalized["components"]
                ),
            }

        gate("fixture:" + name, fixture_check)
    if len(product_lines) > 1:
        raise InvalidEvidence("An acceptance scenario must stay within one product line")

    deployment = manifest.get("deployment")
    if deployment is not None:
        if not isinstance(deployment, dict):
            raise InvalidEvidence("Deployment scope must be an object")
        project = _text(deployment.get("project_id"))
        path = f"{API_PREFIX}/projects/" + quote(project, safe="")
        states = _rows(deployment.get("states", []), 20)
        for row in states:
            state, version = _sha(row.get("state")), _text(row.get("version"))
            if state in state_versions:
                raise InvalidEvidence("Duplicate deployment state")
            state_versions[state] = version
            ids = row.get("fixtures", [])
            if not isinstance(ids, list) or any(
                not isinstance(item, str) or item not in fixture_ids for item in ids
            ):
                raise InvalidEvidence("Deployment references unknown fixture")
            if any(
                fixture.get("version") != version
                for fixture in fixture_rows
                if fixture["id"] in ids
            ):
                raise InvalidEvidence("Fixture and deployment version scopes differ")
            if client is None:
                gates.append(
                    {
                        "gate": "state:" + state,
                        "status": "not_run",
                        "reason": "No deployment client supplied",
                    }
                )
                continue

            def state_check(state=state, version=version, ids=ids):
                raw = _get(client, path + f"/states/{state}/evidence-summary")
                summary = json.loads(raw)
                if summary.get("format") != "dtvp.pipeline-evidence-summary/1" or any(
                    summary.get(key) != value
                    for key, value in {
                        "state": state,
                        "version": version,
                        "project_id": project,
                    }.items()
                ):
                    raise InvalidEvidence("Deployed summary has a different scope")
                material = {key: value for key, value in summary.items() if key != "summary_digest"}
                if digest(canonical(material)) != summary.get("summary_digest"):
                    raise InvalidEvidence("Deployed summary digest does not match")
                for fixture_id in ids:
                    fixture = fixtures.get(fixture_id)
                    if fixture is None:
                        raise InvalidEvidence("Source fixture did not pass validation")
                    original = _get(client, path + f"/states/{state}/artifacts/{fixture['sha256']}")
                    if original != fixture["raw"]:
                        raise InvalidEvidence(
                            "Retained original differs from supplied source bytes"
                        )
                return {
                    "state": state,
                    "version": version,
                    "summary_digest": summary["summary_digest"],
                    "verified_originals": ids,
                }

            gate("state:" + state, state_check)
        for index, row in enumerate(_rows(deployment.get("comparisons", []), 20)):
            before, after = _sha(row.get("before")), _sha(row.get("after"))
            if (
                before not in state_versions
                or after not in state_versions
                or not isinstance(row.get("expect_changes"), bool)
            ):
                raise InvalidEvidence(
                    "Comparison needs declared states and an explicit change expectation"
                )
            if client is None:
                gates.append(
                    {
                        "gate": f"comparison:{index}",
                        "status": "not_run",
                        "reason": "No deployment client supplied",
                    }
                )
                continue

            def compare_check(row=row, before=before, after=after):
                value = json.loads(
                    _get(
                        client,
                        path + "/compare/details",
                        {"before": before, "after": after, "limit": 1},
                    )
                )
                expected = {
                    "project_id": project,
                    "before": before,
                    "after": after,
                    "before_version": state_versions[before],
                    "after_version": state_versions[after],
                }
                if any(value.get(key) != val for key, val in expected.items()):
                    raise InvalidEvidence("Comparison scope differs")
                total = value.get("total")
                if type(total) is not int or total < 0 or bool(total) != row["expect_changes"]:
                    raise InvalidEvidence("Comparison does not meet change expectation")
                return {
                    "before": before,
                    "after": after,
                    "total_changes": total,
                    "response_sha256": digest(canonical(value)),
                }

            gate(f"comparison:{index}", compare_check)
    else:
        gates.append(
            {
                "gate": "deployment",
                "status": "not_run",
                "reason": "No pinned deployment scope supplied",
            }
        )

    attestations = _rows(manifest.get("attestations", []), len(EXTERNAL_GATES))
    supplied = {}
    for row in attestations:
        name = row.get("gate")
        if name not in EXTERNAL_GATES or name in supplied:
            raise InvalidEvidence("Unknown or duplicate external gate")
        supplied[name] = row
    for name in EXTERNAL_GATES:
        row = supplied.get(name)
        if row is None:
            gates.append(
                {
                    "gate": name,
                    "status": "not_run",
                    "reason": "No reviewed external evidence supplied",
                }
            )
            continue

        def attest_check(row=row):
            if row.get("conclusion") not in {"pass", "fail"}:
                raise InvalidEvidence("External conclusion must be pass or fail")
            reviewer = _text(row.get("reviewer"))
            when = datetime.fromisoformat(_text(row.get("reviewed_at")))
            if when.tzinfo is None:
                raise InvalidEvidence("Review timestamp must include timezone")
            scope = row.get("fixture_ids")
            if (
                not isinstance(scope, list)
                or not scope
                or any(not isinstance(item, str) or item not in fixtures for item in scope)
            ):
                raise InvalidEvidence("Attestation must reference validated fixtures")
            raw = _file(root, row.get("path"), row.get("sha256"))
            # Verifying bytes is distinct from verifying the reviewer's supplied conclusion.
            return {
                "status": "not_run",
                "evidence_verification": "pass",
                "assurance": "supplied_attestation_only",
                "declared_conclusion": row["conclusion"],
                "reviewer": reviewer,
                "reviewed_at": when.isoformat(),
                "fixture_ids": scope,
                "evidence_sha256": digest(raw),
            }

        gate(name, attest_check)
    failed = any(
        row["status"] == "fail" or row.get("declared_conclusion") == "fail" for row in gates
    )
    return {
        "format": "dtvp.acceptance-report/1",
        "scenario": scenario,
        "manifest_sha256": digest(canonical(manifest)),
        "verification": "failed" if failed else "configured_checks_passed",
        "acceptance": "not_granted",
        "gates": gates,
        "limitations": LIMITATIONS,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument(
        "--output", type=Path, required=True, help="Fresh report file; never overwrites"
    )
    parser.add_argument("--url", help="Optional deployment origin; GET requests only")
    parser.add_argument(
        "--token-env", help="Environment variable containing a read-only API bearer token"
    )
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Output report must not exist")
    with args.manifest.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        parser.error("Manifest exceeds 1 MiB")
    manifest = json.loads(raw)
    if args.token_env and not args.url:
        parser.error("Token requires a deployment URL")
    if args.url:
        url = urlsplit(args.url)
        if (
            url.scheme not in {"http", "https"}
            or not url.netloc
            or url.username
            or url.password
            or url.query
            or url.fragment
            or url.path not in {"", "/"}
        ):
            parser.error("URL must be an HTTP(S) origin without credentials/path/query")
        if url.scheme != "https" and url.hostname not in {"localhost", "127.0.0.1", "::1"}:
            parser.error("Remote deployments require HTTPS")
        headers = {}
        if args.token_env:
            token = os.environ.get(args.token_env)
            if not token:
                parser.error("Token environment variable is empty")
            headers["Authorization"] = "Bearer " + token
        with httpx.Client(
            base_url=args.url, headers=headers, timeout=60, follow_redirects=False, trust_env=False
        ) as client:
            report = verify(manifest, args.manifest.resolve().parent, client=client)
    else:
        report = verify(manifest, args.manifest.resolve().parent)
    with args.output.open("x") as stream:
        stream.write(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(
        json.dumps(
            {
                "verification": report["verification"],
                "acceptance": report["acceptance"],
                "report": str(args.output),
            }
        )
    )
    raise SystemExit(1 if report["verification"] == "failed" else 0)


if __name__ == "__main__":
    main()
