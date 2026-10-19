"""Generate editable offline scenario data; never connects, imports or resets a project."""

import argparse
import json
from pathlib import Path

VERSION = "7.2.0"
VULNERABILITIES = 5000
ROOTS = ("scale-platform", "scale-operations")
PARTITIONS = (("shared", 80), ("platform", 160), ("operations", 160))
DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "playground/scenarios/scale-5000.json"


def scenario():
    components = [
        {"type": "application", "bom-ref": ref, "name": ref, "version": "1.0.0"} for ref in ROOTS
    ]
    dependencies = [
        {"ref": "product", "dependsOn": list(ROOTS)},
        {"ref": ROOTS[0], "dependsOn": ["platform-000", "shared-000"]},
        {"ref": ROOTS[1], "dependsOn": ["operations-000", "shared-000"]},
    ]
    libraries = []
    for prefix, count in PARTITIONS:
        refs = [f"{prefix}-{index:03}" for index in range(count)]
        libraries.extend(refs)
        for index, ref in enumerate(refs):
            component = {
                "type": "library",
                "bom-ref": ref,
                "name": ref,
                "group": "dtvp-synthetic",
                "description": "Synthetic local scale fixture; no real software or verified discovery.",
            }
            if index % 17:
                component.update(version="1.0.0", purl=f"pkg:generic/dtvp-synthetic/{ref}@1.0.0")
            if index % 3 != 2:
                component["licenses"] = [{"expression": "MIT" if index % 3 == 0 else "Apache-2.0"}]
            components.append(component)
            dependencies.append(
                {
                    "ref": ref,
                    "dependsOn": [
                        refs[child] for child in (2 * index + 1, 2 * index + 2) if child < count
                    ],
                }
            )
    ratings = (
        (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
        (0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
    )
    vulnerabilities = []
    for index in range(VULNERABILITIES):
        score, vector = ratings[index % len(ratings)]
        vulnerabilities.append(
            {
                "id": f"CVE-2099-{50000 + index}",
                "description": f"Synthetic scale issue {index + 1}; not a real advisory. Assess the consuming context explicitly; exploitability, discovery and license coverage are unverified.",
                "source": {"name": "DTVP synthetic scale fixture"},
                "ratings": [{"method": "CVSSv31", "score": score, "vector": vector}],
                "affects": [{"ref": libraries[index * len(libraries) // VULNERABILITIES]}],
            }
        )
    return {
        "format": "dtvp.demo-scenario/1",
        "synthetic": True,
        "fixture_id": "native-scale-5000/1",
        "project_name": "Scale 5000 Vulnerabilities",
        "selected_version": VERSION,
        "baselines": [
            {
                "id": "scale-5000-baseline",
                "version": VERSION,
                "source": "playground:synthetic-scale-5000",
                "build_number": 1,
                "occurred_at": "2026-01-01T00:00:00+00:00",
                "sbom": {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "version": 1,
                    "metadata": {
                        "component": {
                            "type": "application",
                            "bom-ref": "product",
                            "name": "Synthetic scale product",
                            "version": VERSION,
                        }
                    },
                    "components": components,
                    "dependencies": dependencies,
                    "vulnerabilities": vulnerabilities,
                },
                "context": {
                    "subject_kind": "build",
                    "configuration": "synthetic-scale",
                    "pipeline_run": "scale-fixture-1",
                    "collector": "DTVP offline scenario generator",
                    "method": "build",
                    "package_coverage": "unknown",
                    "dependency_coverage": "unknown",
                    "license_coverage": "unknown",
                    "limitations": [
                        "Synthetic composition and CVE-2099 identifiers; not real software or advisories.",
                        "Discovery, source/build authenticity, exploitability and license coverage are unverified.",
                        "No human assessments, approvals, source-service execution or published scores are produced.",
                    ],
                },
            }
        ],
        "ownership": {
            "rules": [
                {"selector": ROOTS[0], "team": "Platform"},
                {"selector": ROOTS[1], "team": "Operations"},
                {"selector": "dtvp-synthetic:platform-001", "team": "Operations"},
            ],
            "context_roots": {VERSION: list(ROOTS)},
        },
        "assessments": [],
        "tags": [],
        "updates": [],
        "licenses": [],
        "vscorer_proposals": [],
        "code_analysis": [],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(scenario(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(args.output)


if __name__ == "__main__":
    main()
