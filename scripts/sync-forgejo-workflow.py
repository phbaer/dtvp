#!/usr/bin/env python3
"""Render Forgejo's workflow from the canonical GitHub workflow."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = ROOT / ".github" / "workflows" / "build-publish.yml"
OUTPUT_PATH = ROOT / ".forgejo" / "workflows" / "build-publish.yml"
GITHUB_ONLY_PERMISSIONS = "permissions:\n  contents: read\n\n"
GITHUB_UPLOAD_ARTIFACT = (
    "uses: actions/upload-artifact@"
    "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1"
)
FORGEJO_UPLOAD_ARTIFACT = (
    "uses: https://data.forgejo.org/actions/upload-artifact@"
    "c6a3b2bd78b3985e4b2f15397fec357f0fd808de # v3.2.2-node20"
)
EXPECTED_UPLOAD_ARTIFACT_USES = 5


def render_forgejo_workflow(source: str) -> str:
    if source.count(GITHUB_ONLY_PERMISSIONS) != 1:
        raise ValueError(
            "canonical workflow must contain exactly one read-only permissions block"
        )
    if source.count(GITHUB_UPLOAD_ARTIFACT) != EXPECTED_UPLOAD_ARTIFACT_USES:
        raise ValueError(
            "canonical workflow must contain exactly "
            f"{EXPECTED_UPLOAD_ARTIFACT_USES} pinned GitHub artifact uploads"
        )
    if FORGEJO_UPLOAD_ARTIFACT in source:
        raise ValueError("canonical workflow must not contain Forgejo artifact actions")

    rendered = source.replace(GITHUB_ONLY_PERMISSIONS, "", 1)
    return rendered.replace(GITHUB_UPLOAD_ARTIFACT, FORGEJO_UPLOAD_ARTIFACT)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail when the generated Forgejo workflow is stale",
    )
    args = parser.parse_args()

    try:
        rendered = render_forgejo_workflow(SOURCE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"Cannot render Forgejo workflow: {exc}", file=sys.stderr)
        return 1

    if args.check:
        try:
            checked_in = OUTPUT_PATH.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"Cannot read generated Forgejo workflow: {exc}", file=sys.stderr)
            return 1
        if checked_in != rendered:
            print(
                "Forgejo workflow is stale; run "
                "`uv run python scripts/sync-forgejo-workflow.py`.",
                file=sys.stderr,
            )
            return 1
        print("Forgejo workflow is current.")
        return 0

    OUTPUT_PATH.write_text(rendered, encoding="utf-8")
    print(f"Wrote {OUTPUT_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
