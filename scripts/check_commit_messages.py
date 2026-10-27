#!/usr/bin/env python3
"""Validate commit subjects locally and in pull request CI."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

SUBJECT_PATTERN = re.compile(
    r"^(?P<type>feat|fix|refactor|docs|docu|test|ci|build|perf|style|revert|chore)"
    r"(?:\((?P<scope>[a-z0-9][a-z0-9._/-]*)\))?(?P<breaking>!)?: (?P<summary>\S.*)$"
)
CHORE_SCOPES = {
    "deps",
    "repo",
    "tooling",
    "build",
    "release",
    "data",
    "config",
}


def validate_subject(subject: str) -> str | None:
    match = SUBJECT_PATTERN.fullmatch(subject.strip())
    if match is None:
        return "expected '<type>(<scope>): <summary>' using an allowed commit type"
    if match.group("type") == "chore" and match.group("scope") not in CHORE_SCOPES:
        return "chore commits require one of these scopes: " + ", ".join(
            sorted(CHORE_SCOPES)
        )
    return None


def read_subjects(base: str, head: str) -> list[tuple[str, str]]:
    commit_ids = subprocess.run(
        ["git", "rev-list", "--no-merges", f"{base}..{head}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    subjects: list[tuple[str, str]] = []
    for commit_id in commit_ids:
        subject = subprocess.run(
            ["git", "show", "-s", "--format=%s", commit_id],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        subjects.append((commit_id, subject))
    return subjects


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--message-file", type=Path)
    group.add_argument("--range", nargs=2, metavar=("BASE", "HEAD"))
    args = parser.parse_args()

    if args.message_file:
        lines = args.message_file.read_text(encoding="utf-8").splitlines()
        message = lines[0] if lines else ""
        subjects = [("commit message", message)]
    else:
        subjects = read_subjects(*args.range)

    failures = 0
    for commit, subject in subjects:
        reason = validate_subject(subject)
        if reason:
            print(f"{commit}: {subject!r}: {reason}", file=sys.stderr)
            failures += 1
    if failures:
        return 1
    print(f"Validated {len(subjects)} commit subject(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
