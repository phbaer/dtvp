---
name: project-entrypoint
description: Generic OKF entry point for this repository. Use before broad scans, planning, architecture review, code changes, or after changes that affect behavior, APIs, configuration, integrations, security boundaries, commands, workflows, or repository structure.
---

# Project Entry Point

## Start Here

Read `docs/index.md` before broad project scans or code changes. It is the
canonical curated project model and routes to focused OKF concepts. Read only
the concepts relevant to the task, then verify their claims against the
`source_paths` named in their frontmatter.

Use `README.md` for the human quick start, command reference, and concise
product summary.

## Working Rules

- Use the OKF index as the first source of context, then inspect only the relevant concepts, source files, tests, and configuration.
- If documentation conflicts with source code, configuration, tests, package metadata, or lockfiles, trust the operational source and update the affected concept.
- Update relevant OKF concepts in the same change when you make meaningful changes to behavior, architecture, APIs, integrations, configuration, security boundaries, commands, workflows, or repository structure. Update the README when its summary or commands are affected.
- Run `uv run python scripts/validate-okf.py docs` after documentation changes.
- Do not create or maintain a second project overview in agent-specific files.
- Use `uv` for Python/backend work from the repository root.
- Use `npm` for the Node/frontend part from `frontend/`.
