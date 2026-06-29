---
name: project-entrypoint
description: Generic AI entry point for this repository. Use before broad scans, planning, architecture review, code changes, or after changes that affect behavior, APIs, configuration, integrations, commands, workflows, or repository structure.
---

# Project Entry Point

## Start Here

Read `README.md` before broad project scans or code changes. It is the canonical architecture and structure overview for this repository and applies to all AI agents, assistants, and automation systems.

## Working Rules

- Use the README as the first source of context, then inspect only the source files, tests, and configuration needed for the current task.
- If the README conflicts with source code, configuration, tests, package metadata, or lockfiles, trust the source and update the README.
- Update `README.md` in the same change when you make meaningful changes to behavior, architecture, APIs, integrations, configuration, commands, workflows, or repository structure.
- Do not create or maintain a second project overview in agent-specific files.
- Use `uv` for Python/backend work from the repository root.
- Use `npm` for the Node/frontend part from `frontend/`.
