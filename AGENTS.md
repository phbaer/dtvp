# Agent Onboarding

This repository uses an Open Knowledge Format (OKF) project entry framework:

- Read `docs/index.md` first for broad scans, planning, architecture review, or changes. It routes to focused concepts with their authoritative source paths and review triggers.
- Use `README.md` for the human quick start, command reference, and concise product summary.
- Inspect only the concepts, source files, tests, and configuration needed for the current task.
- Source code, configuration, tests, package metadata, and lockfiles are operational truth. If they conflict with the OKF bundle or README, trust the source and update the affected documentation.
- After meaningful behavior, architecture, API, integration, configuration, workflow, command, security-boundary, or repository-structure changes, update the relevant `docs/` concept and its index in the same change. Update the README when its concise summary or commands are affected.
- Validate documentation with `uv run python scripts/validate-okf.py docs`.
- Do not maintain another architecture overview in agent-specific files. `AGENTS.md` and `skills/*/SKILL.md` are routing hints that point agents to the OKF bundle.
- The generic project skill entry point is `skills/project-entrypoint/SKILL.md`; `skills/dtvp-project-memory/SKILL.md` remains as a DTVP-named compatibility entry point.
- Use `uv` for Python/backend work from the repository root. Use `npm` for the Node/frontend part from `frontend/`.

The `.codex` and `.agents` directories in this checkout are mounted read-only, so the skillset lives in the normal repository tree.
