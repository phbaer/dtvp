# Agent Onboarding

This repository uses a generic AI agent entry framework:

- Read `README.md` first. It is the canonical project overview for architecture, structure, commands, workflows, and update policy.
- Use the README as the first source of context, then inspect only the code and configuration needed for the current task.
- If the README conflicts with source code, configuration, tests, package metadata, or lockfiles, trust the source and update the README.
- After implementing meaningful behavior, architecture, API, integration, configuration, workflow, command, or repository-structure changes, update `README.md` in the same change.
- Do not maintain a second architecture overview in agent-specific files. `AGENTS.md` and `skills/*/SKILL.md` are routing hints that point agents back to the README.
- The generic project skill entry point is `skills/project-entrypoint/SKILL.md`; `skills/dtvp-project-memory/SKILL.md` remains as a DTVP-named compatibility entry point.
- Use `uv` for Python/backend work from the repository root. Use `npm` for the Node/frontend part from `frontend/`.

The `.codex` and `.agents` directories in this checkout are mounted read-only, so the skillset lives in the normal repository tree.
