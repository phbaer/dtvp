# Agent Onboarding

This repository uses a generic AI agent entry framework:

- Read `README.md` first. It is the canonical project overview for architecture, structure, commands, workflows, and update policy.
- Use the README as the first source of context, then inspect only the code and configuration needed for the current task.
- If the README conflicts with source code, configuration, tests, package metadata, or lockfiles, trust the source and update the README.
- After implementing meaningful behavior, architecture, API, integration, configuration, workflow, command, or repository-structure changes, update `README.md` in the same change.
- Do not maintain a second architecture overview in agent-specific files. `AGENTS.md` and `skills/*/SKILL.md` are routing hints that point agents back to the README.
- The generic project skill entry point is `skills/project-entrypoint/SKILL.md`; `skills/dtvp-project-memory/SKILL.md` remains as a DTVP-named compatibility entry point.
- Use `uv` for Python/backend work from the repository root. Use `npm` for the Node/frontend part from `frontend/`.
- Follow the commit discipline in this file: commit each coherent batch promptly, keep related implementation/tests/docs/configuration together, and do not combine unrelated work. Stage explicit paths after checking `git status`.
- Use Conventional Commit subjects: `<type>(<scope>): <imperative summary>`. Allowed types are `feat`, `fix`, `refactor`, `docs` (or `docu`), `test`, `ci`, `build`, `perf`, `style`, `revert`, and `chore`. `chore` requires a scope from `deps`, `repo`, `tooling`, `build`, `release`, `data`, or `config` (for example `chore(deps): update SQLAlchemy`).
- The tracked `.githooks/commit-msg` hook validates local commits; install it with `git config --local core.hooksPath .githooks`. Pull request CI also validates every non-merge commit subject. Do not amend or rewrite commits unless the user asks.

The `.codex` and `.agents` directories in this checkout are mounted read-only, so the skillset lives in the normal repository tree.
