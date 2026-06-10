# Agent Onboarding

This repository has a project-local skillset for future agents:

- Read `skills/dtvp-project-memory/SKILL.md` before doing broad project scans.
- Then read `skills/dtvp-project-memory/references/project-overview.md` for the current project map, functionality, architecture, commands, and update policy.
- Use that overview as the first source of context. Inspect code only for the files related to the current task or when the overview is stale or incomplete.
- After implementing meaningful behavior, architecture, API, integration, configuration, or workflow changes, update `skills/dtvp-project-memory/references/project-overview.md` in the same change.
- Do not update the overview for formatting-only edits, tiny refactors with no user-visible or agent-relevant effect, or tests-only changes unless they alter validation commands or project conventions.

The `.codex` and `.agents` directories in this checkout are mounted read-only, so the skillset lives in the normal repository tree.
