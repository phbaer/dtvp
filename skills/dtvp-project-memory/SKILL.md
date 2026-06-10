---
name: dtvp-project-memory
description: Use when working in the DTVP repository, understanding its functionality, planning changes, onboarding to the codebase, reviewing project architecture, or after implementing changes that affect behavior, APIs, configuration, integrations, commands, or workflows. Read the project overview before broad scanning, and update it when meaningful changes are made.
---

# DTVP Project Memory

## Start Here

When you are working in this repository, read:

`skills/dtvp-project-memory/references/project-overview.md`

Use it as the project map before performing broad scans. Prefer targeted inspection of the files named in the overview, plus files directly relevant to the user's task.

## When To Update

Update `references/project-overview.md` in the same change when you implement or discover changes to:

- user-facing functionality or workflows
- backend routes, service boundaries, data contracts, or external integrations
- frontend pages, shared stores, API helpers, or reusable components
- configuration files, environment variables, local development commands, or validation commands
- domain rules such as vulnerability grouping, assessment details, rescoring, caching, roles, or lifecycle state handling

Skip updates for formatting-only changes, local cleanup, dependency lockfile churn, or tests-only edits unless they alter project behavior or validation guidance.

## Update Style

Keep the overview factual, current, and compact. Preserve its section structure unless a new section clearly improves future agent onboarding. Write the current state of the project, not a changelog or implementation diary.
