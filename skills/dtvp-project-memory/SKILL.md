---
name: dtvp-project-memory
description: Compatibility entry point for DTVP's OKF project knowledge. Use when onboarding, planning, reviewing architecture, or changing behavior, APIs, configuration, integrations, security boundaries, commands, or workflows.
---

# DTVP Project Memory

## Start Here

When you are working in this repository, read the canonical OKF index first:

`docs/index.md`

Use it as the project map before broad scans. Read the smallest relevant
concepts and inspect the source paths named in their frontmatter. Use
`README.md` for human setup and commands.

## When To Update

Update the relevant OKF concept in the same change when you implement or discover changes to:

- user-facing functionality or workflows
- backend routes, service boundaries, data contracts, or external integrations
- frontend pages, shared stores, API helpers, or reusable components
- configuration files, environment variables, local development commands, or validation commands
- domain rules such as vulnerability grouping, assessment details, rescoring, caching, roles, or lifecycle state handling

Update the README as well when its concise product summary, quick start, or
commands are affected. Skip documentation updates for formatting-only changes,
local cleanup, dependency lockfile churn, or tests-only edits unless they alter
project behavior or validation guidance.

## Update Style

Keep concepts factual, current, and focused. Write the present design, not a
changelog or implementation diary. If documentation conflicts with source
code, configuration, tests, package metadata, or lockfiles, trust the
operational source and update the affected concept. Validate changes with
`uv run python scripts/validate-okf.py docs`.
