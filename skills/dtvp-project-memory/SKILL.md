---
name: dtvp-project-memory
description: Use when working in the DTVP repository, understanding its functionality, planning changes, onboarding to the codebase, reviewing project architecture, or after implementing changes that affect behavior, APIs, configuration, integrations, commands, or workflows. Read README.md before broad scanning, and update it when meaningful changes are made.
---

# DTVP Project Memory

## Start Here

When you are working in this repository, read the canonical project overview first:

`README.md`

Use it as the project map before performing broad scans. Prefer targeted inspection of files named in the README, plus files directly relevant to the user's task.

## When To Update

Update `README.md` in the same change when you implement or discover changes to:

- user-facing functionality or workflows
- backend routes, service boundaries, data contracts, or external integrations
- frontend pages, shared stores, API helpers, or reusable components
- configuration files, environment variables, local development commands, or validation commands
- domain rules such as vulnerability grouping, assessment details, rescoring, caching, roles, or lifecycle state handling

Skip updates for formatting-only changes, local cleanup, dependency lockfile churn, or tests-only edits unless they alter project behavior or validation guidance.

## Update Style

Keep the README factual, current, and compact. Write the current state of the project, not a changelog or implementation diary. If the README conflicts with source code, configuration, tests, package metadata, or lockfiles, trust the source and update the README.
