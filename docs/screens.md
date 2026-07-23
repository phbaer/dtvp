---
type: Reference
title: DTVP Screen Guide
description: User-interface workflows covered by the deterministic documentation screenshot set.
tags:
  - frontend
  - screenshots
  - user-guide
source_paths:
  - frontend/src/
  - frontend/e2e/
  - frontend/package.json
review_when:
  - User-facing screens, navigation, reviewer workflows, or screenshot capture fixtures change.
---

# DTVP Screen Guide

This guide describes the application screens covered by the documentation screenshot set. Regenerate the images from the repository root with:

```bash
cd frontend && npm run test:ui:docs
```

The capture flow uses mocked API fixtures so the screenshots stay deterministic and show the same reviewer-focused examples on every run.

## Entry And Project Navigation

### Login

![Login](screenshots/login.png)

The login screen offers the SSO entry point used before DTVP loads project data.

### Dashboard

![Dashboard](screenshots/dashboard.png)

The dashboard lists Dependency-Track projects, versions, classifiers, and reviewer actions such as opening a project or exporting a project archive.

### Project Review

![Project review](screenshots/project-view.png)

The project review page is the main vulnerability workflow. It combines grouped vulnerability cards, lifecycle state, team ownership, assessment controls, dependency-path context, and code-analysis shortcuts. Compact row badges and the opened card's single Next action guide identify the next useful analyst step. Once its destination tab is open, navigation disappears and the guide points to the concrete control in that tab. A Team filter also scopes the opened card's code evidence and assessment workflow, so another team's saved run or draft does not drive the selected team's next action.

### Lifecycle Badges

![Lifecycle badges](screenshots/lifecycle-badges.png)

The lifecycle view shows the project list with open, incomplete, inconsistent, needs-approval, assessed, and rescored states visible together.

## Vulnerability Review Details

### Vulnerability Card Context

![Vulnerability card overview](screenshots/vuln-card-overview.png)

The Context tab uses four clearly separated sections in a fixed reading order: advisory description and references; project-version, team, finding, and exact component scope; dependency context; and existing assessment evidence. Exact affected components remain visible for both analysts and reviewers and follow the active Team scope.

### Assignee Chips And Approval

![Assignee chips and approval](screenshots/assignee-chips-approve.png)

Cards show assigned users and reviewer approval actions when an analyst-submitted assessment is waiting for review.

### Assignee Filter

![Assignee filter](screenshots/assignee-filter.png)

The assignee filter narrows the project view to vulnerabilities assigned to a specific user.

### Automatic Assessment Filter

![Automatic assessment filter](screenshots/automatic-assessment-filter.png)

Automatic assessment markers show groups with saved automatic code-analysis results, and the sidebar filter can narrow the list to vulnerabilities with or without those cached assessments.

### User Assignment Form

![User assignment form](screenshots/user-assignment-form.png)

The expanded assessment form supports assigning users with known-user suggestions.

### Review Context

![Review context](screenshots/vuln-card-review-context.png)

The Assessment tab uses the same section hierarchy as Context and Code Evidence: first confirm the Global or team scope, then complete the decision and rationale. With a Team filter, analysts see only that team's subview; reviewers start focused on it and can explicitly reveal Global and all-team controls. Team subviews present the latest scoped analyzer result as an optional proposal, while saved or manually edited team assessments remain authoritative. The reviewer-only Global subview summarizes the worst effective state across team decisions and analyzer fallbacks, and also contains CVSS and rescoring so the score and assessment can be evaluated together. Ticket references are marked required only when the current rescored severity is High or Critical.

### Inconsistent Assessment

![Inconsistent assessment](screenshots/inconsistent-assessment.png)

Existing assessment evidence in Context shows conflicting team blocks so reviewers can compare states and resolve the mismatch in Assessment.

### Team Mapping

![Team mapping](screenshots/vuln-card-team-mapping.png)

The Team Mapping tab gives reviewers one scrollable component list for adding or editing ownership tags for components seen in the vulnerability.

### Rescored CVSS

![Rescored CVSS](screenshots/rescored-cvss.png)

Rescored vulnerabilities show the original CVSS score, the contextual score, and the direction of the change.

### Global Review CVSS And Rescoring

![Global review CVSS and rescoring](screenshots/vuln-card-cvss-rescoring.png)

The Global subview of Assessment contains the vector editor, visual calculator entry point, current vector comparison, tmrescore reasoning, and analyzer CVSS notes when present.

### CVSS Calculator

![CVSS calculator](screenshots/cvss-calculator.png)

The CVSS modal provides an interactive vector editor for contextual score adjustments.

### Bulk Sync Modal

![Bulk sync modal](screenshots/bulk-sync-modal.png)

Reviewer bulk sync summarizes incomplete assessments before applying consistent state and details in one action.

### Conflict Resolution

![Conflict resolution](screenshots/conflict-resolution.png)

The conflict dialog appears when Dependency-Track changed the underlying analysis while a reviewer was editing; it compares the current server state with the pending change.

## Statistics

### Statistics Page

![Statistics page](screenshots/statistics.png)

The statistics page summarizes severity and state trends across project versions.

### Statistics Sidebar

![Statistics sidebar](screenshots/statistics-sidebar.png)

The project sidebar provides compact counts and filterable state summaries without leaving the review page.

## Configuration And Archives

### Settings

![Settings](screenshots/settings.png)

Settings provide structured and raw editors for team mapping, including deterministic selectors for component names, groups, package URLs, case-sensitive matches, and no-group matches.

### Settings Archives

![Settings archives](screenshots/settings-archives.png)

The archive tab exports, imports, previews, applies, and downloads project archive snapshots.

## Threat-Model Rescoring

### TMRescore

![TMRescore](screenshots/tmrescore.png)

The threat-model rescoring screen prepares a synthetic analysis SBOM, selects latest-only or merged multi-version scope, and submits tmrescore inputs with optional LLM enrichment.
The configured model is reported by vscorer and shown read-only in DTVP.

## Code Analysis

### Running Inline Scan

![Code analysis running](screenshots/code-analysis-running.png)

The Code Evidence tab shows inline code-analysis state, queue position, active progress, and the current pipeline activity.

### Inline Scan Result

![Code analysis result](screenshots/code-analysis-result.png)

Analysts start with the target-oriented runs section; reviewers start with the Combined assessment and its worst latest verdict plus component-level rationale. The expandable new-analysis control sits inside the runs section above a semantic target list, whose rows keep View, Use as draft, Earlier runs, and Delete actions. Selecting a row opens one indented detail region directly below it with the dismissible outcome, summary, rationale, follow-up context, and all peer disclosures. Assessment draft, benchmark, component results, ticket, version coverage, LLM conversation, and pipeline evidence start collapsed. Derivative benchmark records do not displace a target's latest analysis. Combined preview and draft preparation share the same worst-state ordering, with analyzer CVSS used only as a same-state tie-breaker. When a Team filter is active, history and availability badges include only compatible team-targeted runs (including configured aliases) plus legacy runs for the visible components; combining results stages only the filtered team's draft.

Opening LLM Conversation provides a taller vertically resizable timeline with an optional near-full-screen dialog. A summary above the timeline reports Local-to-LLM and LLM-to-Local message/token totals, captured and per-turn timing, inferred inter-turn local/tool time, retries, context adaptation, model/provider coverage, and requested-versus-locally-executed tool statistics. Every captured turn separates the Agentyzer-assembled request, tool exchange, and raw model response with explicit direction labels and copy actions. Tool activity also identifies bounded local dependent-repository inspections and their returned evidence separately from web/package fetches. If no trace was persisted, configured prompt values remain visibly marked as a non-captured fallback.
The Additional guidance used panel lists the exact component/reviewer guidance found in persisted model requests and the turn numbers that received it. Guidance saved on the analyzer request but absent from the trace is marked as not verifiable; storage-policy redaction is explicit rather than being mistaken for an empty guidance configuration. Follow-up runs resolve static guidance against their selected target component as well as initial runs.
Each request, tool, and response stage is independently collapsible. Requests and tool evidence start closed while model responses remain open; Expand all and Collapse all switch the complete conversation between audit and overview modes. Expanded stage bodies are bounded, keyboard-focusable scroll regions so unusually long prompts, traces, and answers do not obscure the rest of the conversation. Inline and nested regions pass unused wheel scrolling to the surrounding detail view when they have no overflow or reach a boundary; only the full-screen dialog contains overscroll.

### Code Analysis Dashboard

![Code analysis dashboard](screenshots/code-analysis-dashboard.png)

The dedicated dashboard shows DTVP worker state, queue pressure, active agents, model and LLM backend metadata, analyzer configuration, external jobs, auto-sweep status, and expandable structured scan logs. Expanded logs keep the newest line visible and use text color for log levels without boxed rows.

### Analysis Queue Dropdown

![Analysis queue dropdown](screenshots/analysis-queue-dropdown.png)

The header dropdown remains a compact shortcut for recent queued, running, and completed code-analysis jobs, with a link to the full dashboard.
