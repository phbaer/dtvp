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

The project review page is the main vulnerability workflow. It combines grouped vulnerability cards, lifecycle state, team ownership, assessment controls, dependency-path context, and code-analysis shortcuts.

### Lifecycle Badges

![Lifecycle badges](screenshots/lifecycle-badges.png)

The lifecycle view shows the project list with open, incomplete, inconsistent, needs-approval, assessed, and rescored states visible together.

## Vulnerability Review Details

### Vulnerability Card Overview

![Vulnerability card overview](screenshots/vuln-card-overview.png)

The Overview tab starts with the advisory description and references, then shows affected components, team ownership, and dependency context.

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

The Review tab keeps the global or team assessment form together with persisted review context. Ticket references are marked required only when the current rescored severity is High or Critical.

### Inconsistent Assessment

![Inconsistent assessment](screenshots/inconsistent-assessment.png)

The Assessments tab shows conflicting team assessment blocks so reviewers can compare states and resolve the mismatch.

### Team Mapping

![Team mapping](screenshots/vuln-card-team-mapping.png)

The Team Mapping tab gives reviewers one scrollable component list for adding or editing ownership tags for components seen in the vulnerability.

### Rescored CVSS

![Rescored CVSS](screenshots/rescored-cvss.png)

Rescored vulnerabilities show the original CVSS score, the contextual score, and the direction of the change.

### CVSS And Rescoring Tab

![CVSS and rescoring tab](screenshots/vuln-card-cvss-rescoring.png)

The CVSS & Rescoring tab contains the vector editor, visual calculator entry point, current vector comparison, tmrescore reasoning, and analyzer CVSS notes when present.

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

## Code Analysis

### Running Inline Scan

![Code analysis running](screenshots/code-analysis-running.png)

Expanded vulnerability cards show inline code-analysis state, queue position, active progress, and the current pipeline activity.

### Inline Scan Result

![Code analysis result](screenshots/code-analysis-result.png)

Completed inline results show the generated assessment, confidence, CVSS adjustment, and pipeline evidence that can be applied back to the assessment workflow.

### Code Analysis Dashboard

![Code analysis dashboard](screenshots/code-analysis-dashboard.png)

The dedicated dashboard shows DTVP worker state, queue pressure, active agents, model and LLM backend metadata, analyzer configuration, external jobs, auto-sweep status, and expandable structured scan logs. Expanded logs keep the newest line visible and use text color for log levels without boxed rows.

### Analysis Queue Dropdown

![Analysis queue dropdown](screenshots/analysis-queue-dropdown.png)

The header dropdown remains a compact shortcut for recent queued, running, and completed code-analysis jobs, with a link to the full dashboard.
