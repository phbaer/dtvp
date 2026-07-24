---
okf_version: "0.1"
---

# DTVP Knowledge Bundle

This directory is DTVP's
[Open Knowledge Format (OKF)](https://github.com/GoogleCloudPlatform/knowledge-catalog/blob/main/okf/SPEC.md)
bundle. It is the canonical curated project model for people and software
agents. Start with the smallest concept that matches the task, then inspect the
source paths named in its frontmatter.

Source code, configuration, tests, package metadata, and lockfiles remain the
operational truth. When they disagree with this bundle, trust the operational
source and update the affected concept in the same change.

## Start Here

- [Project overview](project.md)
- [Architecture](architecture/)
- [Bundle conventions and maintenance](conventions.md)

## Specialized References

- [Vendor-neutral runtime configuration, Arcane deployment, demo boundary, and Compose backup reference](configuration.md)
- [External integration API surface](integration-api-surface.md)
- [Threat model](threat-model.md)
- [Workflow flowcharts](workflow-flowcharts.md)
- [Screen guide](screens.md)
