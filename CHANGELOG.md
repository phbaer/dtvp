# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### 🚀 Features
- Add complete team filter dropdown
- Separate vulnerability backends from the DTVP deployment, move the bundled
  Dependency-Track stack and mock runtime to an optional demo, and limit
  backups to DTVP-owned state while excluding disposable Agentyzer clones.
- Replace the PostgreSQL-derived backup scheduler with a minimal Alpine image
  containing only the Docker CLI needed to pause DTVP during snapshots.

## [1.0.15] — 2026-07-20

### 📦 Dependencies
- Chore(deps): update dependency @types/node to v25.9.5 (#146)This PR contains the following updates:| Package | Type | Update | Change |
- Chore(deps): update dependency vue-tsc to v3.3.7 (#144)This PR contains the following updates:| Package | Type | Update | Change |
- Chore(deps): update dependency postcss to v8.5.18 (#141)This PR contains the following updates:| Package | Type | Update | Change |

### 🚀 Features
- Auto assessment bulk accept (#174)
- Update all dependencies, move to httpx2 (#173)
- Bulk sync filtering (#171)
- Add Jira issue handoff for analysis tickets (#170)
- CVSS rescore rules (#167)
- Benchmarking generated and manual assessments (#166)
- Improve code analysis user interface (#165)
- Improve the project loading experience (#164)
- Make assessments and DT state exportable (#163)
- Improve responsiveness by cleaning up the UI and moving logic to the server (#162)
- Add auto vulnerability scan (part 1) (#159)

## [1.0.14] — 2026-06-30

### 🚀 Features
- Update dependencies and improve ai agent rules/skills (#161)
- Add-attributedon-filter (#160)

## [1.0.13] — 2026-06-10

### 🐛 Bug Fixes
- Fix regression in dropdowns (#157)

## [1.0.12] — 2026-06-10

### 🐛 Bug Fixes
- Bump version to v1.0.12 (#156)

### 🚀 Features
- Improve ui responsiveness and usability (#155)

## [1.0.11] — 2026-05-29

### 🚀 Features
- Properly render markdown (#152)

## [1.0.10] — 2026-05-04

### 🐛 Bug Fixes
- Fix regression introduced in code analysis (#143)

## [1.0.9] — 2026-05-04

### 🚀 Features
- Integrate code analysis (#139)
- Add-user-assignments (#138)
- Improve backend cache (#133)New TM rescore insights shall mark issues for review again

## [1.8.0] — 2026-04-22

### 📦 Dependencies
- Chore(deps): update dependencytrack/frontend docker tag to v4.14.1 (#72)This PR contains the following updates:| Package | Update | Change |

### 🚀 Features
- Implement lazy loading (#128)
- Improve-settings-and-tagging (#125)Solves phbaer/dtvp#40
- Add-user-assignments (#121)
- Integrate-vscorer (#111)

## [1.0.7] — 2026-04-10

### 🐛 Bug Fixes
- Improve backend performance (#105)

### 📦 Dependencies
- Chore(deps): update nick-fields/retry action to v4 (#92)This PR contains the following updates:| Package | Type | Update | Change |
- Chore(deps): update docker/setup-qemu-action action to v4 (#81)This PR contains the following updates:| Package | Type | Update | Change |
- Chore(deps): update docker/login-action action to v4 (#75)This PR contains the following updates:| Package | Type | Update | Change |
- Chore(deps): update docker/build-push-action action to v7 (#74)This PR contains the following updates:| Package | Type | Update | Change |
- Chore(deps): update docker/setup-buildx-action action to v4 (#80)This PR contains the following updates:| Package | Type | Update | Change |

### 🚀 Features
- Add a caching layer for synced and speedier reads and writes. Streamline UI. (#115)
- Add a dependency indicator to the vulnerabilities (direct vs. depth > 1) (#104)
- Make it possible to clean an existing CVSS string by removing unnecessary modified flags (#103)
- Improve listing affected versions (#100)
- Improve the "open" filter (#99)

## [1.0.6] — 2026-03-23

### 🚀 Features
- Add a link to the webpage/sources and generate an SBOM (#96)

## [1.0.5] — 2026-03-22

### 🚀 Features
- Feat: improve-statistics phbaer/dtvp#87 (#88)Improved statistics with per-major version analysis.

## [1.0.4] — 2026-03-20

### 🚀 Features
- Add bulk operation for incomplete assessments (#83)Fixes phbaer/dtvp#82

## [1.0.3] — 2026-03-16

### 🐛 Bug Fixes
- Use git commits from local workspace phbaer/dtvp#84

### 📦 Dependencies
- Merge pull request 'Update dependency @vue/tsconfig to ^0.9.0' (#68) from renovate/vue-tsconfig-0.x into main
- Merge pull request 'Update dependency postcss to v8.5.8' (#67) from renovate/postcss-8.x-lockfile into main
- Merge pull request 'Update dependency axios to v1.13.6' (#62) from renovate/axios-1.x-lockfile into main
- Merge pull request 'Update dependency ae-cvss-calculator to v1.0.11' (#61) from renovate/ae-cvss-calculator-1.x-lockfile into main
- Merge pull request 'Update dependency autoprefixer to v10.4.27' (#55) from renovate/autoprefixer-10.x-lockfile into main
- Merge pull request 'Update python Docker tag to v3.14' (#54) from renovate/python-3.x into main
- Merge pull request 'Update dependency lucide-vue-next to ^0.577.0' (#53) from renovate/lucide-vue-next-0.x into main
- Merge pull request 'Update dependency jsdom to v28.1.0' (#52) from renovate/jsdom-28.x-lockfile into main
- Merge pull request 'Update dependency @types/node to v25.3.5' (#51) from renovate/node-25.x-lockfile into main

### 🔀 Merged PRs
- Merge pull request 'Implement a first prototype of a statistics view phbaer/dtvp#66' (#76) from add-statistics-view into main
- Merge pull request 'improve-ui fixes phbaer/dtvp#69' (#70) from improve-ui into main
- Merge pull request 'improve-dependencies-view' (#45) from improve-dependencies-view into main

### 🚀 Features
- Generate and show changelog phbaer/dtvp#84 (#86)
- Add changelog generation phbaer/dtvp#84 (#85)

## [1.0.2] — 2026-03-04

### 📦 Dependencies
- Merge pull request 'Update dependency @tailwindcss/postcss to v4.2.1' (#50) from renovate/tailwindcss-postcss-4.x-lockfile into main
- Merge pull request 'Update dependency @playwright/test to v1.58.2' (#49) from renovate/playwright-test-1.x-lockfile into main
- Merge pull request 'Update dependency vue-tsc to v3.2.5' (#48) from renovate/vue-tsc-3.x-lockfile into main
- Merge pull request 'Update dependency vue-router to v5.0.3' (#47) from renovate/vue-router-5.x-lockfile into main
- Merge pull request 'Update dependency vue to v3.5.29' (#46) from renovate/vue-3.x-lockfile into main
- Merge pull request 'Update dependency vite to v7.3.1' (#44) from renovate/vite-7.x-lockfile into main
- Merge pull request 'Update dependency mermaid to v11.12.3' (#43) from renovate/mermaid-11.x-lockfile into main
- Merge pull request 'Update dependency axios to v1.13.5' (#38) from renovate/axios-1.x-lockfile into main
- Merge pull request 'Update dependency autoprefixer to v10.4.24' (#37) from renovate/autoprefixer-10.x-lockfile into main
- Merge pull request 'Update dependency @vitest/coverage-v8 to v4.0.18' (#36) from renovate/vitest-coverage-v8-4.x-lockfile into main
- Merge pull request 'Update dependency @types/node to v25.2.3' (#35) from renovate/node-25.x-lockfile into main

### 🔀 Merged PRs
- Merge pull request 'Create images again' (#64) from fix-image-creation into main
- Merge pull request 'Add workflow_dispatch trigger' (#63) from add-workflow_dispatch into main
- Merge pull request 'Improve team labels: support multiple labels per team. Fixes phbaer/dtvp#57' (#60) from improve-team-mapping into main
- Merge pull request 'UX Improvements, fixes phbaer/dtvp#58' (#59) from cleanup-interface into main
- Merge pull request 'List all existing projects in the dashboard' (#42) from preload-project-names into main
- Merge pull request 'Improve readme and test coverage' (#41) from improve-readme into main

## [1.0.1] — 2026-02-18

### 🔀 Merged PRs
- Merge pull request 'make-issues-team-assessable' (#34) from make-issues-team-assessable into main
- Merge pull request 'Add MIT license' (#33) from phbaer-patch-1 into main

## [1.0.0] — 2026-02-16

### 📦 Dependencies
- Merge pull request 'Update dependency @vitejs/plugin-vue to v6.0.4' (#23) from renovate/vitejs-plugin-vue-6.x-lockfile into main
- Merge pull request 'Update dependency vue-router to v5' (#22) from renovate/vue-router-5.x into main
- Merge pull request 'Update dependency @types/node to v25' (#17) from renovate/node-25.x into main
- Merge pull request 'Update dependency jsdom to v28' (#24) from renovate/jsdom-28.x into main
- Merge pull request 'Update dependency @types/node to v24.10.11' (#25) from renovate/node-24.x-lockfile into main
- Merge pull request 'Update dependency autoprefixer to v10.4.24' (#20) from renovate/autoprefixer-10.x-lockfile into main
- Merge pull request 'Update astral-sh/setup-uv action to v7' (#16) from renovate/astral-sh-setup-uv-7.x into main
- Merge pull request 'Update dependency vite to v7.3.1' (#9) from renovate/vite-7.x-lockfile into main
- Merge pull request 'Update dependency @types/node to v24.10.9' (#6) from renovate/node-24.x-lockfile into main
- Merge pull request 'Update actions/checkout action to v6' (#14) from renovate/actions-checkout-6.x into main
- Merge pull request 'Update dependency vue to v3.5.27' (#10) from renovate/vue-3.x-lockfile into main
- Merge pull request 'Update dependency vue-tsc to v3.2.4' (#11) from renovate/vue-tsc-3.x-lockfile into main
- Merge pull request 'Update dependency lucide-vue-next to ^0.563.0' (#13) from renovate/lucide-vue-next-0.x into main
- Merge pull request 'Update dependency axios to v1.13.4' (#8) from renovate/axios-1.x-lockfile into main
- Merge pull request 'Update dependency @playwright/test to v1.58.0' (#12) from renovate/playwright-test-1.x-lockfile into main
- Merge pull request 'Update dependency @vitest/coverage-v8 to v4.0.18' (#7) from renovate/vitest-coverage-v8-4.x-lockfile into main

### 🔀 Merged PRs
- Merge pull request 'Fix reshuffling' (#31) from fix-mixed-view into main
- Merge pull request 'improve-parallel-operations' (#27) from improve-parallel-operations into main
- Merge pull request 'add-user-roles' (#26) from add-user-roles into main
- Merge pull request 'Improve pipeline: remove debian image' (#21) from make-pipeline-more-resilient into main
- Merge pull request 'Improve pipeline stability: add retries' (#18) from make-pipeline-more-resilient into main
- Merge pull request 'Improve the processing logic' (#5) from improve-efficiencs-and-reduce-complexity-of-vuln-processing into main
- Merge pull request 'Add tag support' (#4) from add-tag-support into main
- Merge pull request 'improve responsiveness and test coverage' (#1) from improve-test-coverage into main
