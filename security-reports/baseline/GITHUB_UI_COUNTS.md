# GitHub-side baseline counts (read manually)

These numbers come from the GitHub web UI and from GitHub's `git push` response, not from a saved tool report. The Dependabot and code-scanning APIs need authentication, which this project's local tooling does not use. They are recorded separately from the triage counts in `summary.md`, which come from the raw reports in this folder. Fields marked *not yet provided* were not read.

## Dependabot alerts: `main` (`4ec80e1`, unmodified app)

| Field | Value | Source |
|---|---|---|
| Open alerts | **6** | GitHub UI, read manually by the repo owner on 2026-11-09 |
| By severity | 6 moderate (0 critical, 0 high, 0 low implied) | GitHub `git push` response on 2026-11-06 and 2026-11-09: "GitHub found 6 vulnerabilities on …'s default branch (6 moderate)". The UI breakdown was *not yet provided*. |
| Packages | *not yet provided* | |
| Manifest paths | *not yet provided* | Needed to confirm all 6 are under `p2p/`: `main` has no dev manifests, so they should be. |

## Code-scanning alerts: PR #1 (`is:open pr:1`)

Read in the GitHub UI by the repo owner on 2026-11-09, before commit `f1a8cc8` was pushed. That covers the first workflow run, 42339552357, on PR head `8086522`.

| Tool | Open alerts |
|---|---|
| **Total** | **3,062** |
| CodeQL | *not yet provided* (the run's SARIFs contain 1 result: see `NOTES.md`) |
| Semgrep | *not yet provided* |
| Gitleaks | *not yet provided* |
| OSV-Scanner | *not yet provided* |
| Trivy | *not yet provided* |
| CodeQL path traversal | *not yet provided* (the run's SARIFs contain no `py/path-injection` result) |

Why this total differs from triage's counts: see `docs/security/PIPELINE.md`, "GitHub alert counts vs triage counts".
