# CI security pipeline

`.github/workflows/security.yml` runs on pushes to `main`, pull requests, weekly (Mondays 06:17 UTC) and on demand. Top-level permissions are `contents: read`; only jobs that upload SARIF get `security-events: write`. Every third-party action is pinned to a full commit SHA, and the Semgrep container to a digest.

| Job | What it runs | Output |
|---|---|---|
| `pytest` | `tests/` (tracker smoke tests, triage unit tests, path traversal tests). Known, unfixed vulnerabilities are `xfail(strict=True)`. | job summary line, `pytest.xml` |
| `semgrep` | `semgrep/semgrep:1.184.0` container; packs `p/default p/python p/flask p/javascript p/dockerfile` on `p2p/` | `semgrep.sarif` → code scanning + artifact |
| `codeql` | CodeQL **advanced setup** (Default setup must be off), `security-extended`, `python` and `javascript-typescript`, `build-mode: none`, paths limited to `p2p/` (`.github/codeql/codeql-config.yml`) | code scanning + `codeql-*.sarif` artifact |
| `osv-scanner` | `google/osv-scanner-action` v2.7.0 on `p2p/` | `osv.json` artifact; `osv.sarif` → code scanning |
| `gitleaks` | `gitleaks/gitleaks-action` v3.0.0 with gitleaks 8.30.1, full clone | `gitleaks.sarif` → code scanning + artifact; **fails on any leak** |
| `trivy` | `aquasecurity/trivy-action` v0.36.0 with trivy v0.76.2: `fs` and `config` on `p2p/`; builds both images and scans them | JSON artifacts + `base-images.json`; SARIF → code scanning |
| `triage` | `scripts/triage.py` on all artifacts, `--compare-to security-reports/baseline/findings.csv` | `findings.csv`, `summary.md`, job summary; **fails on new P1** |

`triage` runs even if a scanner job failed. It first checks that every expected report exists, because a missing report would silently lower the counts.

## Scope: app code only

Every scanner targets `p2p/`, so `requirements-dev.txt`, `requirements-test.txt`, `tests/` (including the triage fixtures, which are fake reports) and `scripts/` never count as app findings. Gitleaks is the exception: it scans git history, where scoping by path would hide leaks.

Dependabot alerts come from GitHub's dependency graph, which reads every manifest in the repo, including `requirements-dev.txt` and `requirements-test.txt`. The report counts Dependabot alerts only for manifests under `p2p/` (the alert's `manifest_path`).

## Differences from the local baseline scan

The local before/after scans (`scripts/run-scans.sh`) are built for exact comparison; CI is built to catch new risk. They differ on purpose:

| | Local (`run-scans.sh`) | CI (`security.yml`) |
|---|---|---|
| Semgrep rules | dated snapshot of the packs (sha256 in `TOOL_VERSIONS.txt`) | live registry packs |
| Vulnerability data | pinned Trivy DB and OSV offline DB | latest at run time |
| Scan root | whole clean worktree (at `4ec80e1`: only `p2p/` and a README) | `p2p/` |
| Gitleaks range | full history of the commit (for the baseline: `4ec80e1`, the app only) | new commits on push/PR, **including this branch's own committed reports**; full history on schedule/dispatch |
| OSV-Scanner | official v2.7.0 image, offline DB | official v2.7.0 action, live API |
| Image SARIF in code scanning | n/a | HIGH and CRITICAL only (to keep the alert list usable); triage still uses the full JSON |

Phase 5 before/after numbers come from the local method, not from CI.

Because CI Gitleaks scans the pull request's commits, it also scans the committed scanner reports, which the local baseline never saw. The first CI run (42339552357) flagged 2 `generic-api-key` hits in `security-reports/baseline/trivy-image-peer.json`. Both were the official Python image's public release-signing key fingerprint (`ENV GPG_KEY=…`), copied in by Trivy. `.gitleaks.toml` allowlists exactly that pattern, only in Trivy image reports, and `.security/triage.yaml` records why. The allowlist was tested to still flag the same value in app code or in other reports, other key names in the same report, and non-fingerprint `GPG_KEY` values. These hits are not part of the Gitleaks baseline count (0), which covers the app at `4ec80e1`.

## Known gaps

- Trivy does not detect the tracker's lowercase `dockerfile` (see `security-reports/baseline/NOTES.md`).
- Dependabot's npm entry points at `p2p/`, whose manifest is misnamed (`pacakage.json`) and invalid JSON, so Dependabot reports it cannot find `package.json` until that is fixed.
- The workflow's `push` trigger is `main` only. A push to `security/appsec-pipeline` does not start it; it runs on a pull request, or through `workflow_dispatch` once the workflow file is on the default branch.
