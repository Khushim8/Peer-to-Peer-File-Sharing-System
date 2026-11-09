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

### Secrets inside compressed reports

Gitleaks skips archives unless given `--max-archive-depth`, so `trivy-image-tracker.json.gz` was a blind spot. gitleaks-action hard-codes its arguments, so the `gitleaks` job adds a second step: the same Gitleaks binary (8.30.1) and config, running `gitleaks dir security-reports --max-archive-depth 2`. Its output is `gitleaks-archives.sarif`. Compressed files only occur under `security-reports/`. Locally, `run-scans.sh` passes `--max-archive-depth 2` to `gitleaks git`.

Turning it on found 53 hits inside the gzipped tracker report:
- **2** were the same `GPG_KEY` fingerprint, already covered by the first allowlist entry.
- **51** were `sourcegraph-access-token` matches on public kernel commit URLs (`git.kernel.org/stable/c/<sha>`, `/linus/<sha>`) in Trivy's CVE references. Each matched line was checked: all 51 are exactly such a URL.

A second allowlist entry covers only that rule, only lines that are exactly one such URL, and only Trivy image reports. Gitleaks percent-decodes before matching, so the entry accepts the URL's optional ` (7.3-rc1)` suffix encoded or decoded. It was tested to still flag the same URL in app code or another report, a bare 40-hex value in the same report, and a URL line with extra content. With both entries, the branch commits and `security-reports/` scan clean at archive depth 0, 1 and 2.

### CodeQL in pull request runs

On pull requests, CodeQL ran with `"incrementalMode": "diff-informed"`, which can limit path queries (such as `py/path-injection`) to code the pull request changes. A PR that does not touch `p2p/` can therefore miss findings that a full analysis would report, so a clean PR result is not proof of absence. The CodeQL before/after numbers therefore come from a full local analysis: `scripts/run-scans.sh codeql`, with the same CodeQL 2.27.4 bundle, `security-extended` suites and config as CI. The JavaScript extractor also fails on the invalid `p2p/pacakage.json`.

**Coverage gap: socket input.** Even the full analysis does not flag the peer path traversal. CodeQL's Python models treat `flask.request`, `input()`, environment variables, command-line arguments and file reads as sources, but not `socket.recv()`, so the peer protocol's input is never tracked into `open()`. The traversal is covered by `tests/test_peer_path_traversal.py` and reported as manual (details: `security-reports/baseline/NOTES.md`).

## GitHub alert counts vs triage counts

GitHub's code-scanning total (3,062 open on PR #1 for run 42339552357; see `security-reports/baseline/GITHUB_UI_COUNTS.md`) and triage's count for the same run (13,715 deduplicated findings, in the run's `triage` artifact `summary.md`) measure different things. Neither is wrong:

- **Severity filter:** code scanning gets the image SARIF with only Critical and High; triage reads every severity from the JSON.
- **Unit of counting:** GitHub makes one alert per rule (advisory) and location per upload category, and its location fingerprints group results differently from triage's (package, advisory) pairs. For example, several binary packages carrying one CVE may share a location.
- **No cross-tool or cross-image deduplication in GitHub:** each SARIF category (`semgrep`, `/language:python`, `osv-scanner`, `gitleaks`, `trivy-fs`, `trivy-image-tracker`, `trivy-image-peer`) is counted on its own. The same CVE in both images, or from OSV and Trivy, is several alerts. Triage merges them.
- **Different OSV and Trivy-fs inputs:** OSV's SARIF has one result per advisory per manifest location; triage merges aliases across manifests.
- **State:** GitHub counts open alerts, which change as alerts are fixed, dismissed or closed by later runs. Triage counts what one set of reports contains.

The report's before/after numbers come from triage on the raw reports. GitHub's numbers are recorded only as a cross-check, by tool, in `GITHUB_UI_COUNTS.md`.

## Known gaps

- Trivy does not detect the tracker's lowercase `dockerfile` (see `security-reports/baseline/NOTES.md`).
- Dependabot's npm entry points at `p2p/`, whose manifest is misnamed (`pacakage.json`) and invalid JSON, so Dependabot reports it cannot find `package.json` until that is fixed.
- The workflow's `push` trigger is `main` only. A push to `security/appsec-pipeline` does not start it; it runs on a pull request, or through `workflow_dispatch` once the workflow file is on the default branch.
