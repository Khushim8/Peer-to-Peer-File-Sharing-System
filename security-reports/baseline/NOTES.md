# Baseline scan notes

Raw outputs in this folder come from one run of

```bash
git -c core.autocrlf=false worktree add --detach ../baseline-4ec80e1 4ec80e1
scripts/run-scans.sh prepare-db
scripts/run-scans.sh scan ../baseline-4ec80e1 security-reports/baseline baseline
```

against a clean, LF checkout of the unmodified commit `4ec80e1`. Tool, rule-pack and database versions are in `TOOL_VERSIONS.txt`; console output is in `scan.log` (ANSI codes and progress bars stripped). Reports over 50 MB are gzipped by the script, losslessly (`trivy-image-tracker.json.gz`; read it with `gzip -dc`). The Phase 5 "after" scan, and a rescan of `4ec80e1` with the same database snapshots, use the same script.

The counts below are read straight from the files in this folder. They are raw tool counts, before deduplication and triage (Phase 2).

| Report | Raw count |
|---|---|
| `semgrep.sarif` | 8 results: 3 error, 1 warning, 4 note |
| `osv.json` | 258 advisory entries, 141 groups summed over 3 manifests, 49 unique package + advisory-group pairs (by OSV `max_severity`: 2 ≥ 9.0, 20 at 7.0–8.9, 21 at 4.0–6.9, 6 below 4.0) |
| `gitleaks.json` | 0 (1 commit scanned). `run-scans.sh` now adds `--max-archive-depth 2`; `4ec80e1` contains no archives, so that cannot change this result. |
| `codeql-python.sarif`, `codeql-javascript.sarif` | 1 and 0 (from CI; see below) |
| `trivy-fs.json` | 6 vulnerabilities (6 MEDIUM); 3 misconfigurations (2 HIGH, 1 LOW); 0 secrets |
| `trivy-config.json` | 3 misconfigurations (2 HIGH, 1 LOW) |
| `trivy-image-tracker.json.gz` | 13,645 vulnerability entries (235 CRITICAL, 2,409 HIGH, 7,669 MEDIUM, 3,178 LOW, 154 UNKNOWN); 0 secrets |
| `trivy-image-peer.json` | 524 vulnerability entries (6 CRITICAL, 137 HIGH, 215 MEDIUM, 163 LOW, 3 UNKNOWN); 0 secrets |

Trivy image counts are one entry per (installed package, vulnerability) pair, so one CVE in a source package that ships several binary packages is counted several times. Almost all of them are Debian OS packages: the tracker uses the full `python:3.9` image with `build-essential`.

## CodeQL baseline (from CI)

CodeQL only runs on GitHub, so its baseline comes from the first workflow run: run 42339552357 (`pull_request`, PR #1, head `8086522`, started 2026-11-07 04:41 UTC). `git diff 4ec80e1 8086522 -- p2p` is empty, so the app code analysed is exactly the baseline's. CodeQL 2.27.4, `security-extended`, `build-mode: none`, paths `p2p/`. The SARIFs are copied unchanged from the run's artifacts.

| File | Language | Results |
|---|---|---|
| `codeql-python.sarif` | python | **1**: `py/bind-socket-all-network-interfaces`, `p2p/peer_client/server.py:34` (security-severity 6.5) |
| `codeql-javascript.sarif` | javascript-typescript | **0**. Extraction failed for `p2p/pacakage.json` ("Unexpected token": the file is invalid JSON). The only JavaScript is the 3 Truffle config and migration files. |

**Path traversal:** CodeQL did **not** flag it. `py/path-injection` was in the query set, with no result. This is not conclusive: the run used `"incrementalMode": "diff-informed"`, which on pull requests can limit path queries to code the PR changes, and this PR changes no app code. A full, non-PR analysis is needed to settle it. Separately, CodeQL may not model `socket.recv()` as untrusted input at all. The traversal is confirmed by `tests/test_peer_path_traversal.py`, reported as manual.

## Coverage gaps (what the tools did not see)

- **`p2p/Tracker_server/requirements.txt` is unpinned.** OSV-Scanner read 5 packages and dropped all of them ("Filtered 5 local/unscannable package/s"), and Trivy fs reports no result for that file. The tracker's dependency risk only shows up in `trivy-image-tracker.json` (the `Python` target), which scans what pip actually installed (listed in `resolved-deps-tracker.txt`).
- **The tracker `dockerfile` (lowercase) is not detected by Trivy.** `trivy fs` and `trivy config` list only `p2p/peer_client/Dockerfile` as a target, so the tracker image's root user, unpinned full base image and so on have no Trivy misconfiguration result. Semgrep does parse it (`missing-user` at `p2p/Tracker_server/dockerfile:22`).
- **`docker-compose.yml` is not scanned for misconfigurations** by any of these tools (Trivy has no Compose scanner). Hardcoded DB passwords and published ports there are in `STACK.md`, not in tool output.
- **`p2p/pacakage.json`** is invalid JSON; Semgrep logs a syntax error for it, and no SCA tool reads it (wrong filename, no lockfile).
- **Gitleaks found 0 leaks.** The DB passwords in `app.py` and `docker-compose.yml` (`password`, `rootpassword`) do not match its default rules.
- **No scanner flagged path traversal** in `peer_client/client.py` or `peer_client/server.py`. That lead stays unverified pending CodeQL (Phase 3) or a test.

## Caveats for triage

- **OSV transitive versions are inferred, not installed.** For the three manifests that pin `web3==6.9.0`, OSV-Scanner also reports `aiohttp 3.9.5`, `certifi 2026.7.22`, `idna 3.9.0` and `pycryptodome 3.9.9` under a second source entry of type `unknown`. These come from OSV's own dependency resolution and do not match what pip installs today (`resolved-deps-peer1.txt`: `aiohttp 3.13.5`, `certifi 2026.10.23`, `idna 3.20`, `pycryptodome 3.24.1`). Triage should check each against the installed versions in `trivy-image-peer.json` before ranking it. The raw counts above are kept as reported.
- **Duplicated manifests.** `web3==6.9.0` is pinned in three `requirements.txt` files, so OSV and Trivy fs report the same advisories up to three times.
- **Database dates.** Trivy DB `UpdatedAt 2026-11-06 18:59:52 UTC`; OSV PyPI database downloaded 2026-11-06 20:11:30 UTC. OSV's transitive resolution also queries the network at scan time, so it is not fully pinned by the offline database.

## How the baseline run was made reproducible

These are scanning-method details, not changes to the app:

- **LF checkout.** Git for Windows (`core.autocrlf=true`) checks out CRLF. Semgrep then fails to parse the tracker `dockerfile`, and images get built from bytes that differ from the commit. The script refuses CRLF-converted targets.
- **UTF-8 SARIF.** Without `PYTHONUTF8=1`, Semgrep on Windows writes the SARIF in the console code page (cp1252), which is not valid UTF-8.
- **Relative paths, registry rule IDs.** All scanners run from inside the target. OSV-Scanner runs from its official image (`ghcr.io/google/osv-scanner:v2.7.0`, same commit as the Windows binary) because it always reports absolute paths. Semgrep rule packs are loaded from a dated snapshot (sha256 in `TOOL_VERSIONS.txt`) placed beside the target, so rule IDs match the registry's.
