# Finding prioritization

`scripts/triage.py` ranks every deduplicated finding P1, P2 or P3. The CI gate fails only on **new, open P1** findings.

## Formula

Rules are checked top to bottom; the first match wins.

| Priority | Rule |
|---|---|
| **P1** | The CVE is in the CISA KEV catalog. |
| **P1** | A secret marked `confirmed_live` in `.security/triage.yaml` (verified as a working credential). |
| **P1** | CVSS ≥ 9.0 **and** EPSS ≥ 0.1. |
| **P2** | CVSS ≥ 7.0. |
| **P2** | No CVSS score, and the tool's severity is High or Critical (misconfigurations, SAST, unconfirmed secrets). |
| **P2** | SAST finding in an injection or auth class (CWE list below) in shipped app code (`p2p/`). |
| **P3** | Everything else. |

**Injection and auth CWEs:** 22, 23, 36, 73 (path traversal); 77, 78, 88 (command injection); 79, 80 (XSS); 89, 90, 643, 917, 1336 (SQL, LDAP, XPath, expression and template injection); 94, 95 (code injection); 502 (deserialization); 611 (XXE); 918 (SSRF); 284, 285, 287, 306, 639, 798, 862, 863 (access control, authentication, hardcoded credentials).

**"Reachable"** is approximated as "in shipped app code under `p2p/`", not call-graph reachability. No tool here computes reachability, so this rule can only promote a finding by where it is, not by whether attacker input reaches it.

## Inputs

| Field | Source |
|---|---|
| CVSS | OSV: the group's `max_severity`. Trivy: NVD V3 score if present, else GHSA, else the highest vendor score. When tools disagree on a merged finding, the highest score is kept. |
| EPSS | FIRST API, `https://api.first.org/data/v1/epss?cve=…`; the highest EPSS across a finding's CVE aliases. Cached in `security-reports/cache/epss.json` and refetched after 7 days. |
| KEV | CISA catalog, `known_exploited_vulnerabilities.json`; a finding is on KEV if any of its CVE aliases is. Cached in `security-reports/cache/kev.json` and refetched after 24 h. If KEV cannot be loaded, `summary.md` says so, because KEV-based P1s are then missed. |
| Severity | Trivy and OSV: as reported (OSV from CVSS bands: ≥ 9 Critical, ≥ 7 High, ≥ 4 Medium, else Low). SARIF: `security-severity` (CodeQL) if present, else level: `error` High, `warning` Medium, `note` Low. Gitleaks: High. |

`summary.md` records the EPSS score date and the KEV catalog version for every run.

## Deduplication

Findings from different tools merge into one finding with a `reported_by` list when:

- **Vulnerabilities (SCA, container):** same ecosystem and package name, and the advisories share any ID or alias (CVE, GHSA, PYSEC, …). The finding keeps every installed version, location and origin seen. Distro advisory IDs (Trivy `VendorIDs`, e.g. Debian `DSA-6238-1`) are **not** aliases: one DSA covers many distinct CVEs (that one covers 395 kernel CVEs), so using them would merge unrelated vulnerabilities.
- **SAST:** same rule class (lowest CWE, else rule ID) at the same file and line.
- **IaC:** same rule class in the same file. Equivalent rules are mapped explicitly; for example, Semgrep `missing-user` and Trivy `DS-0002` are both `dockerfile-root-user`.
- **Secrets:** same file and line.

A finding's `id` is a hash of its identity (package and advisory, or rule class and location; SAST uses CodeQL's line-independent fingerprint where available). It is stable across runs, which is how `--compare-to` decides what is new.

## What the headline numbers count

Raw scanner entries are never used as headline numbers. Per tool, `summary.md` reports:

- **Unique advisory IDs** and **unique (package, advisory) pairs.** One CVE in a Debian source package that ships several binary packages (`openssl`, `libssl3t64`, `libssl-dev`) is still one pair per binary package, because each is a separately installed package with its own fix.
- **Fixable vs no fix:** Trivy `Status: fixed`; for OSV, an affected range with a `fixed` event above the installed version. Trivy `affected`, `fix_deferred` and `will_not_fix` count as no fix.
- **Origin:** `app-dep` (packages from the app's manifests, or installed by the Dockerfile's `pip install`); `app-os` (OS packages added by the Dockerfile); `base-os` and `base-lang` (OS and language packages already in the `FROM` image). Origin comes from the image layer that introduced the package, compared with the base image's layers in `base-images.json`. That file is written by `scripts/run-scans.sh` and checked to be an exact prefix of the scanned image's layers; if the check fails, the origin is `unknown`.
- **OSV inferred-transitive:** packages OSV-Scanner did not read from a manifest but inferred from the dependency ranges of a pinned package (source type other than `lockfile`). These can be versions that are not installed. A merged finding is *inferred-only* when no other scan of an installed package confirms it.

## Triage decisions

`.security/triage.yaml` holds false positives and accepted risks. Each entry needs a one-line `reason`, matches by finding `id` or exact `rule_or_cve` (aliases count), may narrow by a `file_or_package` pattern, and may `expire`. Wildcard rule IDs are rejected, so a decision cannot become a blanket ignore. Triaged findings stay in `findings.csv` with their status and reason; they are only left out of the open counts.

## CI gate

The gate fails only on **new, open P1** findings. "New" is relative to a committed comparison file:

- CI runs `scripts/triage.py <reports> --compare-to security-reports/baseline/findings.csv`. That file is the triaged output of the baseline scan of `4ec80e1`, committed in the repo, so the known baseline P1s do not fail the first push of the workflow (push 1) or later runs.
- A finding is new if its `id` is not in the comparison file **at the same or a higher priority**. A finding known only as P2 that becomes P1 (for example, its CVE is added to KEV) is new and fails the gate. So does any P1 from a scanner the baseline did not include (CodeQL's first findings arrive with push 1).
- IDs depend only on package and advisory, or rule class and location, not on the scan environment, so a local baseline and CI scans compare directly.
- The comparison file only changes deliberately: after Phase 4 fixes, the Phase 5 "after" `findings.csv` replaces it in a reviewed commit. Comparing against the target branch's latest findings is the alternative; it was not chosen because it needs artifacts from another workflow run and would quietly accept any P1 already merged to `main`.

## Known limitations

- **`linux-libc-dev` kernel CVEs, including the 5 baseline P1s on KEV, are not exploitable through these containers.** `linux-libc-dev` contains only the Linux kernel's userspace API headers, used to compile programs: checked in the baseline tracker image (`linux-libc-dev 6.12.48-1`), every file it installs is a `.h` header under `/usr/include` or `/usr/lib/linux/uapi/<arch>/`, or documentation under `/usr/share`. It contains no kernel code. A container has no kernel of its own: it runs on the host's kernel, so a kernel CVE is exploitable only if the *host* kernel is vulnerable, whatever this package's version. The tracker image has the package only because the full `python:3.9` base installs compilers and headers. The findings are **not suppressed**: they are ranked by the formula like everything else, and they are fixed by updating or slimming the base image (Phase 4). The `python:3.9-slim` peer image does not contain the package.
- **The CVSS ≥ 7 rule dominates container counts.** Most P2s in the baseline are base-image OS packages. The fixable/no-fix and origin columns exist so that this is visible rather than hidden.
- **SAST IDs without a fingerprint use the line number,** so editing code above a finding can make it look new. This only matters for the gate if a SAST finding is P1, which the formula does not produce.
