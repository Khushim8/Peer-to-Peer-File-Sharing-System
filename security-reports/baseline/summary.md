# Triage summary: baseline

Generated 2026-11-09 18:18 UTC by `scripts/triage.py`. Formula: `docs/security/PRIORITIZATION.md`.

## Vulnerabilities per tool (unique package + advisory pairs)

Headline unit is a unique (package, advisory) pair per tool: the same advisory on the same package counts once, however many manifests, images or layers report it. Raw entries are shown only for traceability.

| Tool | Unique advisory IDs | Unique (pkg, advisory) | Fixable | No fix | App deps | App-added OS pkgs | Base-image OS pkgs | Base-image lang pkgs | Origin unknown | OSV inferred-transitive | Raw entries |
|---|---|---|---|---|---|---|---|---|---|---|---|
| osv-scanner | 49 | 49 | 49 | 0 | 49 | 0 | 0 | 0 | 0 | 45 | 141 |
| trivy-fs | 4 | 4 | 4 | 0 | 4 | 0 | 0 | 0 | 0 | 0 | 9 |
| trivy-image | 8386 | 13676 | 11345 | 2331 | 32 | 0 | 13633 | 11 | 0 | 0 | 14169 |

## Severity per tool (unique)

| Tool | Critical | High | Medium | Low | Unknown | Total |
|---|---|---|---|---|---|---|
| codeql | 0 | 0 | 1 | 0 | 0 | 1 |
| osv-scanner | 2 | 20 | 21 | 6 | 0 | 49 |
| semgrep | 0 | 2 | 1 | 4 | 0 | 7 |
| trivy-config | 0 | 2 | 0 | 1 | 0 | 3 |
| trivy-fs | 0 | 2 | 4 | 1 | 0 | 7 |
| trivy-image | 235 | 2416 | 7688 | 3183 | 154 | 13676 |

## Priority (deduplicated across tools, open findings)

A finding is one (package, advisory) pair, or one rule class at one location. *OSV inferred-only*: reported only from OSV-Scanner's inferred transitive versions and not confirmed by any scan of an installed package; check the installed version before acting.

| Priority | Findings | Unique advisories | New | SAST | SCA | Container | IaC | Secret | Fixable | OSV inferred-only |
|---|---|---|---|---|---|---|---|---|---|---|
| P1 | 11 | 7 | 11 | 0 | 0 | 11 | 0 | 0 | 11 | 0 |
| P2 | 3791 | 1873 | 3791 | 0 | 22 | 3766 | 3 | 0 | 3142 | 7 |
| P3 | 9907 | 6529 | 9907 | 6 | 27 | 9873 | 1 | 0 | 8215 | 16 |

Deduplicated findings: 13709 (29 reported by more than one tool). Triaged out: 0.

## Enrichment

- CVEs: 8352, with an EPSS score: 8349 (EPSS dates: 2026-11-06)
- CISA KEV catalog: 2026.11.06 (released 2026-11-06T19:44:45.1797Z)
- KEV matches: 7

## Triage file notes

- matched nothing: generic-api-key
- matched nothing: sourcegraph-access-token

## New P1 findings

| ID | Rule/CVE | Package/file | Why |
|---|---|---|---|
| cb4c020ef02f | CVE-2025-15467 | libssl3t64 | CVSS 9.8, EPSS 0.74793 |
| 3457db5936c7 | CVE-2025-15467 | openssl | CVSS 9.8, EPSS 0.74793 |
| cd56d980c62a | CVE-2025-15467 | openssl-provider-legacy | CVSS 9.8, EPSS 0.74793 |
| e9b1d68dc950 | CVE-2026-111497 | libbrotli-dev | KEV |
| 4eb45056772b | CVE-2026-111497 | libbrotli1 | KEV |
| 79f178d53ae3 | CVE-2025-15467 | libssl-dev | CVSS 9.8, EPSS 0.74793 |
| 6078b0fc51a3 | CVE-2026-31431 | linux-libc-dev | KEV |
| 71e5b7a5585f | CVE-2026-46300 | linux-libc-dev | KEV |
| e8d6b34d2ffc | CVE-2026-53266 | linux-libc-dev | KEV |
| e28da6cd05ad | CVE-2026-53362 | linux-libc-dev | KEV |
| 821b9dc7a96a | CVE-2025-39964 | linux-libc-dev | KEV |
