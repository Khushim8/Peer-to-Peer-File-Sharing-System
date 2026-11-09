# CodeQL SARIFs from PR run 42339552357 (diff-informed, not the baseline)

Copied unchanged from the `scan-codeql-*` artifacts of workflow run 42339552357 (`pull_request`, PR #1, head `8086522`; app code identical to `4ec80e1`). CodeQL 2.27.4, `security-extended`.

These runs used `"incrementalMode": "diff-informed"`, which can limit path queries to code the pull request changes. They are kept for traceability only. **The CodeQL baseline is `../codeql-python-full.sarif` and `../codeql-javascript-full.sarif`** (full local analysis of `4ec80e1`, same CodeQL version and suite). `scripts/triage.py` reads only the top level of `security-reports/baseline/`, so these files are not counted.

Results here: python 1 (`py/bind-socket-all-network-interfaces`, `p2p/peer_client/server.py:34`), javascript 0. These match the full run.
