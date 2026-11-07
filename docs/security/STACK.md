# Stack inventory (Phase 0)

Snapshot of the unmodified code at commit `4ec80e1` (branch `security/appsec-pipeline`), taken 2026-11-06.

## Repository

- `https://github.com/Khushim8/Peer-to-Peer-File-Sharing-System`: **public** (GitHub API `"visibility": "public"`), so CodeQL and code-scanning SARIF upload are free; GitHub Advanced Security is not needed.
- Default branch: `main`.
- All application code lives under `p2p/`.

## Languages and frameworks

| Component | Path | Language / framework | Runtime |
|---|---|---|---|
| Tracker API | `p2p/Tracker_server/` | Python, Flask 3, Flask-SQLAlchemy (ORM), PyMySQL | `python:3.9` image (Debian 13), Flask dev server on `0.0.0.0:5000` |
| Peer client | `p2p/peer_client/` | Python, raw TCP sockets, `requests`, web3.py | `python:3.9-slim` image; interactive CLI (`input()` menu) |
| Blockchain logger | `p2p/blockchain_logger/` and a second, diverged copy in `p2p/peer_client/blockchain_logger/` | Python, web3.py 6.9.0 | used by the peer client |
| Smart contracts | `p2p/contracts/*.sol` | Solidity `^0.8.0` (`FileShareLogger`, `Migrations`) | Ganache (`trufflesuite/ganache-cli:latest`) |
| Contract tooling | `p2p/truffle-config.js`, `p2p/migrations/*.js` | Node.js, Truffle | not containerised |
| Database | `docker-compose.yml` | MySQL `8.0` | container |

Python 3.9 reached end of life in October 2025. Both images run Python 3.9.25.

## Dependency manifests

| File | Ecosystem | Pinned? | Notes |
|---|---|---|---|
| `p2p/Tracker_server/requirements.txt` | PyPI | **No**: `cryptography`, `Flask`, `Flask-SQLAlchemy`, `mysqlclient`, `pymysql`, all unversioned | OSV-Scanner cannot match an unversioned requirement to an advisory, so a source scan understates tracker SCA risk. The versions pip resolved at build time are in `security-reports/baseline/resolved-deps-tracker.txt`. `mysqlclient` is installed but never imported: `app.py` uses PyMySQL via `pymysql.install_as_MySQLdb()`. |
| `p2p/peer_client/requirements.txt` | PyPI | Yes: `requests==2.31.0`, `web3==6.9.0` | Transitive deps are unpinned; resolved set in `security-reports/baseline/resolved-deps-peer1.txt`. |
| `p2p/blockchain_logger/requirements.txt` | PyPI | Yes: `web3==6.9.0` | |
| `p2p/peer_client/blockchain_logger/requirements.txt` | PyPI | Yes: `web3==6.9.0` | duplicate |
| `p2p/pacakage.json` | npm | n/a | **Misnamed** (`pacakage`) and **not valid JSON**: line 1 starts with a stray `web3==6.9.0` (`JSON.parse` → `SyntaxError: Unexpected token 'w'`). Declares `truffle ^5.11.4` and `@truffle/hdwallet-provider ^2.1.13`. No lockfile. npm, OSV-Scanner and Dependabot are not expected to read it under this name. |
| lockfiles | none | | No `package-lock.json`, `poetry.lock`, `Pipfile.lock`, etc. |

## Container and IaC files

| File | Notes |
|---|---|
| `p2p/Tracker_server/dockerfile` | Lowercase filename. Base image `python:3.9` (full, not slim; built image is 1.66 GB) + `build-essential` and `default-libmysqlclient-dev`. No `USER` (runs as root). **Trivy does not detect it** (Phase 1: `trivy fs` and `trivy config` list only the peer Dockerfile). Semgrep does parse it. Dependabot detection is checked after push 1. |
| `p2p/Tracker_server/docker` | Empty file (0 bytes). |
| `p2p/peer_client/Dockerfile` | Base `python:3.9-slim`, no `USER` (runs as root). Two `CMD` lines (the second, `tail -f /dev/null`, wins). `COPY ../blockchain_logger ./blockchain_logger` references a path outside the build context; **it builds anyway** under BuildKit (see below). |
| `p2p/docker-compose.yml` | `mysql:8.0`, `trufflesuite/ganache-cli:latest` (unpinned, `latest`), tracker, peer1, peer2. Publishes MySQL `3306`, Ganache `8545`, tracker `5000`, peers `6001`/`6002` on all host interfaces. |
| Kubernetes manifests | **None in the repo.** The spec mentions them; nothing was added just to scan. IaC scanning covers the Dockerfiles and compose file only. |

## Database access

- Tracker uses the Flask-SQLAlchemy ORM only (`Model.query.filter_by(...)`, `db.session.add/commit`, `Query.get`).
- `git grep` over `p2p/*.py` for `execute(`, `text(`, `cursor`, and `SELECT/INSERT/UPDATE/DELETE … FROM/INTO/SET/WHERE` found **no raw SQL** and no string-built queries (the only hit was `app.app_context()` matching `text(`).
- `database.py` runs `db.create_all()`; there are no migrations.

## Config that holds or could hold secrets

| Location | What |
|---|---|
| `p2p/Tracker_server/app.py:12` | DB URI with credentials hardcoded: `mysql+pymysql://user:password@db:3306/p2p_db`. The `DATABASE_URL` env var set in compose is **never read**. |
| `p2p/docker-compose.yml:5,8,21` | `MYSQL_ROOT_PASSWORD: rootpassword`, `MYSQL_PASSWORD: password`, same DB URI. |
| `p2p/peer_client/client.py:27`, `p2p/peer_client/blockchain_logger/blockchain_logger.py:38` | Hardcoded contract address `0xCfEB869F69431e42cdB54A4F4f105C19C080A601` (public address, not a secret). |
| `p2p/build/contracts/*.json` | Committed Truffle build output: ABI, bytecode, deployed addresses and tx hashes from earlier local Ganache runs. `grep` for `mnemonic`, `private_key`, `secret` found nothing; all 26 64-hex-digit values are `transactionHash` fields, not keys. |
| `p2p/truffle-config.js` | Local `127.0.0.1:8545` network only; no mnemonic, no provider keys. |
| Ganache | `--deterministic` mode: the well-known public test mnemonic, so accounts are funded and unlocked. Local development only. |

These values are weak, development-style defaults. Whether they count as "real secrets" in the sense of hard rule 6 is decided after the Gitleaks baseline.

## Other committed artifacts

- `__pycache__/*.cpython-313.pyc` in three directories (built with Python 3.13 locally; the images run 3.9, so they are dead weight and are copied into the peer image by `COPY . .`).
- `p2p/files1/test.txt`, `p2p/files2/test.txt` (sample payloads, `hello app`).
- No `.gitignore` existed before this branch.

## Baseline runtime check (unmodified code, 2026-11-06)

Run with `docker compose -p p2p-baseline` from `p2p/` on Docker Engine 29.9.2 / Compose 5.6.1.

| Step | Result |
|---|---|
| `docker compose build` | **Pass**, all three images. The peer image builds despite `COPY ../blockchain_logger`: BuildKit resolves the source relative to the context root, so it copies `peer_client/blockchain_logger`, which `COPY . .` had already copied. The legacy (non-BuildKit) builder would reject the path. |
| First `docker compose up` | **Tracker exits (1)**: `OperationalError (2003) Can't connect to MySQL server on 'db' (Connection refused)`. On a fresh volume MySQL took ~25 s to accept connections; the tracker waits a fixed `sleep 10` and `depends_on` has no healthcheck. Startup race, not a code error (reliability bug R1 in `docs/KNOWN_ISSUES.md`). |
| `docker compose start tracker` (DB already up) | **Pass**: `GET /health` → `{"status":"healthy"}`. |
| peer1 upload `/app/files/test.txt` | **Pass**: registered as peer 1, file hash `a6ed0c78…3204a`. |
| peer2 download by hash | **Pass**: `/app/downloads/test.txt` contents match the source (`hello app`). |
| Blockchain logging | **Misleading success** (reliability bug R2 in `docs/KNOWN_ISSUES.md`). The client prints "logged on blockchain", but `eth_getCode` at the hardcoded address returns `0x`: no contract is deployed (migrations were not run, and `pacakage.json` cannot be installed). The transaction is a plain transfer to an empty address, so nothing is actually logged. |
| `POST /register_file` without `peer_id` | **HTTP 500** (unhandled `KeyError`). The `File` row is committed before the failure. |

## Local tooling

Set up per `requirements-dev.txt`; exact versions are in `security-reports/baseline/TOOL_VERSIONS.txt`.

- `.venv/` (gitignored): Semgrep, pytest, requests, PyYAML, plus tracker runtime deps for the smoke tests.
- `tools/` (gitignored): portable Windows binaries for Trivy, Gitleaks and OSV-Scanner, each SHA-256 verified against the release checksum file kept beside it, plus the Trivy DB cache, OSV offline DB, and Semgrep rule-pack snapshots used by the scans.
- `scripts/run-scans.sh`: runs every local scan against a clean LF worktree of a given commit (see `security-reports/baseline/NOTES.md`).
- Smoke tests: `.venv/Scripts/python -m pytest tests` (6 tests, in-memory SQLite via a test fixture; no app code changed). Baseline result: **6 passed**.

## Unverified leads (not findings)

Carried from an earlier read-only review. Each will be reported only if a scanner or a test confirms it:

- Path traversal in `peer_client/client.py` `handle_client` and `peer_client/server.py` `handle_client`: a socket-supplied name joined onto `/app/files`.
- Arbitrary file write in `client.py` `download_file`: saves to `downloads/{file_name}`, and `file_name` comes from the tracker, where any client can register it.
- Tracker has no authentication and no input validation (the missing-`peer_id` 500 above is confirmed; the rest is not yet).
