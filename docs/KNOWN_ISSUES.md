# Known reliability issues

Functional bugs found while running the unmodified app (commit `4ec80e1`, 2026-11-06). They are **not security findings** and are not counted in the scan report. Each will be fixed in its own commit, separate from the security fixes.

## R1. Tracker loses the startup race with MySQL

- **Symptom:** On a fresh `docker compose up`, the tracker exits with code 1: `OperationalError (2003) Can't connect to MySQL server on 'db' ([Errno 111] Connection refused)`.
- **Cause:** The tracker's compose `command` is `sleep 10 && python database.py && python app.py`, and `depends_on: db` waits only for the container to start, not for MySQL to accept connections. On a new volume MySQL took about 25 s to initialize.
- **Workaround:** `docker compose start tracker` once the DB is up.
- **Planned fix:** a MySQL `healthcheck` in compose with `depends_on: db: condition: service_healthy`, replacing the fixed sleep.

## R2. Peer client reports "logged on blockchain" when nothing is logged

- **Symptom:** Uploads and downloads print `Transaction logged. Hash: …` and `📦 Upload/Download logged on blockchain.`, but `eth_getCode` at the hardcoded address `0xCfEB869F69431e42cdB54A4F4f105C19C080A601` returns `0x`. No contract is deployed there, so `logFileShare` is never executed.
- **Cause:** The contract address is hardcoded instead of read from the Truffle deployment, and `log_file_share` treats any mined transaction as success. A call to an address with no code succeeds as a plain transfer. Contract migrations cannot run as shipped either, because `p2p/pacakage.json` is misnamed and is not valid JSON.
- **Planned fix:** read the address from the deployment (`build/contracts/FileShareLogger.json` `networks`) or from an environment variable; check at startup that code exists at that address; report a failure if the receipt has no `FileShared` event.
