# Custom rule results on the baseline (`4ec80e1`)

**Label: custom rule written after manual discovery.** These results are not part of the original tool baseline. The path traversal was found by manual tests (`tests/test_peer_path_traversal.py`), and no baseline scanner flagged it. CodeQL, for example, does not model `socket.recv()` as a source. The rule `.semgrep/p2p-socket-path-traversal.yaml` was written afterwards, so that the class is caught automatically from now on. `scripts/triage.py` reads only the top level of `security-reports/baseline/`, so these results do not change the baseline counts.

- Rule `p2p-socket-input-to-file-path` (Semgrep taint): source `<socket>.recv(...)`; sinks `os.path.join(...)` and `open(...)`; sanitizer `resolve_inside(...)`; `taint_assume_safe_indexes: true`, so looking up a registered path by a socket-supplied key is not flagged. Rule tests: `.semgrep/p2p-socket-path-traversal.py` (`semgrep --test .semgrep/`).
- Produced by `scripts/run-scans.sh custom-rules ../baseline-4ec80e1 <out>` (Semgrep 1.184.0, scope `p2p/`).

| Commit | Results |
|---|---|
| `4ec80e1` (baseline) | **4**: `p2p/peer_client/server.py:13` and `client.py:66`, `os.path.join(FILES_DIR, file_hash)`; `server.py:20` and `client.py:75`, `open(file_path, "rb")` |
| `217b986` (after the class 1 fix) | **0** |

Not covered: the arbitrary write in `download_file`. Its file name comes from the tracker's HTTP response (`requests`), not from a socket, so it is outside this rule's source. It is covered by `test_download_stays_inside_downloads_dir`.
