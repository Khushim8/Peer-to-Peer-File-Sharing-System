"""Path traversal checks for the peer file server and download path.

These are manual tests, not scanner output: what they found is reported as
"manual/custom rule", separately from the tool baseline. Each attack test asserts
the SAFE behaviour. Until the Phase 4 fix they were xfail(strict=True); they now
pass and guard against regressions.
"""
import os
import socket
import sys
import threading
import time
import types
from pathlib import Path

import pytest

PEER_DIR = Path(__file__).resolve().parents[1] / "p2p" / "peer_client"
SECRET = b"outside FILES_DIR"


@pytest.fixture()
def peer_modules(monkeypatch):
    """Import peer_client/server.py and client.py without web3 or a Ganache node."""
    stub_pkg = types.ModuleType("blockchain_logger")
    stub_mod = types.ModuleType("blockchain_logger.blockchain_logger")
    stub_mod.BlockchainLogger = object
    monkeypatch.setitem(sys.modules, "blockchain_logger", stub_pkg)
    monkeypatch.setitem(sys.modules, "blockchain_logger.blockchain_logger", stub_mod)
    monkeypatch.syspath_prepend(str(PEER_DIR))
    for name in ("server", "client"):
        sys.modules.pop(name, None)
    import client
    import server
    return server, client


@pytest.fixture()
def layout(tmp_path):
    files = tmp_path / "files"
    files.mkdir()
    (files / "shared.txt").write_bytes(b"shared content")
    (tmp_path / "secret.txt").write_bytes(SECRET)
    return tmp_path


def request(handler, name: str) -> bytes:
    """Send `name` to a handle_client-style function over a socket pair; return the full reply."""
    ours, theirs = socket.socketpair()
    ours.sendall(name.encode())
    handler(theirs)
    chunks = []
    while chunk := ours.recv(4096):
        chunks.append(chunk)
    ours.close()
    return b"".join(chunks)


def server_handler(server):
    return lambda sock: server.handle_client(sock, ("test", 0))


def client_handler(client):
    peer = client.PeerClient.__new__(client.PeerClient)   # skip __init__: it needs the contract ABI and Ganache
    peer.files = {}
    return peer.handle_client


TRAVERSALS = {
    "relative": lambda root: "../secret.txt",
    "absolute": lambda root: str(root / "secret.txt"),
}


# ---------------------------------------------------------------- controls (must pass now)

def test_server_serves_file_inside_files_dir(peer_modules, layout, monkeypatch):
    server, _ = peer_modules
    monkeypatch.setattr(server, "FILES_DIR", str(layout / "files"))
    assert request(server_handler(server), "shared.txt") == b"FILE_FOUNDshared content"


def test_client_serves_file_inside_files_dir(peer_modules, layout, monkeypatch):
    _, client = peer_modules
    monkeypatch.setattr(client, "FILES_DIR", str(layout / "files"))
    assert request(client_handler(client), "shared.txt") == b"FILE_FOUND14\nshared content"


# ---------------------------------------------------------------- attacks (must be refused)

@pytest.mark.parametrize("kind", TRAVERSALS)
def test_server_refuses_path_outside_files_dir(peer_modules, layout, monkeypatch, kind):
    server, _ = peer_modules
    monkeypatch.setattr(server, "FILES_DIR", str(layout / "files"))
    reply = request(server_handler(server), TRAVERSALS[kind](layout))
    assert SECRET not in reply
    assert reply == b"FILE_NOT_FOUND"


@pytest.mark.parametrize("kind", TRAVERSALS)
def test_client_refuses_path_outside_files_dir(peer_modules, layout, monkeypatch, kind):
    _, client = peer_modules
    monkeypatch.setattr(client, "FILES_DIR", str(layout / "files"))
    reply = request(client_handler(client), TRAVERSALS[kind](layout))
    assert SECRET not in reply
    assert reply == b"FILE_NOT_FOUND"


PAYLOAD = b"peer-chosen content"


def download(client, monkeypatch, workdir: Path, file_name: str) -> None:
    """Run PeerClient.download_file with the tracker returning `file_name` and a peer serving PAYLOAD."""
    monkeypatch.chdir(workdir)
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]

    def peer_server():
        conn, _ = listener.accept()
        conn.recv(1024)
        # The client reads header, size and body with separate recv() calls, so
        # space the sends out or TCP may coalesce them.
        for part in (b"FILE_FOUND", f"{len(PAYLOAD)}\n".encode(), PAYLOAD):
            conn.sendall(part)
            time.sleep(0.2)
        conn.close()
    t = threading.Thread(target=peer_server, daemon=True)
    t.start()

    class TrackerResponse:
        def json(self):
            return {"status": "success", "file_name": file_name, "peers": [{"ip": "127.0.0.1", "port": port}]}
    monkeypatch.setattr(client.requests, "get", lambda *a, **kw: TrackerResponse())

    peer = client.PeerClient.__new__(client.PeerClient)
    peer.logger = types.SimpleNamespace(log_file_share=lambda h: False)
    peer.download_file("0" * 64)
    t.join(5)
    listener.close()


def test_download_harness_writes_into_downloads(peer_modules, tmp_path, monkeypatch):
    _, client = peer_modules
    download(client, monkeypatch, tmp_path, "ok.txt")
    assert (tmp_path / "downloads" / "ok.txt").read_bytes() == PAYLOAD


def test_download_stays_inside_downloads_dir(peer_modules, tmp_path, monkeypatch):
    """The file name comes from the tracker, which any client can set via /register_file."""
    _, client = peer_modules
    workdir = tmp_path / "work"
    workdir.mkdir()
    download(client, monkeypatch, workdir, "../escaped.txt")
    assert not (tmp_path / "work" / "escaped.txt").exists(), "download wrote outside ./downloads"
    written = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert all(p.resolve().is_relative_to((workdir / "downloads").resolve()) for p in written)


# ---------------------------------------------------------------- resolve_inside

@pytest.fixture()
def safe_paths(monkeypatch):
    monkeypatch.syspath_prepend(str(PEER_DIR))
    sys.modules.pop("safe_paths", None)
    import safe_paths
    return safe_paths


@pytest.mark.parametrize("name", ["", ".", "..", "../x", "a/b", "a\\b", "/etc/passwd", "C:\\x", "x\x00y", None])
def test_resolve_inside_rejects_non_bare_names(safe_paths, layout, name):
    assert safe_paths.resolve_inside(str(layout / "files"), name) is None


def test_resolve_inside_accepts_bare_name(safe_paths, layout):
    assert safe_paths.resolve_inside(str(layout / "files"), "shared.txt") == os.path.realpath(layout / "files" / "shared.txt")


def test_resolve_inside_rejects_symlink_escape(safe_paths, layout):
    link = layout / "files" / "link.txt"
    try:
        os.symlink(layout / "secret.txt", link)
    except (OSError, NotImplementedError):
        pytest.skip("cannot create symlinks here (Windows without privilege)")
    assert safe_paths.resolve_inside(str(layout / "files"), "link.txt") is None
