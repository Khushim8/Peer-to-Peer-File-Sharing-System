# Test cases for p2p-socket-path-traversal.yaml (run: semgrep --test .semgrep/)
import os

from safe_paths import resolve_inside

FILES_DIR = "/app/files"


def vulnerable_join(conn):
    name = conn.recv(1024).decode().strip()
    # ruleid: p2p-socket-input-to-file-path
    path = os.path.join(FILES_DIR, name)
    # ruleid: p2p-socket-input-to-file-path
    with open(path, "rb") as f:
        return f.read()


def vulnerable_open(conn):
    # ruleid: p2p-socket-input-to-file-path
    return open(conn.recv(1024).decode(), "rb")


def fixed(conn):
    name = conn.recv(1024).decode().strip()
    path = resolve_inside(FILES_DIR, name)
    if path is None:
        return None
    # ok: p2p-socket-input-to-file-path
    with open(path, "rb") as f:
        return f.read()


def registered_lookup(conn, files):
    name = conn.recv(1024).decode().strip()
    # ok: p2p-socket-input-to-file-path
    with open(files[name], "rb") as f:
        return f.read()


def not_from_socket():
    # ok: p2p-socket-input-to-file-path
    return open(os.path.join(FILES_DIR, "fixed-name.txt"), "rb")
