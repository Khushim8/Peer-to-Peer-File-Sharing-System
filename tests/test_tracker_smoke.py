"""Smoke tests for the tracker API's happy paths and basic input handling."""
import hashlib


def test_health(tracker):
    resp = tracker.get("/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "healthy"}


def test_register_peer(tracker):
    resp = tracker.post("/register_peer", json={"ip": "10.0.0.5", "port": 6000})
    assert resp.status_code == 200
    assert isinstance(resp.get_json()["peer_id"], int)


def test_register_peer_missing_fields(tracker):
    resp = tracker.post("/register_peer", json={"ip": "10.0.0.5"})
    assert resp.status_code == 400
    assert resp.get_json()["status"] == "error"


def test_register_file_then_search(tracker):
    peer_id = tracker.post("/register_peer", json={"ip": "10.0.0.5", "port": 6000}).get_json()["peer_id"]

    resp = tracker.post("/register_file", json={"file_name": "test.txt", "peer_id": peer_id})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "success"
    assert body["file_hash"] == hashlib.sha256(b"test.txt").hexdigest()

    resp = tracker.get("/search", query_string={"file_hash": body["file_hash"]})
    assert resp.status_code == 200
    found = resp.get_json()
    assert found["status"] == "success"
    assert found["file_name"] == "test.txt"
    assert found["peers"] == [{"ip": "10.0.0.5", "port": 6000}]


def test_same_file_from_two_peers(tracker):
    p1 = tracker.post("/register_peer", json={"ip": "10.0.0.5", "port": 6000}).get_json()["peer_id"]
    p2 = tracker.post("/register_peer", json={"ip": "10.0.0.6", "port": 6000}).get_json()["peer_id"]
    tracker.post("/register_file", json={"file_name": "shared.bin", "peer_id": p1})
    file_hash = tracker.post("/register_file", json={"file_name": "shared.bin", "peer_id": p2}).get_json()["file_hash"]

    peers = tracker.get("/search", query_string={"file_hash": file_hash}).get_json()["peers"]
    assert {p["ip"] for p in peers} == {"10.0.0.5", "10.0.0.6"}


def test_search_unknown_hash(tracker):
    resp = tracker.get("/search", query_string={"file_hash": "0" * 64})
    assert resp.get_json()["status"] == "error"
