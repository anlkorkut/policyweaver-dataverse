import json

from fastapi.testclient import TestClient

from policyweaver.app import create_app
from policyweaver.demo import uid
from policyweaver.storage import load_inventory, save_inventory


def test_local_console_and_simulator(monkeypatch, tmp_path):
    monkeypatch.setenv("POLICYWEAVER_DATA_DIR", str(tmp_path))
    with TestClient(create_app()) as client:
        assert client.get("/api/health").json()["production_enforcement"] is False
        overview = client.get("/api/overview")
        assert overview.json()["inventory"] is None
        assert overview.json()["plan"]["publishable"] is False
        assert overview.headers["Content-Security-Policy"].startswith("default-src 'self'")
        response = client.post("/api/evaluate", json={"user_id": uid("analyst"), "table": "account", "record_id": uid("fund-account")})
        assert response.json()["allowed"]
        assert response.json()["simulation"]
        assert client.post("/api/evaluate", json={"user_id": "x", "table": "account", "record_id": "x", "admin": True}).status_code == 422
        assert client.get("/api/health", headers={"host": "attacker.example"}).status_code == 400


def test_versioned_snapshot_round_trip_and_tamper(tmp_path):
    first = save_inventory({"counts": {"users": 5}, "complete": False}, tmp_path)
    second = save_inventory({"counts": {"users": 6}, "complete": True}, tmp_path)
    assert first != second and first.exists()
    assert load_inventory(tmp_path)["counts"]["users"] == 6
    second.write_text("{}", encoding="utf-8")
    import pytest
    with pytest.raises(ValueError, match="hash"):
        load_inventory(tmp_path)


def test_manifest_cannot_escape_storage_directory(tmp_path):
    import pytest
    (tmp_path / "latest.json").write_text(json.dumps({"file": "../outside.json", "sha256": "x"}))
    with pytest.raises(ValueError, match="escapes"):
        load_inventory(tmp_path)
