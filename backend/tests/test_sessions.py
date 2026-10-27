def test_create_device_session(client):
    res = client.post("/api/v1/device-sessions", json={
        "device_name": "Field Officer iPhone",
        "device_fingerprint": "fp_8832a",
        "client_metadata": {"browser": "Safari Mobile", "os": "iOS 18"}
    })
    assert res.status_code == 201
    data = res.json()
    assert "capture_session_id" in data
    assert data["device_name"] == "Field Officer iPhone"
    assert data["is_active"] is True


def test_list_session_analyses_empty(client):
    # Create session
    session_res = client.post("/api/v1/device-sessions", json={"device_name": "Test Device"})
    session_id = session_res.json()["capture_session_id"]

    res = client.get(f"/api/v1/device-sessions/{session_id}/analyses")
    assert res.status_code == 200
    assert isinstance(res.json(), list)
    assert len(res.json()) == 0


def test_session_not_found(client):
    res = client.get("/api/v1/device-sessions/non_existent_uuid/analyses")
    assert res.status_code == 404
