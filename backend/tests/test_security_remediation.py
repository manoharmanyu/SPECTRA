import pytest
from fastapi.testclient import TestClient
from app.models.analysis import AnalysisJob
from app.models.audit import AuditEvent
from app.services.analysis_service import AnalysisService


from app.storage import get_storage


def test_object_level_authorization_idor(client, db_session):
    """
    Verify object-level authorization (IDOR prevention):
    A user cannot view or download analysis jobs belonging to another user.
    """
    # 1. Create a job owned by investigator_alice
    job = AnalysisJob(
        id="job-alice-12345",
        user_id="investigator_alice",
        media_type="image",
        detected_mime_type="image/jpeg",
        original_filename="alice_evidence.jpg",
        storage_key="evidence_alice.jpg",
        size_bytes=1024,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        status="completed",
        final_report={"job_id": "job-alice-12345", "status": "completed"}
    )
    db_session.add(job)
    db_session.commit()

    # 2. Investigator Bob attempts to access Alice's job -> MUST be rejected (403)
    bob_headers = {"X-User-Id": "investigator_bob", "X-User-Role": "investigator"}
    resp = client.get("/api/v1/analyses/job-alice-12345", headers=bob_headers)
    assert resp.status_code == 403, "Investigator Bob should be blocked from viewing Alice's job"

    # 3. Investigator Alice accesses her own job -> MUST succeed (200)
    alice_headers = {"X-User-Id": "investigator_alice", "X-User-Role": "investigator"}
    resp = client.get("/api/v1/analyses/job-alice-12345", headers=alice_headers)
    assert resp.status_code == 200
    assert resp.json()["job_id"] == "job-alice-12345"

    # 4. Admin accesses Alice's job -> MUST succeed (200)
    admin_headers = {"X-User-Id": "admin_user", "X-User-Role": "admin"}
    resp = client.get("/api/v1/analyses/job-alice-12345", headers=admin_headers)
    assert resp.status_code == 200


def test_chain_of_custody_tamper_detection(client, db_session):
    """
    Verify tamper-evident audit logging with cryptographic SHA-256 hash chaining.
    Modifying any audit event breaks the chain and is detected by verify_audit_chain.
    """
    job_id = "job-custody-chain-test"
    job = AnalysisJob(
        id=job_id,
        user_id="forensic_officer",
        media_type="image",
        detected_mime_type="image/jpeg",
        original_filename="tamper_test.jpg",
        storage_key="tamper_test.jpg",
        size_bytes=2048,
        sha256_hash="a" * 64,
        status="queued"
    )
    db_session.add(job)
    db_session.commit()

    # 1. Log sequential chain of events
    AnalysisService.log_audit(db_session, job_id, "evidence_intake", {"step": 1}, actor_id="officer_1")
    AnalysisService.log_audit(db_session, job_id, "stage_completed", {"step": 2, "stage": "metadata"}, actor_id="worker_1")
    AnalysisService.log_audit(db_session, job_id, "report_finalized", {"step": 3, "conclusion": "AUTHENTIC"}, actor_id="system")

    # 2. Verify clean chain passes
    chain_status = AnalysisService.verify_audit_chain(db_session, job_id)
    assert chain_status["intact"] is True
    assert chain_status["entries_verified"] == 3

    # 3. Verify via API endpoint
    auth_headers = {"X-User-Id": "forensic_officer", "X-User-Role": "investigator"}
    api_resp = client.get(f"/api/v1/analyses/{job_id}/custody-chain", headers=auth_headers)
    assert api_resp.status_code == 200
    assert api_resp.json()["intact"] is True

    # 4. TAMPER: Modify the payload of the second audit event directly in the database
    event_2 = db_session.query(AuditEvent).filter(AuditEvent.job_id == job_id, AuditEvent.sequence_number == 2).first()
    assert event_2 is not None
    event_2.details = {"step": 2, "stage": "metadata", "MALICIOUS_TAMPERING": True}
    db_session.commit()

    # 5. Verify that tamper is detected
    tampered_status = AnalysisService.verify_audit_chain(db_session, job_id)
    assert tampered_status["intact"] is False, "Cryptographic chain must detect tampered record"
    assert "tampered_sequence" in tampered_status
    assert tampered_status["tampered_sequence"] == 2


def test_evidence_download_authorization(client, db_session):
    """
    Verify evidence download endpoint enforces authentication and object ownership.
    """
    job_id = "job-evidence-download-test"
    storage = get_storage()
    storage_key = "test_evidence_file_123.jpg"
    target_path = storage._resolve_path(storage_key)
    with open(target_path, "wb") as f:
        f.write(b"JPEG_MOCK_EVIDENCE_BYTES_12345")

    job = AnalysisJob(
        id=job_id,
        user_id="authorized_investigator",
        media_type="image",
        detected_mime_type="image/jpeg",
        original_filename="sample.jpg",
        storage_key=storage_key,
        size_bytes=len(b"JPEG_MOCK_EVIDENCE_BYTES_12345"),
        sha256_hash="b" * 64,
        status="completed"
    )
    db_session.add(job)
    db_session.commit()

    # 1. Unauthorized user attempt
    unauth_headers = {"X-User-Id": "unauthorized_user", "X-User-Role": "investigator"}
    resp = client.get(f"/api/v1/analyses/{job_id}/evidence/download", headers=unauth_headers)
    assert resp.status_code == 403

    # 2. Authorized owner attempt
    auth_headers = {"X-User-Id": "authorized_investigator", "X-User-Role": "investigator"}
    resp = client.get(f"/api/v1/analyses/{job_id}/evidence/download", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.content == b"JPEG_MOCK_EVIDENCE_BYTES_12345"
