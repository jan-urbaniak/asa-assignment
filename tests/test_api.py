import os
import sys
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("NOTIFY_SERVICE_KEY", "test-notify-service-key")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from database import Base, get_db  # noqa: E402
import main  # noqa: E402
from main import app  # noqa: E402
import models  # noqa: E402

TEST_DB_URL = "sqlite:///./test_vulntracker.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def register_and_login(username="alice", email="alice@example.com", password="password123"):
    client.post("/auth/register", json={"username": username, "email": email, "password": password})
    resp = client.post("/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def create_scan_for_user(token, title="Shared finding"):
    response = client.post("/scans", json={
        "title": title,
        "severity": "high",
        "affected_component": "shared component",
    }, headers=auth_headers(token))
    return response.json()["id"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_register_user():
    resp = client.post("/auth/register", json={
        "username": "bob",
        "email": "bob@example.com",
        "password": "secret",
    })
    assert resp.status_code == 201
    assert resp.json()["username"] == "bob"


def test_register_duplicate_username():
    payload = {"username": "bob", "email": "bob@example.com", "password": "secret"}
    client.post("/auth/register", json=payload)
    resp = client.post("/auth/register", json={**payload, "email": "bob2@example.com"})
    assert resp.status_code == 400


def test_login_success():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "pw"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401


def test_create_scan():
    token = register_and_login()
    resp = client.post("/scans", json={
        "title": "Reflected XSS in search",
        "description": "User input is echoed without sanitisation",
        "severity": "high",
        "affected_component": "GET /search",
    }, headers=auth_headers(token))
    assert resp.status_code == 201
    assert resp.json()["title"] == "Reflected XSS in search"


def test_scan_notification_uses_service_key(monkeypatch):
    requests = []

    def capture_notification(*args, **kwargs):
        requests.append((args, kwargs))

    monkeypatch.setattr(main.httpx, "post", capture_notification)
    token = register_and_login()
    create_scan_for_user(token)

    assert requests[0][1]["headers"] == {"X-Service-Key": "test-notify-service-key"}


def test_create_and_retrieve_unprotected_share_link():
    token = register_and_login()
    scan_id = create_scan_for_user(token)

    response = client.post(
        f"/scans/{scan_id}/share",
        json={},
        headers={**auth_headers(token), "Host": "reports.example.test"},
    )

    assert response.status_code == 201
    share_url = response.json()["share_url"]
    assert share_url.startswith("http://reports.example.test/share/")
    shared_scan = client.get(share_url).json()
    assert shared_scan["id"] == scan_id
    assert "owner_id" not in shared_scan


def test_password_protected_share_link_requires_correct_password():
    token = register_and_login()
    scan_id = create_scan_for_user(token)
    response = client.post(
        f"/scans/{scan_id}/share",
        json={"password": "stakeholder-password"},
        headers=auth_headers(token),
    )
    share_url = response.json()["share_url"]
    share_token = share_url.rsplit("/", 1)[1]

    db = TestingSessionLocal()
    try:
        share_link = db.query(models.SharedScanLink).filter_by(token=share_token).one()
        assert share_link.password_hash != "stakeholder-password"
    finally:
        db.close()

    assert client.get(share_url).status_code == 401
    assert client.get(f"{share_url}?password=wrong-password").status_code == 401
    assert client.get(f"{share_url}?password=stakeholder-password").status_code == 200


def test_expired_and_nonexistent_share_links_are_not_available():
    token = register_and_login()
    scan_id = create_scan_for_user(token)
    response = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    share_token = response.json()["share_url"].rsplit("/", 1)[1]

    db = TestingSessionLocal()
    try:
        share_link = db.query(models.SharedScanLink).filter_by(token=share_token).one()
        share_link.expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.commit()
    finally:
        db.close()

    assert client.get(f"/share/{share_token}").status_code == 404
    assert client.get("/share/does-not-exist").status_code == 404


def test_only_scan_owner_can_create_share_link():
    owner_token = register_and_login()
    scan_id = create_scan_for_user(owner_token)
    other_token = register_and_login("bob", "bob@example.com", "password456")

    response = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(other_token))

    assert response.status_code == 404


def test_list_scans():
    token = register_and_login()
    client.post("/scans", json={
        "title": "Test finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token))
    resp = client.get("/scans", headers=auth_headers(token))
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_search_scans():
    # TODO: add assertions for search results
    token = register_and_login()
    client.post("/scans", json={
        "title": "SQL Injection via login",
        "severity": "critical",
        "affected_component": "POST /auth/login",
    }, headers=auth_headers(token))
    resp = client.get("/scans/search?q=SQL", headers=auth_headers(token))
    assert resp.status_code == 200


def test_update_scan_status():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Open redirect",
        "severity": "medium",
        "affected_component": "redirect handler",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.patch(f"/scans/{scan_id}", json={"status": "in_progress"}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"


def test_delete_scan():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Stale finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.delete(f"/scans/{scan_id}", headers=auth_headers(token))
    assert resp.status_code == 204
