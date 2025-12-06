# tests/test_api.py
import pytest
import time
from fastapi.testclient import TestClient
from secure_messaging.server import app, state
from secure_messaging.storage import JSONStore, UserStorage, MessageStorage

# --------------------------
# Temporary database for tests
# --------------------------
@pytest.fixture(scope="function", autouse=True)
def use_temp_database(tmp_path):
    """
    Use temporary JSON files for UserStorage and MessageStorage.
    Ensures tests do not affect real data.
    """
    users_file = tmp_path / "users.json"
    messages_file = tmp_path / "messages.json"

    # Create temporary storages (files are created automatically if they don't exist)
    tmp_users_storage = UserStorage(path=users_file)
    tmp_messages_storage = MessageStorage(path=messages_file)

    # Patch state.db to use temporary storages
    state.db.users = tmp_users_storage.store
    state.db.messages = tmp_messages_storage.store

    # Recreate services to use patched database
    state.auth = state.auth.__class__(database=state.db)
    state.messaging = state.messaging.__class__(database=state.db)
    state.sessions = state.sessions.__class__()

    yield  # tests run here

# --------------------------
# FastAPI test client
# --------------------------
@pytest.fixture
def client():
    return TestClient(app)

# --------------------------
# Fixture to register and log in a test user
# --------------------------
@pytest.fixture
def register_and_login_user(client):
    username = f"testuser_{int(time.time() * 1000)}"
    password = "StrongP@ssword1"

    # Register user
    resp = client.post("/api/register", json={
        "username": username,
        "password": password,
        "email": f"{username}@example.com"
    })
    assert resp.status_code == 200

    # Log in
    resp = client.post("/api/login", json={
        "username": username,
        "password": password
    })
    assert resp.status_code == 200
    token = resp.json()["token"]

    return token, username

# --------------------------
# Example tests
# --------------------------
def test_register_new_user(client):
    username = f"newuser_{int(time.time() * 1000)}"
    password = "StrongP@ssword1"
    resp = client.post("/api/register", json={
        "username": username,
        "password": password,
        "email": f"{username}@example.com"
    })
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"

def test_list_users(client, register_and_login_user):
    token, _ = register_and_login_user
    resp = client.get("/api/users", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    users = resp.json()
    assert isinstance(users, list)
    assert len(users) > 0
