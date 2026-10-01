"""A restored database that drops a high-water fact stays in maintenance."""

import shutil
from pathlib import Path

import httpx

from open_did_server.errors import ApiError
from open_did_server.identity import sign_headers
from open_did_server.service import Service
from open_did_server.signatures import PROFILE_WHOAMI
from open_did_server.store import Store
from tests.harness import _Server, started
from tests.test_http_api import _grant, _publish, _web


def test_restored_database_cannot_clear_maintenance_by_waiting():
    fixture = started()
    server = fixture.__enter__()
    try:
        grant_id, token = _grant(server, web=["identities/web/bob"])
        web, key = _web()
        published, _raw = _publish(server, web, key, token)
        assert published.status_code == 201, published.text
        content_path = published.json()["content_path"]
        server.service.store.checkpoint()
        snapshot = server.tmp / "snapshot.db"
        shutil.copy(server.settings.database_path, snapshot)
        server.service.revoke_grant(grant_id)
    finally:
        fixture.__exit__(None, None, None)

    database = Path(server.settings.database_path)
    shutil.copy(snapshot, database)
    for suffix in ("-wal", "-shm"):
        leftover = Path(str(database) + suffix)
        if leftover.exists():
            leftover.unlink()
    restored = Service(server.settings, Store(server.settings.database_path))
    reason = restored.startup()
    assert reason is not None
    assert "behind" in reason
    http = _Server(server.settings)
    http.start()
    try:
        with httpx.Client(trust_env=False, timeout=10) as client:
            health = client.get(server.base + "/healthz")
            assert health.status_code == 200
            assert health.json()["maintenance"] is True
            document = client.get(server.base + content_path)
            assert document.status_code == 200
            assert document.json()["id"] == web["id"]
            whoami_url = server.base + "/examples/auth/whoami"
            blocked = client.get(
                whoami_url,
                headers=sign_headers(web, key, "GET", whoami_url, PROFILE_WHOAMI),
            )
            assert blocked.status_code == 503
            assert blocked.json()["error"] == "maintenance"
        try:
            restored.clear_maintenance()
        except ApiError as exc:
            assert exc.status == 409
            assert "High-water" in exc.message
        else:
            raise AssertionError("maintenance cleared without the revoked grant")
    finally:
        http.stop()
