"""A restored database that drops a high-water fact stays in maintenance."""

import re
import shutil
import sqlite3
import time
from pathlib import Path

import httpx

from open_did_server.errors import ApiError
from open_did_server.highwater import read_facts
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
        with sqlite3.connect(database) as connection:
            resume = int(
                connection.execute(
                    "SELECT value FROM meta WHERE key = 'auth_resume_after'"
                ).fetchone()[0]
            )
        restored.clock = lambda: resume + 1
        try:
            restored.clear_maintenance()
        except ApiError as exc:
            assert exc.status == 409
            assert "High-water" in exc.message
        else:
            raise AssertionError("waiting restored a missing revoked grant")
    finally:
        http.stop()


def test_restoring_consumed_nonces_blocks_replay_until_the_window_ends():
    clock = {"now": int(time.time())}

    def now() -> int:
        return clock["now"]

    fixture = started(clock=now)
    server = fixture.__enter__()
    try:
        _grant_id, token = _grant(server, web=["identities/web/bob"])
        web, key = _web()
        clock["now"] = int(time.time())
        published, _raw = _publish(server, web, key, token)
        assert published.status_code == 201, published.text
        server.service.store.checkpoint()
        snapshot = server.tmp / "snapshot.db"
        shutil.copy(server.settings.database_path, snapshot)
        whoami_url = server.base + "/examples/auth/whoami"
        clock["now"] = int(time.time())
        headers = sign_headers(web, key, "GET", whoami_url, PROFILE_WHOAMI)
        accepted = server.client.get(whoami_url, headers=headers)
        assert accepted.status_code == 200, accepted.text
        watermark = read_facts(server.settings.high_water_path)
        assert watermark is not None
        assert watermark.nonce_watermark >= 2
    finally:
        fixture.__exit__(None, None, None)

    database = Path(server.settings.database_path)
    shutil.copy(snapshot, database)
    for suffix in ("-wal", "-shm"):
        leftover = Path(str(database) + suffix)
        if leftover.exists():
            leftover.unlink()
    with sqlite3.connect(database) as connection:
        stored = connection.execute(
            "SELECT value FROM meta WHERE key = 'nonce_watermark'"
        ).fetchone()
    assert stored is not None
    assert int(stored[0]) < watermark.nonce_watermark

    clock["now"] = int(time.time())
    restored = Service(server.settings, Store(server.settings.database_path), clock=now)
    reason = restored.startup()
    assert reason is not None
    assert "replay" in reason
    http = _Server(server.settings, clock=now)
    http.start()
    try:
        with httpx.Client(trust_env=False, timeout=10) as client:
            replay = client.get(whoami_url, headers=headers)
            assert replay.status_code == 503, replay.text
            assert replay.json()["error"] == "maintenance"
        with sqlite3.connect(database) as connection:
            resume = int(
                connection.execute(
                    "SELECT value FROM meta WHERE key = 'auth_resume_after'"
                ).fetchone()[0]
            )
        clock["now"] = resume - 1
        try:
            restored.clear_maintenance()
        except ApiError as exc:
            assert "signature window" in exc.message
        else:
            raise AssertionError("replay gap cleared before the signature window")
        clock["now"] = resume
        restored.clear_maintenance()
        with httpx.Client(trust_env=False, timeout=10) as client:
            after = client.get(whoami_url, headers=headers)
        assert after.status_code == 401, after.text
        assert after.json()["error"] == "invalid_timestamp"
    finally:
        http.stop()


def _meta(database: Path, key: str) -> str:
    with sqlite3.connect(database) as connection:
        row = connection.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    assert row is not None
    return str(row[0])


def test_structural_and_nonce_gap_keeps_the_replay_horizon():
    """Restoring a missing grant and consumed nonces must not revive an in-window signature."""
    clock = {"now": int(time.time())}

    def now() -> int:
        return clock["now"]

    fixture = started(clock=now)
    server = fixture.__enter__()
    try:
        grant_id, token = _grant(server, web=["identities/web/bob"])
        web, key = _web()
        clock["now"] = int(time.time())
        published, _raw = _publish(server, web, key, token)
        assert published.status_code == 201, published.text
        server.service.store.checkpoint()
        snapshot = server.tmp / "snapshot.db"
        shutil.copy(server.settings.database_path, snapshot)
        whoami_url = server.base + "/examples/auth/whoami"
        clock["now"] = int(time.time())
        headers = sign_headers(web, key, "GET", whoami_url, PROFILE_WHOAMI)
        accepted = server.client.get(whoami_url, headers=headers)
        assert accepted.status_code == 200, accepted.text
        server.service.revoke_grant(grant_id)
        watermark = read_facts(server.settings.high_water_path)
        assert watermark is not None
        assert grant_id in watermark.revoked_grants
        assert watermark.nonce_watermark >= 2
    finally:
        fixture.__exit__(None, None, None)

    database = Path(server.settings.database_path)
    shutil.copy(snapshot, database)
    for suffix in ("-wal", "-shm"):
        leftover = Path(str(database) + suffix)
        if leftover.exists():
            leftover.unlink()

    signed = {name.lower(): value for name, value in headers.items()}
    expires = int(re.search(r"expires=(\d+)", signed["signature-input"]).group(1))
    last_valid = expires + server.settings.clock_skew
    # Keep the frozen sign-time clock so maintenance starts while this signature is still acceptable.
    restored = Service(server.settings, Store(server.settings.database_path), clock=now)
    reason = restored.startup()
    assert reason is not None
    assert "behind" in reason
    http = _Server(server.settings, clock=now)
    http.start()
    try:
        started_at = int(_meta(database, "maintenance_started_at"))
        structural_deadline = started_at + server.settings.signature_lifetime + server.settings.clock_skew
        replay_deadline = started_at + server.settings.signature_lifetime + (2 * server.settings.clock_skew) + 1
        assert int(_meta(database, "auth_resume_after")) >= replay_deadline
        assert structural_deadline <= last_valid

        with httpx.Client(trust_env=False, timeout=10) as client:
            blocked = client.get(whoami_url, headers=headers)
            assert blocked.status_code == 503, blocked.text

        restored.revoke_grant(grant_id)
        assert read_facts(server.settings.high_water_path).nonce_watermark == watermark.nonce_watermark

        clock["now"] = structural_deadline
        try:
            restored.clear_maintenance()
        except ApiError as exc:
            assert exc.status == 409
            assert "signature window" in exc.message
        else:
            raise AssertionError("combined restore cleared on the structural window")
        assert read_facts(server.settings.high_water_path).nonce_watermark == watermark.nonce_watermark
        with httpx.Client(trust_env=False, timeout=10) as client:
            still_blocked = client.get(whoami_url, headers=headers)
        assert still_blocked.status_code == 503, still_blocked.text
        assert still_blocked.json()["error"] == "maintenance"

        clock["now"] = max(replay_deadline, last_valid + 1)
        restored.clear_maintenance()
        with httpx.Client(trust_env=False, timeout=10) as client:
            after = client.get(whoami_url, headers=headers)
        assert after.status_code == 401, after.text
        assert after.json()["error"] == "invalid_timestamp"
    finally:
        http.stop()
