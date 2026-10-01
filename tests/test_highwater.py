"""A restored database that drops a high-water fact stays in maintenance."""

import re
import shutil
import sqlite3
import time
from pathlib import Path

import httpx

from open_did_server.errors import ApiError
from open_did_server.highwater import Facts, decide_recovery, read_facts
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
        restored.clock = lambda: int(time.time()) + 10_000
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
        resume = read_facts(server.settings.high_water_path).replay_resume_after
        assert resume >= clock["now"] + server.settings.signature_lifetime + (2 * server.settings.clock_skew) + 1
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


def _set_meta(database: Path, key: str, value: str) -> None:
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


def test_recovery_decision_ignores_database_clocks():
    reference = Facts({}, (), ("grant-old",), {}, nonce_watermark=4, replay_resume_after=1_000)
    current = Facts({}, (), (), {}, nonce_watermark=1)
    waiting = decide_recovery(reference, current, now=1_400, ordinary_span=330, replay_span=361, sidecar_replay_resume_after=1_000)
    assert waiting.structural_ok is False
    assert waiting.clearable is False
    assert waiting.watermark == 4
    assert waiting.resume_after == max(1_000, 1_400 + 361)

    caught_up = Facts({}, (), ("grant-old",), {}, nonce_watermark=1)
    still_early = decide_recovery(
        reference, caught_up, now=1_200, ordinary_span=330, replay_span=361, sidecar_replay_resume_after=2_000
    )
    assert still_early.structural_ok is True
    assert still_early.replay_behind is True
    assert still_early.clearable is False
    assert still_early.watermark == 4
    assert still_early.resume_after == 2_000

    due = decide_recovery(
        reference, caught_up, now=1_000, ordinary_span=330, replay_span=361, sidecar_replay_resume_after=1_000
    )
    assert due.clearable is True
    assert due.watermark == 4
    assert due.resume_after == max(1_000, 1_000 + 361)

    fresh = decide_recovery(reference, caught_up, now=2_000, ordinary_span=330, replay_span=361, sidecar_replay_resume_after=0)
    assert fresh.clearable is False
    assert fresh.resume_after == 2_000 + 361
    assert fresh.watermark == 4


def test_snapshot_from_an_older_maintenance_episode_does_not_release_replay():
    """A backup taken during earlier maintenance must not authorize a later signature."""
    wall = int(time.time())
    clock = {"now": wall}

    def now() -> int:
        return clock["now"]

    fixture = started(clock=now)
    server = fixture.__enter__()
    try:
        _grant_id, token = _grant(server, web=["identities/web/bob"])
        web, key = _web()
        published, _raw = _publish(server, web, key, token)
        assert published.status_code == 201, published.text
        clock["now"] = wall - 400
        server.service.mark_maintenance("older episode")
        server.service.store.checkpoint()
        snapshot = server.tmp / "snapshot.db"
        shutil.copy(server.settings.database_path, snapshot)
        clock["now"] = wall
        server.service.clear_maintenance()
        whoami_url = server.base + "/examples/auth/whoami"
        headers = sign_headers(web, key, "GET", whoami_url, PROFILE_WHOAMI)
        accepted = server.client.get(whoami_url, headers=headers)
        assert accepted.status_code == 200, accepted.text
        server.service.revoke_grant(_grant_id)
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
    episode_start = wall - 400
    _set_meta(database, "maintenance", "1")
    _set_meta(database, "maintenance_started_at", str(episode_start))
    _set_meta(database, "auth_resume_after", str(episode_start + 361))
    _set_meta(database, "replay_gap", "1")

    clock["now"] = wall
    restored = Service(server.settings, Store(server.settings.database_path), clock=now)
    reason = restored.startup()
    assert reason is not None
    http = _Server(server.settings, clock=now)
    http.start()
    try:
        span = server.settings.signature_lifetime + (2 * server.settings.clock_skew) + 1
        first_deadline = read_facts(server.settings.high_water_path).replay_resume_after
        assert first_deadline >= wall + span
        assert read_facts(server.settings.high_water_path).nonce_watermark == watermark.nonce_watermark
        restored.revoke_grant(_grant_id)
        assert read_facts(server.settings.high_water_path).nonce_watermark == watermark.nonce_watermark
        try:
            restored.clear_maintenance()
        except ApiError as exc:
            assert "signature window" in exc.message
        else:
            raise AssertionError("an older maintenance episode cleared the replay gap")
        assert read_facts(server.settings.high_water_path).nonce_watermark == watermark.nonce_watermark
        with httpx.Client(trust_env=False, timeout=10) as client:
            replay = client.get(whoami_url, headers=headers)
        assert replay.status_code == 503, replay.text
        assert replay.json()["error"] == "maintenance"

        clock["now"] = wall + 30
        restored.startup()
        moved = read_facts(server.settings.high_water_path).replay_resume_after
        assert moved >= clock["now"] + span
        assert moved > first_deadline
        with httpx.Client(trust_env=False, timeout=10) as client:
            again = client.get(whoami_url, headers=headers)
        assert again.status_code == 503, again.text
    finally:
        http.stop()


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
        replay_deadline = read_facts(server.settings.high_water_path).replay_resume_after
        ordinary = server.settings.signature_lifetime + server.settings.clock_skew
        replay_span = ordinary + server.settings.clock_skew + 1
        assert replay_deadline >= clock["now"] + replay_span
        structural_deadline = replay_deadline - (replay_span - ordinary)
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
