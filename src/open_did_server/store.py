"""SQLite storage for documents, grants, handles, and replay nonces."""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager

from open_did_server.highwater import Facts

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS publication_grants (
    grant_id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    token_sha256 TEXT NOT NULL UNIQUE,
    wba_paths TEXT NOT NULL,
    web_paths TEXT NOT NULL,
    handles TEXT NOT NULL,
    expires_at INTEGER,
    revoked INTEGER NOT NULL DEFAULT 0,
    record_version INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS did_documents (
    document_id TEXT PRIMARY KEY,
    did TEXT NOT NULL UNIQUE,
    method TEXT NOT NULL,
    canonical_url TEXT NOT NULL UNIQUE,
    path_key TEXT NOT NULL UNIQUE,
    stable_path_key TEXT,
    owner_id TEXT NOT NULL,
    original_json BLOB NOT NULL,
    content_etag TEXT NOT NULL,
    local_auth_status TEXT NOT NULL,
    record_version INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS stable_subject_paths (
    stable_path_key TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    did TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS handle_bindings (
    local_part TEXT PRIMARY KEY,
    handle TEXT NOT NULL UNIQUE,
    provider_domain TEXT NOT NULL,
    did TEXT NOT NULL UNIQUE,
    owner_id TEXT NOT NULL,
    status TEXT NOT NULL,
    binding_generation TEXT NOT NULL,
    exact INTEGER NOT NULL,
    validated_document_version INTEGER NOT NULL,
    record_version INTEGER NOT NULL,
    suspend_reason TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS handle_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    local_part TEXT NOT NULL,
    handle TEXT NOT NULL,
    did TEXT NOT NULL,
    old_status TEXT,
    new_status TEXT NOT NULL,
    binding_generation TEXT NOT NULL,
    reason TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS used_nonces (
    keyid TEXT NOT NULL,
    nonce TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (keyid, nonce)
);
"""


class Store:
    def __init__(self, path: str) -> None:
        self.path = path

    def connect(self) -> sqlite3.Connection:
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def init(self) -> None:
        connection = self.connect()
        try:
            connection.executescript(SCHEMA)
        finally:
            connection.close()

    @contextmanager
    def immediate(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def checkpoint(self) -> None:
        connection = self.connect()
        try:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            connection.close()

    def meta_get(self, connection: sqlite3.Connection, key: str) -> str | None:
        row = connection.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return None if row is None else str(row["value"])

    def meta_set(self, connection: sqlite3.Connection, key: str, value: str) -> None:
        connection.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def maintenance(self, connection: sqlite3.Connection) -> bool:
        return self.meta_get(connection, "maintenance") == "1"

    def facts(self, connection: sqlite3.Connection) -> Facts:
        generations: dict[str, str] = {}
        tombstones: list[str] = []
        for row in connection.execute("SELECT handle, binding_generation, status FROM handle_bindings"):
            generations[str(row["handle"])] = str(row["binding_generation"])
            if row["status"] == "revoked":
                tombstones.append(str(row["handle"]))
        revoked = [
            str(row["grant_id"])
            for row in connection.execute("SELECT grant_id FROM publication_grants WHERE revoked = 1")
        ]
        stable = {
            str(row["stable_path_key"]): str(row["owner_id"])
            for row in connection.execute("SELECT stable_path_key, owner_id FROM stable_subject_paths")
        }
        return Facts(
            generations=generations,
            tombstones=tuple(sorted(tombstones)),
            revoked_grants=tuple(sorted(revoked)),
            stable_paths=stable,
        )


def json_list(value: str) -> tuple[str, ...]:
    parsed = json.loads(value)
    if not isinstance(parsed, list) or any(not isinstance(item, str) for item in parsed):
        raise ValueError("stored JSON list is malformed")
    return tuple(parsed)
