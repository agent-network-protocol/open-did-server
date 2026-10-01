"""Publication, Handle, and example authentication transactions."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from anp.wns.binding import canonicalize_binding_generation
from anp.wns.validator import validate_handle

from open_did_server.canonical import canonical_url_for_http_path, decode_segment, path_key
from open_did_server.config import Settings
from open_did_server.documents import RESERVED_HANDLES, declaration_satisfies, validate_document
from open_did_server.errors import ApiError, auth_error
from open_did_server.highwater import EMPTY, Facts, decide_recovery, read_facts, write_facts
from open_did_server.jsonutil import parse_json_object
from open_did_server.signatures import (
    PROFILE_CREATE,
    PROFILE_ECHO,
    PROFILE_UPDATE,
    PROFILE_WHOAMI,
    REALM,
    ParsedSignature,
    accept_signature,
    header_values,
    parse_limited_signature,
    verify_limited_signature,
)
from open_did_server.store import Store, json_list


@dataclass
class Result:
    status: int
    body: Any
    headers: dict[str, str]
    media_type: str = "application/json"


class _Rollback(Exception):
    def __init__(self, result: Result) -> None:
        super().__init__(result.body["message"] if isinstance(result.body, dict) else "rollback")
        self.result = result


class _Replay(Exception):
    def __init__(self, profile: tuple[str, ...]) -> None:
        super().__init__("replay")
        self.profile = profile


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def content_etag(raw: bytes) -> str:
    return '"' + hashlib.sha256(raw).hexdigest() + '"'


def version_etag(version: int) -> str:
    return f'"v{version}"'


def generation_etag(generation: str) -> str:
    return f'"g{canonicalize_binding_generation(generation)}"'


def next_generation(current: str | None) -> str:
    if current is None:
        value = "1"
    else:
        canonicalize_binding_generation(current)
        value = str(int(current) + 1)
    return canonicalize_binding_generation(value)


def grant_path_key(raw: str, settings: Settings) -> str:
    text = raw.strip()
    if text.count("|") == 2:
        host, port_text, rest = text.split("|")
        port = int(port_text)
        segments = tuple(decode_segment(part) for part in rest.split("/") if part) if rest else ()
        return path_key(host.lower(), None if port == 443 else port, segments)
    stripped = text.strip("/")
    segments = tuple(decode_segment(part) for part in stripped.split("/")) if stripped else ()
    if segments and segments[0] == settings.public_did_domain:
        segments = segments[1:]
    port = None if settings.public_did_port == 443 else settings.public_did_port
    return path_key(settings.public_did_domain, port, segments)


def _mode(settings: Settings) -> str:
    return "local-demo" if settings.local_demo else "production"


def _error(status: int, error: str, message: str, headers: dict[str, str] | None = None) -> Result:
    return Result(status, {"error": error, "message": message}, headers or {})


def _auth_failure(profile: tuple[str, ...], code: str, message: str) -> Result:
    failure = auth_error(code, message, realm=REALM, accept_signature=accept_signature(profile))
    return Result(
        401,
        {"error": failure.error, "message": failure.message},
        {
            "WWW-Authenticate": failure.www_authenticate or "",
            "Cache-Control": "no-store",
            "Accept-Signature": failure.accept_signature or "",
        },
    )


def _authentication_ids(document: dict[str, Any]) -> tuple[str, ...]:
    found: list[str] = []
    for entry in document.get("authentication") or []:
        if isinstance(entry, str):
            found.append(entry)
        elif isinstance(entry, dict) and isinstance(entry.get("id"), str):
            found.append(entry["id"])
    return tuple(found)


def _json_bytes(document: dict[str, Any]) -> bytes:
    return json.dumps(document, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class Service:
    def __init__(
        self,
        settings: Settings,
        store: Store,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.clock = clock or (lambda: int(time.time()))
        self._high_water_lock = threading.Lock()

    def startup(self) -> str | None:
        """Reconcile the sidecar. Return a maintenance reason when service writes must stop."""
        self.store.init()
        current = self._facts()
        try:
            reference = read_facts(self.settings.high_water_path)
        except ValueError as exc:
            self._hold_maintenance(str(exc))
            return str(exc)
        if reference is None:
            if _facts_empty(current):
                write_facts(self.settings.high_water_path, current)
                return self._maintenance_reason()
            reason = "high-water file is missing for a non-empty database"
            self._hold_maintenance(reason)
            return reason
        decision = decide_recovery(
            reference,
            current,
            self.clock(),
            self._ordinary_span(),
            self._replay_span(),
            reference.replay_resume_after,
        )
        if not decision.structural_ok or decision.replay_behind:
            reason = (
                "database is behind the high-water file"
                if not decision.structural_ok
                else "replay watermark is ahead of the database"
            )
            self._hold_maintenance(reason)
            if decision.replay_behind:
                self._persist_replay(reference, decision.watermark, decision.resume_after)
            return reason
        write_facts(
            self.settings.high_water_path,
            _facts_with_replay(current, decision.watermark, 0),
        )
        return self._maintenance_reason()

    def create_grant(
        self,
        owner_id: str,
        *,
        wba_paths: list[str],
        web_paths: list[str],
        handles: list[str],
        expires_at: int | None = None,
    ) -> tuple[str, str]:
        import secrets
        import uuid

        if not owner_id or any(character.isspace() for character in owner_id):
            raise ApiError(422, "invalid_grant", "owner_id is required")
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        grant_id = "grant_" + uuid.uuid4().hex
        normalized_handles = []
        for handle in handles:
            local, domain = validate_handle(handle)
            if domain != self.settings.handle_provider_domain:
                raise ApiError(422, "invalid_handle", "Grant handle domain must be this provider")
            if local in RESERVED_HANDLES:
                raise ApiError(422, "reserved_handle", "Handle local-part is reserved")
            normalized_handles.append(f"{local}.{domain}")
        wba = [grant_path_key(path, self.settings) for path in wba_paths]
        web = [grant_path_key(path, self.settings) for path in web_paths]
        with self.store.immediate() as connection:
            connection.execute(
                """
                INSERT INTO publication_grants(
                    grant_id, owner_id, token_sha256, wba_paths, web_paths, handles,
                    expires_at, revoked, record_version, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, 0, 1, ?)
                """,
                (
                    grant_id,
                    owner_id,
                    digest,
                    json.dumps(wba),
                    json.dumps(web),
                    json.dumps(normalized_handles),
                    expires_at,
                    iso_now(),
                ),
            )
        return grant_id, token

    def revoke_grant(self, grant_id: str) -> None:
        with self.store.immediate() as connection:
            row = connection.execute(
                "SELECT revoked FROM publication_grants WHERE grant_id = ?",
                (grant_id,),
            ).fetchone()
            if row is None:
                raise ApiError(404, "not_found", "Grant was not found")
            if not row["revoked"]:
                connection.execute(
                    "UPDATE publication_grants SET revoked = 1, record_version = record_version + 1 WHERE grant_id = ?",
                    (grant_id,),
                )
        self._sync_high_water()

    def set_auth_status(self, did: str, status: str) -> int:
        if status not in {"active", "suspended"}:
            raise ApiError(422, "invalid_status", "Local auth status must be active or suspended")
        suspended = 0
        with self.store.immediate() as connection:
            row = connection.execute("SELECT * FROM did_documents WHERE did = ?", (did,)).fetchone()
            if row is None:
                raise ApiError(404, "not_found", "DID is not published on this server")
            if row["local_auth_status"] == status:
                return 0
            now = iso_now()
            connection.execute(
                "UPDATE did_documents SET local_auth_status = ?, updated_at = ? WHERE document_id = ?",
                (status, now, row["document_id"]),
            )
            if status == "suspended":
                suspended = self._suspend_handles(connection, did, now, "did_suspended")
        self._sync_high_water()
        return suspended

    def mark_maintenance(self, reason: str) -> None:
        """Refresh the ordinary operator window without moving a sidecar replay deadline."""
        with self.store.immediate() as connection:
            self.store.meta_set(connection, "maintenance", "1")
            self.store.meta_set(connection, "maintenance_reason", reason or "operator maintenance")
            self.store.meta_set(connection, "auth_resume_after", str(self.clock() + self._ordinary_span()))

    def clear_maintenance(self) -> None:
        current = self._facts()
        reference = read_facts(self.settings.high_water_path)
        if reference is None:
            raise ApiError(409, "maintenance", "High-water file is missing")
        decision = decide_recovery(
            reference,
            current,
            self.clock(),
            self._ordinary_span(),
            self._replay_span(),
            reference.replay_resume_after,
        )
        if not decision.structural_ok:
            raise ApiError(
                409,
                "maintenance",
                "High-water facts are not satisfied. Waiting does not restore missing ownership or tombstones.",
            )
        if decision.replay_behind:
            if reference.replay_resume_after <= 0 or self.clock() < reference.replay_resume_after:
                raise ApiError(
                    409,
                    "maintenance",
                    "Authentication must stay in maintenance until the signature window has elapsed",
                )
            with self.store.immediate() as connection:
                self.store.meta_set(connection, "nonce_watermark", str(decision.watermark))
                self.store.meta_set(connection, "maintenance", "0")
                raised = self.store.facts(connection)
            write_facts(self.settings.high_water_path, _facts_with_replay(raised, decision.watermark, 0))
            return
        with self.store.immediate() as connection:
            if not self.store.maintenance(connection):
                return
            resume = int(self.store.meta_get(connection, "auth_resume_after") or "0")
            if self.clock() < resume:
                raise ApiError(
                    409,
                    "maintenance",
                    "Authentication must stay in maintenance until the signature window has elapsed",
                )
            self.store.meta_set(connection, "maintenance", "0")
        write_facts(self.settings.high_water_path, _facts_with_replay(current, decision.watermark, 0))

    def health(self) -> Result:
        connection = self.store.connect()
        try:
            maintenance = self.store.maintenance(connection)
        finally:
            connection.close()
        return Result(
            200,
            {
                "status": "ok",
                "mode": _mode(self.settings),
                "maintenance": maintenance,
                "wba_handles_enabled": self.settings.wba_handles_enabled,
            },
            {},
        )

    def publish_document(self, method: str, target_uri: str, raw_headers: list[tuple[str, str]], body: bytes) -> Result:
        if header_values(raw_headers, "if-match"):
            return _error(400, "invalid_precondition", "First publication does not accept If-Match")
        parsed = self._parse(raw_headers, body, PROFILE_CREATE, require_json=True)
        document = parse_json_object(body, limit=self.settings.max_body_bytes)
        validated = validate_document(document, self.settings)
        if parsed.did != validated.parsed.original:
            raise auth_error(
                "invalid_did",
                "keyid DID does not equal the candidate document id",
                realm=REALM,
                accept_signature=accept_signature(PROFILE_CREATE),
            )
        self._verify(parsed, document, method, target_uri, body, PROFILE_CREATE)
        self._require_json_type(parsed, PROFILE_CREATE)
        self._require_authentication(parsed, document, PROFILE_CREATE)

        def publish(connection: sqlite3.Connection) -> tuple[Result, bool]:
            self._begin(connection, parsed, PROFILE_CREATE)
            grant = self._load_grant(connection, parsed.headers.get("anp-publication-token", ""))
            if not self._grant_usable(grant) or not _grant_covers_document(grant, validated):
                return _error(403, "publication_forbidden", "Publication credential is not authorized for this DID"), False
            existing_did = connection.execute(
                "SELECT document_id FROM did_documents WHERE did = ?",
                (validated.parsed.original,),
            ).fetchone()
            if existing_did is not None:
                return _error(409, "did_already_published", "This DID is already published"), False
            existing_url = connection.execute(
                "SELECT document_id FROM did_documents WHERE canonical_url = ?",
                (validated.parsed.canonical_url,),
            ).fetchone()
            if existing_url is not None:
                return _error(409, "canonical_url_conflict", "An equivalent DID URL is already published"), False
            stable = validated.parsed.stable_path_key
            if stable is not None:
                taken = connection.execute(
                    "SELECT did FROM stable_subject_paths WHERE stable_path_key = ?",
                    (stable,),
                ).fetchone()
                if taken is not None:
                    return _error(409, "stable_subject_path_reserved", "This WBA stable subject path is already assigned"), False
            import uuid

            document_id = "doc_" + uuid.uuid4().hex
            now = iso_now()
            connection.execute(
                """
                INSERT INTO did_documents(
                    document_id, did, method, canonical_url, path_key, stable_path_key, owner_id,
                    original_json, content_etag, local_auth_status, record_version, created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', 1, ?, ?)
                """,
                (
                    document_id,
                    validated.parsed.original,
                    validated.parsed.method,
                    validated.parsed.canonical_url,
                    validated.parsed.path_key,
                    stable,
                    grant["owner_id"],
                    body,
                    content_etag(body),
                    now,
                    now,
                ),
            )
            if stable is not None:
                connection.execute(
                    """
                    INSERT INTO stable_subject_paths(stable_path_key, owner_id, did, created_at)
                    VALUES(?, ?, ?, ?)
                    """,
                    (stable, grant["owner_id"], validated.parsed.original, now),
                )
            return Result(
                201,
                {
                    "document_id": document_id,
                    "did": validated.parsed.original,
                    "document_url": validated.parsed.canonical_url,
                    "content_path": validated.parsed.content_path,
                    "etag": version_etag(1),
                    "content_etag": content_etag(body),
                    "version": 1,
                    "method": validated.parsed.method,
                    "owner_id": grant["owner_id"],
                },
                {"ETag": version_etag(1)},
            ), True

        return self._run(publish, PROFILE_CREATE)

    def update_document(
        self,
        document_id: str,
        method: str,
        target_uri: str,
        raw_headers: list[tuple[str, str]],
        body: bytes,
    ) -> Result:
        if not header_values(raw_headers, "if-match"):
            return _error(428, "precondition_required", "Document update requires If-Match")
        current = self._document_by_id(document_id)
        if current is None:
            return _error(404, "not_found", "Document was not found")
        parsed = self._parse(raw_headers, body, PROFILE_UPDATE, require_json=True)
        published = parse_json_object(bytes(current["original_json"]), limit=self.settings.max_body_bytes)
        if parsed.did != current["did"]:
            raise auth_error(
                "invalid_did",
                "keyid DID does not equal the published document",
                realm=REALM,
                accept_signature=accept_signature(PROFILE_UPDATE),
            )
        self._verify(parsed, published, method, target_uri, body, PROFILE_UPDATE)
        self._require_json_type(parsed, PROFILE_UPDATE)
        self._require_authentication(parsed, published, PROFILE_UPDATE)
        if_match = parsed.headers["if-match"]
        verified_version = int(current["record_version"])

        def run(connection: sqlite3.Connection) -> tuple[Result, bool]:
            self._begin(connection, parsed, PROFILE_UPDATE)
            row = connection.execute(
                "SELECT * FROM did_documents WHERE document_id = ?",
                (document_id,),
            ).fetchone()
            if row is None:
                return _error(404, "not_found", "Document was not found"), False
            if int(row["record_version"]) != verified_version:
                return _error(412, "stale_auth_version", "The document changed after the signature was checked"), False
            if row["local_auth_status"] != "active":
                return _error(403, "local_auth_suspended", "Local authentication for this DID is suspended"), False
            try:
                matched = _version_from_etag(if_match)
            except ApiError as exc:
                return _error(exc.status, exc.error, exc.message), False
            if matched != int(row["record_version"]):
                return _error(412, "precondition_failed", "If-Match does not match the current document version"), False
            try:
                incoming = parse_json_object(body, limit=self.settings.max_body_bytes)
                validated = validate_document(incoming, self.settings)
            except ApiError as exc:
                return _error(exc.status, exc.error, exc.message), False
            if validated.parsed.original != row["did"] or validated.parsed.canonical_url != row["canonical_url"]:
                return _error(409, "did_identity_changed", "An update cannot change the DID or its canonical URL"), False
            grant = self._load_grant(connection, parsed.headers.get("anp-publication-token", ""))
            if (
                not self._grant_usable(grant)
                or grant["owner_id"] != row["owner_id"]
                or not _grant_covers_document(grant, validated)
            ):
                return _error(403, "publication_forbidden", "Publication credential is not authorized for this DID"), False
            binding = connection.execute(
                "SELECT * FROM handle_bindings WHERE did = ?",
                (row["did"],),
            ).fetchone()
            if binding is not None and binding["status"] == "active":
                if not declaration_satisfies(
                    validated.declaration,
                    local_part=binding["local_part"],
                    exact=bool(binding["exact"]),
                    provider_domain=self.settings.handle_provider_domain,
                ):
                    return _error(
                        409,
                        "active_handle_declaration_conflict",
                        "Active Handle still requires its method-specific service declaration",
                    ), False
            new_version = int(row["record_version"]) + 1
            now = iso_now()
            updated = connection.execute(
                """
                UPDATE did_documents
                SET original_json = ?, content_etag = ?, record_version = ?, updated_at = ?
                WHERE document_id = ? AND record_version = ?
                """,
                (body, content_etag(body), new_version, now, document_id, row["record_version"]),
            )
            if updated.rowcount != 1:
                return _error(412, "stale_auth_version", "The document changed after the signature was checked"), False
            if binding is not None and binding["status"] == "active":
                connection.execute(
                    "UPDATE handle_bindings SET validated_document_version = ?, updated_at = ? WHERE did = ?",
                    (new_version, now, row["did"]),
                )
            return Result(
                200,
                {
                    "document_id": document_id,
                    "did": row["did"],
                    "document_url": row["canonical_url"],
                    "content_path": validated.parsed.content_path,
                    "etag": version_etag(new_version),
                    "content_etag": content_etag(body),
                    "version": new_version,
                    "method": row["method"],
                    "owner_id": row["owner_id"],
                },
                {"ETag": version_etag(new_version)},
            ), True

        return self._run(run, PROFILE_UPDATE)

    def document_metadata(self, document_id: str) -> Result:
        row = self._document_by_id(document_id)
        if row is None:
            return _error(404, "not_found", "Document was not found")
        return Result(200, _metadata(row, urlsplit(row["canonical_url"]).path), {})

    def read_distributed(
        self,
        raw_path: str,
        http_method: str,
        if_none_match: str | None,
        accept: str | None,
    ) -> Result:
        if "?" in raw_path:
            return _error(404, "not_found", "No document is published at this path")
        try:
            canonical = canonical_url_for_http_path(
                raw_path,
                host=self.settings.public_did_domain,
                port=self.settings.public_did_port,
            )
        except ApiError:
            return _error(404, "not_found", "No document is published at this path")
        connection = self.store.connect()
        try:
            row = connection.execute(
                "SELECT * FROM did_documents WHERE canonical_url = ?",
                (canonical,),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            return _error(404, "not_found", "No document is published at this path")
        if accept is not None and not _accepts_did(accept):
            return _error(406, "not_acceptable", "Supported document types are application/did+json and application/json")
        headers = {
            "ETag": row["content_etag"],
            "Cache-Control": f"public, max-age={self.settings.cache_seconds}",
            "Content-Type": "application/did+json",
        }
        raw = bytes(row["original_json"])
        if if_none_match == row["content_etag"]:
            return Result(304, None, headers, media_type="application/did+json")
        headers["Content-Length"] = str(len(raw))
        if http_method == "HEAD":
            return Result(200, b"", headers, media_type="application/did+json")
        return Result(200, raw, headers, media_type="application/did+json")

    def put_handle(
        self,
        local_part: str,
        method: str,
        target_uri: str,
        raw_headers: list[tuple[str, str]],
        body: bytes,
    ) -> Result:
        try:
            normalized_local, domain = validate_handle(f"{local_part}.{self.settings.handle_provider_domain}")
        except Exception as exc:
            raise ApiError(422, "invalid_handle", "Handle local-part is not valid") from exc
        if domain != self.settings.handle_provider_domain:
            return _error(422, "invalid_handle", "Handle domain is not this provider")
        if normalized_local in RESERVED_HANDLES:
            return _error(422, "reserved_handle", "Handle local-part is reserved")
        handle = f"{normalized_local}.{domain}"
        did, status = _handle_request(body, self.settings.max_body_bytes)
        supplied_match = header_values(raw_headers, "if-match")
        profile = PROFILE_UPDATE if supplied_match else PROFILE_CREATE
        current = self._document_by_did(did)
        if current is None:
            raise auth_error(
                "invalid_did",
                "Handle target DID is not published on this server",
                realm=REALM,
                accept_signature=accept_signature(profile),
            )
        parsed = self._parse(raw_headers, body, profile, require_json=True)
        published = parse_json_object(bytes(current["original_json"]), limit=self.settings.max_body_bytes)
        if parsed.did != did or parsed.did != current["did"]:
            raise auth_error(
                "invalid_did",
                "keyid DID does not equal the Handle target",
                realm=REALM,
                accept_signature=accept_signature(profile),
            )
        self._verify(parsed, published, method, target_uri, body, profile)
        self._require_json_type(parsed, profile)
        self._require_authentication(parsed, published, profile)
        if_match = parsed.headers.get("if-match")
        verified_version = int(current["record_version"])

        def run(connection: sqlite3.Connection) -> tuple[Result, bool]:
            self._begin(connection, parsed, profile)
            row = connection.execute("SELECT * FROM did_documents WHERE did = ?", (did,)).fetchone()
            if row is None:
                return _error(404, "not_found", "DID is not published on this server"), False
            if int(row["record_version"]) != verified_version:
                return _error(412, "stale_auth_version", "The document changed after the signature was checked"), False
            if row["local_auth_status"] != "active":
                return _error(403, "local_auth_suspended", "Local authentication for this DID is suspended"), False
            grant = self._load_grant(connection, parsed.headers.get("anp-publication-token", ""))
            allowed_handles = set(json_list(grant["handles"])) if grant is not None else set()
            if not self._grant_usable(grant) or grant["owner_id"] != row["owner_id"] or handle not in allowed_handles:
                return _error(403, "publication_forbidden", "Publication credential is not authorized for this Handle"), False
            existing = connection.execute(
                "SELECT * FROM handle_bindings WHERE local_part = ?",
                (normalized_local,),
            ).fetchone()
            by_did = connection.execute(
                "SELECT * FROM handle_bindings WHERE did = ?",
                (did,),
            ).fetchone()
            if existing is None:
                if if_match is not None:
                    return _error(404, "not_found", "Handle is not registered"), False
                if by_did is not None:
                    return _error(409, "handle_did_taken", "This DID already has a Handle binding"), False
                if status != "active":
                    return _error(422, "invalid_handle_status", "The first Handle binding must be active"), False
                try:
                    validated = validate_document(
                        parse_json_object(bytes(row["original_json"]), limit=self.settings.max_body_bytes),
                        self.settings,
                    )
                except ApiError as exc:
                    return _error(exc.status, exc.error, exc.message), False
                exact = validated.parsed.method == "wba"
                if not declaration_satisfies(
                    validated.declaration,
                    local_part=normalized_local,
                    exact=exact,
                    provider_domain=domain,
                ):
                    return _error(409, "handle_declaration_mismatch", "Published document does not satisfy this Handle"), False
                generation = next_generation(None)
                now = iso_now()
                connection.execute(
                    """
                    INSERT INTO handle_bindings(
                        local_part, handle, provider_domain, did, owner_id, status, binding_generation,
                        exact, validated_document_version, record_version, suspend_reason, created_at, updated_at
                    ) VALUES(?, ?, ?, ?, ?, 'active', ?, ?, ?, 1, NULL, ?, ?)
                    """,
                    (
                        normalized_local,
                        handle,
                        domain,
                        did,
                        row["owner_id"],
                        generation,
                        1 if exact else 0,
                        int(row["record_version"]),
                        now,
                        now,
                    ),
                )
                self._history(connection, normalized_local, handle, did, None, "active", generation, "created", now)
                body_out = self._handle_admin(handle, did, "active", generation, int(row["record_version"]), exact)
                return Result(201, body_out, {"ETag": generation_etag(generation)}), True
            if if_match is None:
                return _error(409, "handle_exists", "An existing Handle requires If-Match and is not updated implicitly"), False
            if existing["did"] != did or (by_did is not None and by_did["local_part"] != normalized_local):
                return _error(409, "handle_rebinding_forbidden", "An existing Handle cannot be moved to another DID"), False
            try:
                matched = _generation_from_etag(if_match)
            except ApiError as exc:
                return _error(exc.status, exc.error, exc.message), False
            if matched != existing["binding_generation"]:
                return _error(412, "precondition_failed", "If-Match does not match the current Handle generation"), False
            if existing["status"] == "revoked" and status != "revoked":
                return _error(409, "handle_revoked", "A revoked Handle cannot be restored"), False
            if existing["status"] == status:
                body_out = self._handle_admin(
                    existing["handle"],
                    existing["did"],
                    existing["status"],
                    existing["binding_generation"],
                    int(existing["validated_document_version"]),
                    bool(existing["exact"]),
                )
                return Result(200, body_out, {"ETag": generation_etag(existing["binding_generation"])}), False
            validated = validate_document(
                parse_json_object(bytes(row["original_json"]), limit=self.settings.max_body_bytes),
                self.settings,
            )
            if status == "active":
                if not declaration_satisfies(
                    validated.declaration,
                    local_part=normalized_local,
                    exact=bool(existing["exact"]),
                    provider_domain=domain,
                ):
                    return _error(
                        409,
                        "active_handle_declaration_conflict",
                        "Restoring the Handle requires the current document declaration",
                    ), False
            generation = next_generation(existing["binding_generation"])
            now = iso_now()
            reason = None if status == "active" else status
            updated = connection.execute(
                """
                UPDATE handle_bindings
                SET status = ?, binding_generation = ?, record_version = record_version + 1,
                    validated_document_version = ?, suspend_reason = ?, updated_at = ?
                WHERE local_part = ? AND binding_generation = ?
                """,
                (
                    status,
                    generation,
                    int(row["record_version"]),
                    reason,
                    now,
                    normalized_local,
                    existing["binding_generation"],
                ),
            )
            if updated.rowcount != 1:
                return _error(412, "stale_auth_version", "The Handle changed after the signature was checked"), False
            self._history(
                connection,
                normalized_local,
                handle,
                did,
                existing["status"],
                status,
                generation,
                status,
                now,
            )
            body_out = self._handle_admin(
                handle,
                did,
                status,
                generation,
                int(row["record_version"]),
                bool(existing["exact"]),
            )
            return Result(200, body_out, {"ETag": generation_etag(generation)}), True

        return self._apply_exact_handle(self._run(run, profile))

    def read_handle(self, local_part: str) -> Result:
        return self._read_name(local_part, by_did=None)

    def read_handle_by_did(self, did: str) -> Result:
        if not did:
            return _error(400, "invalid_request", "did query parameter is required")
        return self._read_name(None, by_did=did)

    def whoami(self, method: str, target_uri: str, raw_headers: list[tuple[str, str]], body: bytes) -> Result:
        if body:
            return _error(400, "invalid_request", "whoami does not accept a request body")
        return self._example(method, target_uri, raw_headers, body, PROFILE_WHOAMI, echo=False)

    def echo(self, method: str, target_uri: str, raw_headers: list[tuple[str, str]], body: bytes) -> Result:
        if not body:
            return _error(400, "invalid_request", "echo requires a JSON body")
        return self._example(method, target_uri, raw_headers, body, PROFILE_ECHO, echo=True)

    def _example(
        self,
        method: str,
        target_uri: str,
        raw_headers: list[tuple[str, str]],
        body: bytes,
        profile: tuple[str, ...],
        *,
        echo: bool,
    ) -> Result:
        parsed = self._parse(raw_headers, body, profile, require_json=echo)
        row = self._document_by_did(parsed.did)
        if row is None:
            raise auth_error(
                "invalid_did",
                "DID is not published on this server",
                realm=REALM,
                accept_signature=accept_signature(profile),
            )
        document = parse_json_object(bytes(row["original_json"]), limit=self.settings.max_body_bytes)
        self._verify(parsed, document, method, target_uri, body, profile)
        if echo:
            self._require_json_type(parsed, profile)
        self._require_authentication(parsed, document, profile)
        payload: Any = None
        if echo:
            try:
                payload = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                return self._consume_failure(parsed, profile, 422, "invalid_json", "Echo body must be JSON")

        def run(connection: sqlite3.Connection) -> tuple[Result, bool]:
            self._begin(connection, parsed, profile)
            current = connection.execute("SELECT * FROM did_documents WHERE did = ?", (parsed.did,)).fetchone()
            if current is None:
                return _error(404, "not_found", "DID is not published on this server"), False
            if int(current["record_version"]) != int(row["record_version"]):
                return _error(412, "stale_auth_version", "The document changed after the signature was checked"), False
            if current["local_auth_status"] != "active":
                return _error(403, "local_auth_suspended", "Local authentication for this DID is suspended"), False
            response = {
                "did": current["did"],
                "auth_scheme": "http_signatures",
                "mode": _mode(self.settings),
            }
            if echo:
                response["body"] = payload
            return Result(200, response, {"Cache-Control": "no-store"}), False

        return self._run(run, profile)

    def _handle_admin(
        self,
        handle: str,
        did: str,
        status: str,
        generation: str,
        document_version: int,
        exact: bool,
    ) -> dict[str, Any]:
        observed = canonicalize_binding_generation(generation)
        pending_exact = False
        if self.settings.local_demo:
            verification = "declaration-consistent" if exact else "web-provider-domain"
            note = (
                "Local demo checks the stored WBA declaration only. It does not dereference HTTPS and is not exact-handle."
                if exact
                else "Web binding uses provider-domain declaration compatibility. It is not exact-handle."
            )
        elif not exact:
            verification = "web-provider-domain"
            note = "Web binding uses provider-domain declaration compatibility. It is not exact-handle."
        else:
            # The public GET must observe the committed generation. Do the HTTPS read after commit.
            pending_exact = True
            verification = "declaration-consistent"
            note = "Public HTTPS dereference did not complete. This result is not exact-handle."
        body = {
            "handle": handle,
            "did": did,
            "status": status,
            "binding_generation": observed,
            "etag": generation_etag(observed),
            "validated_document_version": document_version,
            "verification": verification,
            "verification_note": note,
            "observed_document_version": document_version,
            "observed_binding_generation": observed,
        }
        if pending_exact:
            body["_exact_handle_check"] = True
        return body

    def _apply_exact_handle(self, result: Result) -> Result:
        """Dereference a WBA Handle only after its binding transaction has committed."""
        if not isinstance(result.body, dict) or not result.body.get("_exact_handle_check"):
            return result
        body = {key: value for key, value in result.body.items() if key != "_exact_handle_check"}
        verification, note = _dereference_exact_handle(
            str(body["handle"]),
            str(body["did"]),
            str(body["binding_generation"]),
            self.settings.handle_provider_domain,
        )
        body["verification"] = verification
        body["verification_note"] = note
        return Result(result.status, body, result.headers, result.media_type)

    def _read_name(self, local_part: str | None, by_did: str | None) -> Result:
        connection = self.store.connect()
        try:
            if self.store.maintenance(connection):
                return _error(503, "maintenance", "Name service is in maintenance")
            if by_did is None:
                try:
                    normalized_local, domain = validate_handle(f"{local_part}.{self.settings.handle_provider_domain}")
                except Exception as exc:
                    raise ApiError(422, "invalid_handle", "Handle local-part is not valid") from exc
                if domain != self.settings.handle_provider_domain:
                    return _error(404, "not_found", "Handle is not registered")
                row = connection.execute(
                    "SELECT * FROM handle_bindings WHERE local_part = ?",
                    (normalized_local,),
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT * FROM handle_bindings WHERE did = ?",
                    (by_did,),
                ).fetchone()
        finally:
            connection.close()
        if row is None:
            return _error(404, "not_found", "Handle is not registered")
        if row["status"] == "revoked":
            return _error(410, "handle_revoked", "Handle has been revoked")
        return Result(
            200,
            {
                "handle": row["handle"],
                "did": row["did"],
                "status": row["status"],
                "binding_generation": canonicalize_binding_generation(row["binding_generation"]),
                "ttl": self.settings.cache_seconds,
                "updated": row["updated_at"],
            },
            {"Cache-Control": f"public, max-age={self.settings.cache_seconds}"},
        )

    def _parse(
        self,
        raw_headers: list[tuple[str, str]],
        body: bytes,
        profile: tuple[str, ...],
        *,
        require_json: bool,
    ) -> ParsedSignature:
        parsed = parse_limited_signature(
            raw_headers,
            body=body,
            profile=profile,
            settings=self.settings,
            now=self.clock(),
            require_json=require_json,
        )
        return parsed

    def _require_json_type(self, parsed: ParsedSignature, profile: tuple[str, ...]) -> None:
        if parsed.headers.get("content-type") != "application/json":
            raise auth_error(
                "invalid_request",
                "Content-Type must be exactly application/json",
                realm=REALM,
                accept_signature=accept_signature(profile),
            )

    def _verify(
        self,
        parsed: ParsedSignature,
        document: dict[str, Any],
        method: str,
        target_uri: str,
        body: bytes,
        profile: tuple[str, ...],
    ) -> None:
        verify_limited_signature(
            parsed,
            document,
            method=method,
            target_uri=target_uri,
            body=body,
            profile=profile,
        )

    def _require_authentication(self, parsed: ParsedSignature, document: dict[str, Any], profile: tuple[str, ...]) -> None:
        if parsed.keyid not in _authentication_ids(document):
            raise auth_error(
                "invalid_verification_method",
                "The signature key is not authorized by authentication",
                realm=REALM,
                accept_signature=accept_signature(profile),
            )

    def _begin(self, connection: sqlite3.Connection, parsed: ParsedSignature, profile: tuple[str, ...]) -> None:
        connection.execute("DELETE FROM used_nonces WHERE expires_at < ?", (self.clock(),))
        if self.store.maintenance(connection):
            raise _Rollback(_error(503, "maintenance", "Name and authentication writes are in maintenance"))
        try:
            connection.execute(
                "INSERT INTO used_nonces(keyid, nonce, expires_at) VALUES(?, ?, ?)",
                (parsed.keyid, parsed.nonce, parsed.expires + self.settings.clock_skew),
            )
            current_mark = int(self.store.meta_get(connection, "nonce_watermark") or "0")
            self.store.meta_set(connection, "nonce_watermark", str(current_mark + 1))
        except sqlite3.IntegrityError as exc:
            if "used_nonces" in str(exc):
                raise _Replay(profile) from exc
            raise

    def _run(self, operation: Callable[[sqlite3.Connection], tuple[Result, bool]], profile: tuple[str, ...]) -> Result:
        try:
            with self.store.immediate() as connection:
                result, changed = operation(connection)
        except _Rollback as exc:
            return exc.result
        except _Replay as exc:
            return _auth_failure(exc.profile, "invalid_nonce", "This signature has already been used")
        except ApiError:
            raise
        self._sync_high_water()
        return result

    def _consume_failure(
        self,
        parsed: ParsedSignature,
        profile: tuple[str, ...],
        status: int,
        error: str,
        message: str,
    ) -> Result:
        def run(connection: sqlite3.Connection) -> tuple[Result, bool]:
            self._begin(connection, parsed, profile)
            return _error(status, error, message), False

        return self._run(run, profile)

    def _load_grant(self, connection: sqlite3.Connection, token: str) -> sqlite3.Row | None:
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        return connection.execute(
            "SELECT * FROM publication_grants WHERE token_sha256 = ?",
            (digest,),
        ).fetchone()

    def _grant_usable(self, grant: sqlite3.Row | None) -> bool:
        if grant is None or int(grant["revoked"]):
            return False
        expires = grant["expires_at"]
        return expires is None or int(expires) > self.clock()

    def _document_by_id(self, document_id: str) -> sqlite3.Row | None:
        connection = self.store.connect()
        try:
            return connection.execute(
                "SELECT * FROM did_documents WHERE document_id = ?",
                (document_id,),
            ).fetchone()
        finally:
            connection.close()

    def _document_by_did(self, did: str) -> sqlite3.Row | None:
        connection = self.store.connect()
        try:
            return connection.execute("SELECT * FROM did_documents WHERE did = ?", (did,)).fetchone()
        finally:
            connection.close()

    def _facts(self):
        connection = self.store.connect()
        try:
            return self.store.facts(connection)
        finally:
            connection.close()

    def _sync_high_water(self) -> None:
        with self._high_water_lock:
            current = self._facts()
            reference = read_facts(self.settings.high_water_path)
            if reference is None:
                if _facts_empty(current):
                    write_facts(self.settings.high_water_path, current)
                return
            decision = decide_recovery(
                reference,
                current,
                self.clock(),
                self._ordinary_span(),
                self._replay_span(),
                reference.replay_resume_after,
            )
            if not decision.structural_ok or decision.replay_behind:
                reason = (
                    "database is behind the high-water file"
                    if not decision.structural_ok
                    else "replay watermark is ahead of the database"
                )
                self._hold_maintenance(reason)
                if decision.replay_behind and reference.replay_resume_after <= 0:
                    self._persist_replay(reference, decision.watermark, decision.resume_after)
                return
            latest = read_facts(self.settings.high_water_path)
            if latest is not None and latest.nonce_watermark > current.nonce_watermark:
                return
            write_facts(
                self.settings.high_water_path,
                _facts_with_replay(current, decision.watermark, 0),
            )

    def _ordinary_span(self) -> int:
        return self.settings.signature_lifetime + self.settings.clock_skew

    def _replay_span(self) -> int:
        # A consumed signature may have been created one skew in the future and
        # remains acceptable until expires plus another skew. The extra second
        # covers the strict `expires < now - skew` boundary.
        return self._ordinary_span() + self.settings.clock_skew + 1

    def _hold_maintenance(self, reason: str) -> None:
        """Stop authentication writes. The replay deadline stays in the sidecar."""
        with self.store.immediate() as connection:
            self.store.meta_set(connection, "maintenance", "1")
            self.store.meta_set(connection, "maintenance_reason", reason)

    def _persist_replay(self, reference, watermark: int, resume_after: int) -> None:
        write_facts(
            self.settings.high_water_path,
            _facts_with_replay(reference, watermark, resume_after),
        )

    def _maintenance_reason(self) -> str | None:
        connection = self.store.connect()
        try:
            if not self.store.maintenance(connection):
                return None
            return self.store.meta_get(connection, "maintenance_reason") or "maintenance"
        finally:
            connection.close()

    def _suspend_handles(self, connection: sqlite3.Connection, did: str, now: str, reason: str) -> int:
        rows = connection.execute(
            "SELECT * FROM handle_bindings WHERE did = ? AND status = 'active'",
            (did,),
        ).fetchall()
        for row in rows:
            generation = next_generation(row["binding_generation"])
            connection.execute(
                """
                UPDATE handle_bindings
                SET status = 'suspended', binding_generation = ?, record_version = record_version + 1,
                    suspend_reason = ?, updated_at = ?
                WHERE local_part = ?
                """,
                (generation, reason, now, row["local_part"]),
            )
            self._history(
                connection,
                row["local_part"],
                row["handle"],
                did,
                "active",
                "suspended",
                generation,
                reason,
                now,
            )
        return len(rows)

    def _history(
        self,
        connection: sqlite3.Connection,
        local_part: str,
        handle: str,
        did: str,
        old_status: str | None,
        new_status: str,
        generation: str,
        reason: str | None,
        now: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO handle_history(
                local_part, handle, did, old_status, new_status, binding_generation, reason, created_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (local_part, handle, did, old_status, new_status, generation, reason, now),
        )


def _facts_with_replay(facts: Facts, watermark: int, resume_after: int) -> Facts:
    return Facts(
        facts.generations,
        facts.tombstones,
        facts.revoked_grants,
        facts.stable_paths,
        nonce_watermark=watermark,
        replay_resume_after=resume_after,
    )


def _facts_empty(facts) -> bool:
    return facts == EMPTY or (
        not facts.generations
        and not facts.tombstones
        and not facts.revoked_grants
        and not facts.stable_paths
        and facts.nonce_watermark == 0
    )


def _grant_covers_document(grant: sqlite3.Row | None, validated) -> bool:
    if grant is None:
        return False
    if validated.parsed.method == "wba":
        return validated.parsed.stable_path_key in set(json_list(grant["wba_paths"]))
    return validated.parsed.path_key in set(json_list(grant["web_paths"]))


def _metadata(row: sqlite3.Row, content_path: str) -> dict[str, Any]:
    return {
        "document_id": row["document_id"],
        "did": row["did"],
        "document_url": row["canonical_url"],
        "content_path": content_path,
        "etag": version_etag(int(row["record_version"])),
        "content_etag": row["content_etag"],
        "version": int(row["record_version"]),
        "method": row["method"],
        "local_auth_status": row["local_auth_status"],
        "owner_id": row["owner_id"],
    }


def _version_from_etag(value: str) -> int:
    if value == "*" or "," in value or value.startswith("W/") or not (value.startswith('"') and value.endswith('"')):
        raise ApiError(400, "invalid_precondition", "If-Match must be one strong ETag")
    inner = value[1:-1]
    if not inner.startswith("v"):
        raise ApiError(400, "invalid_precondition", "Document If-Match must be a vN ETag")
    number = inner[1:]
    if not number.isdecimal() or number[0] == "0":
        raise ApiError(400, "invalid_precondition", "Document version must be a canonical positive integer")
    return int(number)


def _generation_from_etag(value: str) -> str:
    if value == "*" or "," in value or value.startswith("W/") or not (value.startswith('"') and value.endswith('"')):
        raise ApiError(400, "invalid_precondition", "If-Match must be one strong ETag")
    inner = value[1:-1]
    if not inner.startswith("g"):
        raise ApiError(400, "invalid_precondition", "Handle If-Match must be a gN ETag")
    try:
        return canonicalize_binding_generation(inner[1:])
    except ValueError as exc:
        raise ApiError(400, "invalid_precondition", "Handle generation must be a canonical positive decimal") from exc


def _handle_request(body: bytes, limit: int) -> tuple[str, str]:
    document = parse_json_object(body, limit=limit)
    if set(document) != {"did", "status"}:
        raise ApiError(422, "invalid_handle", "Handle body must contain only did and status")
    if not isinstance(document["did"], str) or not isinstance(document["status"], str):
        raise ApiError(422, "invalid_handle", "Handle did and status must be strings")
    if document["status"] not in {"active", "suspended", "revoked"}:
        raise ApiError(422, "invalid_handle_status", "Handle status is not supported")
    return document["did"], document["status"]


def _accepts_did(accept: str) -> bool:
    if accept.strip() == "":
        return True
    for part in accept.split(","):
        media = part.split(";", 1)[0].strip().lower()
        if media in {"*/*", "application/*", "application/did+json", "application/json"}:
            return True
    return False


def _dereference_exact_handle(handle: str, did: str, generation: str, provider: str) -> tuple[str, str]:
    local = handle.split(".", 1)[0]
    url = f"https://{provider}/.well-known/handle/{local}"
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            payload = json.loads(response.read().decode("utf-8"))
            status = getattr(response, "status", 200)
        if (
            status == 200
            and payload.get("handle") == handle
            and payload.get("did") == did
            and payload.get("status") == "active"
            and payload.get("binding_generation") == generation
        ):
            return "exact-handle", "Public HTTPS resolution returned the active Handle and DID."
    except Exception:
        pass
    return (
        "declaration-consistent",
        "Public HTTPS dereference did not complete. This result is not exact-handle.",
    )
