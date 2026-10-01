"""Strict JSON object parsing for uploaded DID documents."""

from __future__ import annotations

import json
from typing import Any

from open_did_server.errors import ApiError

_PRIVATE_NAMES = {
    "d",
    "privatekey",
    "privatekeypem",
    "private_key",
    "private_key_pem",
    "seed",
}


def parse_json_object(raw: bytes, *, limit: int) -> Any:
    if len(raw) > limit:
        raise ApiError(413, "payload_too_large", "Request body exceeds 1 MiB")
    if not raw:
        raise ApiError(422, "invalid_json", "Request body must be a JSON object")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ApiError(422, "invalid_json", "Request body must be UTF-8 JSON") from exc

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        seen: set[str] = set()
        result: dict[str, Any] = {}
        for key, value in items:
            if key in seen:
                raise ApiError(422, "duplicate_json_key", f"Duplicate JSON field {key}")
            seen.add(key)
            result[key] = value
        return result

    try:
        value = json.loads(text, object_pairs_hook=pairs)
    except ApiError:
        raise
    except json.JSONDecodeError as exc:
        raise ApiError(422, "invalid_json", "Request body is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ApiError(422, "invalid_json", "Request body must be a JSON object")
    _reject_private_material(value)
    return value


def _reject_private_material(node: Any) -> None:
    if isinstance(node, dict):
        jwk_like = "kty" in node or "crv" in node
        for key, value in node.items():
            lowered = key.lower()
            if lowered in _PRIVATE_NAMES and (lowered != "d" or jwk_like or "x" in node):
                raise ApiError(422, "private_key_rejected", "Uploaded document contains private key material")
            if isinstance(value, str) and "PRIVATE KEY" in value:
                raise ApiError(422, "private_key_rejected", "Uploaded document contains a private key PEM")
            _reject_private_material(value)
    elif isinstance(node, list):
        for item in node:
            _reject_private_material(item)
