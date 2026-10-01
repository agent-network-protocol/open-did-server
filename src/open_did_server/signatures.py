"""Limited sig1 HTTP Message Signature adapter.

The SDK parser rebuilds parameters in a fixed order and collapses duplicate
headers. This module rejects ambiguous input from the raw header list before
that parser, then calls the SDK to check the signature bytes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass

from anp.authentication.http_signatures import (
    extract_signature_metadata,
    verify_http_message_signature,
)

from open_did_server.canonical import parse_did
from open_did_server.config import Settings
from open_did_server.errors import ApiError, auth_error

REALM = "open-did-server"

PROFILE_WHOAMI = ("@method", "@target-uri", "@authority")
PROFILE_ECHO = PROFILE_WHOAMI + ("content-digest", "content-type")
PROFILE_CREATE = PROFILE_ECHO + ("anp-publication-token",)
PROFILE_UPDATE = PROFILE_ECHO + ("if-match", "anp-publication-token")

_CRITICAL = {
    "authorization",
    "anp-publication-token",
    "content-digest",
    "content-length",
    "content-type",
    "forwarded",
    "if-match",
    "if-none-match",
    "signature",
    "signature-input",
    "www-authenticate",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
}
_COMPONENTS = re.compile(
    r'^(?:"(?:@(?:method|target-uri|authority)|[a-z0-9-]+)")'
    r'(?: "(?:@(?:method|target-uri|authority)|[a-z0-9-]+)")*$'
)
_SIGNATURE_INPUT = re.compile(
    r"^sig1=\((?P<components>[^)]*)\);"
    r"created=(?P<created>0|[1-9][0-9]{0,11});"
    r"expires=(?P<expires>0|[1-9][0-9]{0,11});"
    r'nonce="(?P<nonce>[0-9a-f]{32})";'
    r'keyid="(?P<keyid>[^"\\]*)"$'
)
_SIGNATURE = re.compile(r"^sig1=:([A-Za-z0-9+/]{86}==):$")
_DIGEST = re.compile(r"^sha-256=:([A-Za-z0-9+/]{43}=):$")
_FRAGMENT = re.compile(r"[A-Za-z0-9._~-]+")


@dataclass(frozen=True)
class ParsedSignature:
    keyid: str
    did: str
    fragment: str
    nonce: str
    created: int
    expires: int
    components: tuple[str, ...]
    headers: dict[str, str]
    signature_input: str
    signature: str


def accept_signature(profile: tuple[str, ...]) -> str:
    covered = " ".join(f'"{component}"' for component in profile)
    return f"sig1=({covered})"


def _auth(profile: tuple[str, ...], code: str, message: str) -> ApiError:
    return auth_error(code, message, realm=REALM, accept_signature=accept_signature(profile))


def header_values(raw_headers: list[tuple[str, str]], name: str) -> list[str]:
    lowered = name.lower()
    return [value for key, value in raw_headers if key.lower() == lowered]


def single_header(raw_headers: list[tuple[str, str]], name: str) -> str | None:
    values = header_values(raw_headers, name)
    if not values:
        return None
    if len(values) > 1:
        raise ApiError(400, "invalid_request", f"Duplicate {name} header")
    return values[0]


def content_digest_for(body: bytes) -> str:
    digest = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
    return f"sha-256=:{digest}:"


def _components(raw: str) -> tuple[str, ...]:
    if not raw or not _COMPONENTS.fullmatch(raw):
        raise ValueError("components")
    names = tuple(part[1:-1] for part in raw.split(" "))
    if len(names) != len(set(names)):
        raise ValueError("duplicate-component")
    return names


def _keyid(value: str) -> tuple[str, str]:
    if (
        not value
        or value.count("#") != 1
        or any(ord(character) < 33 or character in '"\\' for character in value)
    ):
        raise ValueError("keyid")
    did, fragment = value.split("#", 1)
    if not _FRAGMENT.fullmatch(fragment) or not did.startswith("did:"):
        raise ValueError("keyid")
    parse_did(did)
    return did, fragment


def parse_limited_signature(
    raw_headers: list[tuple[str, str]],
    *,
    body: bytes,
    profile: tuple[str, ...],
    settings: Settings,
    now: int,
    require_json: bool,
) -> ParsedSignature:
    """Reject every supported-profile ambiguity before header dictionaries."""
    counts: dict[str, int] = {}
    for name, _value in raw_headers:
        lowered = name.lower()
        counts[lowered] = counts.get(lowered, 0) + 1
    for name in _CRITICAL:
        if counts.get(name, 0) > 1:
            raise _auth(profile, "invalid_request", f"Duplicate {name} header")

    signature_input = single_header(raw_headers, "signature-input")
    signature = single_header(raw_headers, "signature")
    if not signature_input or not signature:
        raise _auth(profile, "invalid_request", "Signature-Input and Signature are required")
    if "," in signature_input or "," in signature:
        raise _auth(profile, "invalid_request", "Multiple signatures are not accepted")
    match = _SIGNATURE_INPUT.fullmatch(signature_input)
    signature_match = _SIGNATURE.fullmatch(signature)
    if match is None or signature_match is None:
        raise _auth(profile, "invalid_request", "Signature parameters are outside the supported sig1 profile")
    try:
        signature_bytes = base64.b64decode(signature_match.group(1), validate=True)
    except ValueError as exc:
        raise _auth(profile, "invalid_request", "Signature is not canonical base64") from exc
    if len(signature_bytes) != 64:
        raise _auth(profile, "invalid_signature", "Signature is not a 64-byte Ed25519 signature")
    try:
        components = _components(match.group("components"))
        did, fragment = _keyid(match.group("keyid"))
    except ApiError:
        raise
    except Exception as exc:
        raise _auth(profile, "invalid_request", "Signature-Input is outside the supported sig1 profile") from exc
    if components != profile:
        raise _auth(profile, "invalid_request", "Signature components do not match this endpoint")
    for component in components:
        if component.startswith("@"):
            continue
        if counts.get(component, 0) != 1:
            raise _auth(profile, "invalid_request", f"Covered header {component} is missing or duplicated")

    created = int(match.group("created"))
    expires = int(match.group("expires"))
    if expires <= created or expires - created > settings.signature_lifetime:
        raise _auth(profile, "invalid_timestamp", "Signature lifetime is outside the 300 second window")
    if created > now + settings.clock_skew or expires < now - settings.clock_skew:
        raise _auth(profile, "invalid_timestamp", "Signature is outside the accepted clock window")

    headers = {name.lower(): value for name, value in raw_headers}
    if require_json:
        digest = headers.get("content-digest")
        if digest is None or _DIGEST.fullmatch(digest) is None:
            raise _auth(profile, "invalid_content_digest", "Content-Digest must be a single sha-256 value")
        if not hmac.compare_digest(digest, content_digest_for(body)):
            raise _auth(profile, "invalid_content_digest", "Content-Digest does not match the request body")
    return ParsedSignature(
        keyid=match.group("keyid"),
        did=did,
        fragment=fragment,
        nonce=match.group("nonce"),
        created=created,
        expires=expires,
        components=components,
        headers=headers,
        signature_input=signature_input,
        signature=signature,
    )


def verify_limited_signature(
    parsed: ParsedSignature,
    document: dict,
    *,
    method: str,
    target_uri: str,
    body: bytes,
    profile: tuple[str, ...],
) -> None:
    """Verify with the SDK after the application profile has been enforced."""
    header_map = {
        "Signature-Input": parsed.signature_input,
        "Signature": parsed.signature,
    }
    for name, value in parsed.headers.items():
        header_map.setdefault(name, value)
    try:
        metadata = extract_signature_metadata(header_map)
    except Exception as exc:
        raise _auth(profile, "invalid_request", "Signature metadata does not match the supported profile") from exc
    if tuple(metadata.get("components") or ()) != parsed.components or metadata.get("params", {}).get("keyid") != parsed.keyid:
        raise _auth(profile, "invalid_request", "Signature metadata does not match the supported profile")
    ok, message, details = verify_http_message_signature(
        document,
        method,
        target_uri,
        header_map,
        body,
    )
    if not ok:
        if "Content-Digest" in message:
            raise _auth(profile, "invalid_content_digest", "Content-Digest verification failed")
        if "not found" in message.lower() or "keyid" in message.lower():
            raise _auth(profile, "invalid_verification_method", "Verification method was not found")
        raise _auth(profile, "invalid_signature", "HTTP signature verification failed")
    if details.get("keyid") != parsed.keyid:
        raise _auth(profile, "invalid_signature", "Verified key does not match Signature-Input")
