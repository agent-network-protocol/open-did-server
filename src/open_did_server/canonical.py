"""One canonical resource key for did:wba and did:web."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import quote, unquote

from open_did_server.errors import ApiError

_SEGMENT = re.compile(r"(?:[A-Za-z0-9._~-]|%[0-9A-Fa-f]{2})+")
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_E1 = re.compile(r"e1_[A-Za-z0-9_-]{43}")
_RESERVED_FIRST = {"api", "healthz", "examples", ".well-known"}


class CanonicalError(ApiError):
    def __init__(self, message: str) -> None:
        super().__init__(422, "invalid_did", message)


@dataclass(frozen=True)
class ParsedDid:
    original: str
    method: str
    host: str
    port: int | None
    segments: tuple[str, ...]
    canonical_url: str
    path_key: str
    stable_path_key: str | None
    is_root: bool
    is_e1_path: bool

    @property
    def effective_port(self) -> int:
        return 443 if self.port is None else self.port

    @property
    def content_path(self) -> str:
        return canonical_path(self.segments)


def canonical_path(segments: tuple[str, ...]) -> str:
    if not segments:
        return "/.well-known/did.json"
    encoded = "/".join(encode_segment(segment) for segment in segments)
    return f"/{encoded}/did.json"


def encode_segment(segment: str) -> str:
    return quote(segment, safe="-._~")


def decode_segment(raw: str) -> str:
    if not raw or not _SEGMENT.fullmatch(raw):
        raise CanonicalError("DID path segment is empty or ambiguously encoded")
    decoded = unquote(raw)
    if decoded in {"", ".", ".."}:
        raise CanonicalError("DID path segment is empty or a dot segment")
    if any(character in "/\\?#" or ord(character) < 32 or ord(character) == 127 for character in decoded):
        raise CanonicalError("DID path segment contains a separator or control character")
    if "%" in decoded and unquote(decoded) != decoded:
        raise CanonicalError("DID path segment requires a second decode")
    return decoded


def _split_host_port(authority: str) -> tuple[str, int | None]:
    if authority.count(":") > 1 or "@" in authority or authority.endswith("."):
        raise CanonicalError("DID authority is ambiguous")
    if ":" in authority:
        host, port_text = authority.split(":", 1)
        if not port_text.isascii() or not port_text.isdecimal() or port_text[0] == "0":
            raise CanonicalError("DID port is not a canonical decimal integer")
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise CanonicalError("DID port is out of range")
    else:
        host, port = authority, None
    host = host.lower()
    labels = host.split(".")
    if (
        len(host) > 253
        or len(labels) < 2
        or not any(character.isalpha() for character in labels[-1])
        or any(not _HOST_LABEL.fullmatch(label) for label in labels)
    ):
        raise CanonicalError("DID authority is not a DNS hostname")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise CanonicalError("DID authority must not be an IP address")
    return host, port


def path_key(host: str, port: int | None, segments: tuple[str, ...]) -> str:
    effective = 443 if port is None else port
    return f"{host}|{effective}|{'/'.join(segments)}"


def origin_for(host: str, port: int | None) -> str:
    if port in (None, 443):
        return f"https://{host}"
    return f"https://{host}:{port}"


def parse_did(did: str) -> ParsedDid:
    """Parse a DID without rewriting the caller's original string."""
    if not isinstance(did, str) or not did.startswith("did:") or any(ord(character) < 33 for character in did):
        raise CanonicalError("DID is missing or contains whitespace")
    parts = did.split(":")
    if len(parts) < 3 or parts[0] != "did" or parts[1] not in {"wba", "web"}:
        raise CanonicalError("DID method must be did:wba or did:web")
    if any(part == "" for part in parts):
        raise CanonicalError("DID contains an empty component")
    method = parts[1]
    try:
        authority = decode_segment(parts[2])
    except CanonicalError as exc:
        raise CanonicalError("DID authority is not canonically encoded") from exc
    host, port = _split_host_port(authority)
    segments = tuple(decode_segment(part) for part in parts[3:])
    if segments and segments[0] in _RESERVED_FIRST:
        raise CanonicalError("DID path is reserved by the server")
    is_e1 = bool(segments) and _E1.fullmatch(segments[-1]) is not None
    if method == "wba" and segments and not is_e1:
        raise CanonicalError("new did:wba path identities must end in an e1 fingerprint")
    if method == "web" and is_e1:
        # A Web path may literally contain an e1_-looking segment. That does not
        # make it a WBA profile, but this server's Web example paths do not use one.
        pass
    stable = path_key(host, port, segments[:-1]) if method == "wba" and is_e1 else None
    if method == "wba" and not segments:
        stable = path_key(host, port, ())
    url = origin_for(host, port) + canonical_path(segments)
    return ParsedDid(
        original=did,
        method=method,
        host=host,
        port=port,
        segments=segments,
        canonical_url=url,
        path_key=path_key(host, port, segments),
        stable_path_key=stable,
        is_root=not segments,
        is_e1_path=is_e1,
    )


def canonical_url_for_http_path(path: str, *, host: str, port: int) -> str:
    """Map a request path onto the same resource key used at publication."""
    if not path.startswith("/") or "?" in path or "#" in path:
        raise CanonicalError("document path is not absolute")
    public_port = None if port == 443 else port
    if path == "/.well-known/did.json":
        return origin_for(host, public_port) + path
    if not path.endswith("/did.json"):
        raise CanonicalError("document path must end in did.json")
    middle = path[1 : -len("/did.json")]
    if not middle or middle.endswith("/"):
        raise CanonicalError("document path is empty")
    segments = tuple(decode_segment(part) for part in middle.split("/"))
    if segments[0] in _RESERVED_FIRST:
        raise CanonicalError("document path is reserved")
    return origin_for(host, public_port) + canonical_path(segments)


def hosted(parsed: ParsedDid, *, domain: str, port: int) -> None:
    effective = 443 if parsed.port is None else parsed.port
    if parsed.host != domain or effective != port:
        raise ApiError(403, "publication_forbidden", "DID authority is not hosted by this server")
