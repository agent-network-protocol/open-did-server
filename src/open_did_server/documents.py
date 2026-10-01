"""Upload-time DID document checks that the SDK method helper does not replace."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from anp.authentication.did_wba import validate_did_document_binding
from anp.wns.validator import validate_handle

from open_did_server.canonical import ParsedDid, hosted, parse_did
from open_did_server.config import Settings
from open_did_server.errors import ApiError

_WBA_CONTEXTS = {
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/data-integrity/v2",
    "https://w3id.org/security/multikey/v1",
}
_WEB_CONTEXTS = [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
]
_FRAGMENT = re.compile(r"[A-Za-z0-9._~-]+")
RESERVED_HANDLES = {
    "admin",
    "agent",
    "api",
    "did",
    "ftp",
    "mail",
    "official",
    "root",
    "security",
    "service",
    "support",
    "system",
    "well-known",
    "www",
}


@dataclass(frozen=True)
class HandleDeclaration:
    local_part: str
    handle: str
    endpoint: str
    exact: bool


@dataclass(frozen=True)
class ValidatedDocument:
    parsed: ParsedDid
    authentication_ids: tuple[str, ...]
    assertion_ids: tuple[str, ...]
    declaration: HandleDeclaration | None


def _error(status: int, error: str, message: str) -> ApiError:
    return ApiError(status, error, message)


def _absolute_method_id(value: Any, did: str, field: str) -> str:
    if not isinstance(value, str) or value.startswith("#") or not value.startswith(f"{did}#"):
        raise _error(422, "unsupported_relative_did_url", f"{field} must be an absolute DID URL")
    fragment = value.split("#", 1)[1]
    if not _FRAGMENT.fullmatch(fragment):
        raise _error(422, "invalid_verification_method", f"{field} fragment is not supported")
    return value


def _relationship(document: dict[str, Any], name: str, did: str) -> tuple[str, ...]:
    entries = document.get(name, [])
    if entries is None:
        return ()
    if not isinstance(entries, list):
        raise _error(422, "invalid_did_document", f"{name} must be an array")
    result: list[str] = []
    for entry in entries:
        if isinstance(entry, str):
            result.append(_absolute_method_id(entry, did, name))
        elif isinstance(entry, dict):
            result.append(_absolute_method_id(entry.get("id"), did, name))
        else:
            raise _error(422, "invalid_did_document", f"{name} entry is not a reference")
    return tuple(result)


def _reject_lifecycle(document: dict[str, Any]) -> None:
    if "successorDid" in document or "successor_did" in document:
        raise _error(422, "unsupported_did_lifecycle", "successorDid is not accepted in this version")
    if "deactivated" in document and document["deactivated"] is not False:
        raise _error(422, "unsupported_did_lifecycle", "deactivated must be false when present")


def _jwk_ok(jwk: Any) -> None:
    if not isinstance(jwk, dict):
        raise _error(422, "unsupported_key", "publicKeyJwk must be an object")
    if any(str(name).lower() in {"d", "privatekey", "private_key", "seed"} for name in jwk):
        raise _error(422, "private_key_rejected", "Uploaded document contains private key material")
    if set(jwk) != {"crv", "kty", "x"}:
        raise _error(422, "unsupported_key", "Ed25519 publicKeyJwk must contain only kty, crv, and x")
    if jwk["kty"] != "OKP" or jwk["crv"] != "Ed25519":
        raise _error(422, "unsupported_key", "Only OKP Ed25519 keys are accepted")
    try:
        padded = jwk["x"] + "=" * (-len(jwk["x"]) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (TypeError, ValueError, AttributeError) as exc:
        raise _error(422, "unsupported_key", "publicKeyJwk.x is not canonical base64url") from exc
    if len(raw) != 32 or "=" in jwk["x"] or not re.fullmatch(r"[A-Za-z0-9_-]+", jwk["x"]):
        raise _error(422, "unsupported_key", "publicKeyJwk.x must be unpadded base64url for 32 bytes")


def _check_methods(document: dict[str, Any], did: str, *, web: bool) -> dict[str, dict[str, Any]]:
    methods = document.get("verificationMethod")
    if not isinstance(methods, list) or not methods:
        raise _error(422, "invalid_did_document", "verificationMethod is required")
    found: dict[str, dict[str, Any]] = {}
    for method in methods:
        if not isinstance(method, dict):
            raise _error(422, "invalid_did_document", "verificationMethod entry must be an object")
        method_id = _absolute_method_id(method.get("id"), did, "verificationMethod.id")
        if method_id in found:
            raise _error(422, "invalid_did_document", "verificationMethod ids must be unique")
        if method.get("controller") != did:
            raise _error(422, "invalid_did_document", "verificationMethod controller must equal the document id")
        material = [name for name in ("publicKeyJwk", "publicKeyMultibase", "publicKeyBase58") if name in method]
        if len(material) != 1:
            raise _error(422, "unsupported_key", "A verification method needs exactly one public key field")
        if web:
            if method.get("type") != "JsonWebKey2020" or material != ["publicKeyJwk"]:
                raise _error(422, "unsupported_key", "Web documents in this version use JsonWebKey2020")
            _jwk_ok(method["publicKeyJwk"])
        else:
            if method.get("type") != "Multikey" or material != ["publicKeyMultibase"]:
                raise _error(422, "unsupported_key", "WBA E1 documents in this version use Multikey")
            if not isinstance(method["publicKeyMultibase"], str) or not method["publicKeyMultibase"].startswith("z"):
                raise _error(422, "unsupported_key", "Multikey material must be base58-btc")
        found[method_id] = method
    return found


def _contexts(document: dict[str, Any], *, web: bool) -> None:
    context = document.get("@context")
    if web:
        if context is not None and context != _WEB_CONTEXTS:
            raise _error(422, "unsupported_context", "Web @context must be omitted or the fixed JWK set")
        return
    if not isinstance(context, list) or any(item not in _WBA_CONTEXTS for item in context):
        raise _error(422, "unsupported_context", "WBA @context must use the fixed E1 set")
    if "https://www.w3.org/ns/did/v1" not in context:
        raise _error(422, "unsupported_context", "WBA @context must include the DID Core context")


def _standard_local_part(path: str) -> str | None:
    prefix = "/.well-known/handle/"
    if not path.startswith(prefix):
        return None
    rest = path[len(prefix) :]
    if not rest or "/" in rest:
        return None
    return rest


def _handle_declaration(
    document: dict[str, Any],
    parsed: ParsedDid,
    settings: Settings,
) -> HandleDeclaration | None:
    services = document.get("service", [])
    if services is None:
        return None
    if not isinstance(services, list):
        raise _error(422, "invalid_did_document", "service must be an array")
    found: HandleDeclaration | None = None
    provider = settings.handle_provider_domain
    for service in services:
        if not isinstance(service, dict):
            raise _error(422, "invalid_did_document", "service entry must be an object")
        _absolute_method_id(service.get("id"), parsed.original, "service.id")
        endpoint = service.get("serviceEndpoint")
        if not isinstance(endpoint, str) or "://" not in endpoint:
            raise _error(422, "invalid_service", "serviceEndpoint must be an absolute URI")
        if service.get("type") != "ANPHandleService":
            continue
        if found is not None:
            raise _error(422, "invalid_service", "Only one ANPHandleService is accepted")
        parsed_url = urlsplit(endpoint)
        if (
            parsed_url.scheme != "https"
            or parsed_url.username
            or parsed_url.password
            or parsed_url.query
            or parsed_url.fragment
            or parsed_url.port not in (None, 443)
        ):
            raise _error(422, "invalid_service", "ANPHandleService must be an https URL without user info or a port")
        if (parsed_url.hostname or "").lower() != provider:
            raise _error(422, "invalid_service", "ANPHandleService host must be this Handle provider")
        exact = parsed.method == "wba"
        if exact and not settings.wba_handles_enabled:
            raise _error(
                422,
                "invalid_service",
                "WBA Handle is disabled until PUBLIC_DID_DOMAIN matches HANDLE_PROVIDER_DOMAIN",
            )
        raw_local = _standard_local_part(parsed_url.path)
        local_part: str | None = None
        handle = ""
        if raw_local is not None:
            try:
                local_part, normalized_domain = validate_handle(f"{raw_local}.{provider}")
            except Exception as exc:
                raise _error(422, "invalid_handle", "Handle in the service endpoint is not valid") from exc
            if normalized_domain != provider:
                raise _error(422, "invalid_service", "ANPHandleService host must be this Handle provider")
            if local_part in RESERVED_HANDLES:
                raise _error(422, "reserved_handle", "Handle local-part is reserved")
            handle = f"{local_part}.{normalized_domain}"
        if exact:
            canonical = f"https://{provider}/.well-known/handle/{local_part}"
            if local_part is None or endpoint != canonical or parsed_url.path != f"/.well-known/handle/{local_part}":
                raise _error(422, "invalid_service", "WBA service endpoint is not the canonical resolution URL")
            stored_endpoint = canonical
        else:
            stored_endpoint = f"https://{provider}{parsed_url.path or '/'}"
        found = HandleDeclaration(
            local_part=local_part or "",
            handle=handle,
            endpoint=stored_endpoint,
            exact=exact,
        )
    return found


def _require_known_ids(ids: tuple[str, ...], methods: dict[str, dict[str, Any]], field: str) -> None:
    for method_id in ids:
        if method_id not in methods:
            raise _error(422, "invalid_did_document", f"{field} references an unknown verification method")


def validate_document(document: dict[str, Any], settings: Settings) -> ValidatedDocument:
    """Validate a document the server is willing to store and authenticate."""
    if not isinstance(document, dict) or not isinstance(document.get("id"), str):
        raise _error(422, "invalid_did_document", "Document id is required")
    _reject_lifecycle(document)
    parsed = parse_did(document["id"])
    hosted(parsed, domain=settings.public_did_domain, port=settings.public_did_port)
    if parsed.is_root and settings.root_method != parsed.method:
        raise _error(422, "root_did_disabled", "Root DID publication is not enabled for this method")
    web = parsed.method == "web"
    _contexts(document, web=web)
    methods = _check_methods(document, parsed.original, web=web)
    authentication = _relationship(document, "authentication", parsed.original)
    assertion = _relationship(document, "assertionMethod", parsed.original)
    if not authentication:
        raise _error(422, "invalid_did_document", "authentication must authorize at least one key")
    _require_known_ids(authentication, methods, "authentication")
    _require_known_ids(assertion, methods, "assertionMethod")
    if not web:
        if not parsed.is_e1_path and not parsed.is_root:
            raise _error(422, "invalid_did_document", "WBA path document is not an E1 identity")
        proof = document.get("proof")
        if parsed.is_e1_path:
            if not isinstance(proof, dict):
                raise _error(422, "invalid_proof", "WBA E1 document proof is required")
            if proof.get("type") != "DataIntegrityProof" or proof.get("cryptosuite") != "eddsa-jcs-2022":
                raise _error(422, "invalid_proof", "WBA E1 proof must be DataIntegrityProof eddsa-jcs-2022")
            if proof.get("proofPurpose") != "assertionMethod":
                raise _error(422, "invalid_proof", "WBA E1 proof purpose must be assertionMethod")
            proof_method = _absolute_method_id(proof.get("verificationMethod"), parsed.original, "proof")
            if proof_method not in assertion:
                raise _error(422, "invalid_proof", "WBA E1 proof key must be authorized by assertionMethod")
            if not validate_did_document_binding(document):
                raise _error(422, "invalid_proof", "WBA E1 fingerprint or document proof did not verify")
    declaration = _handle_declaration(document, parsed, settings)
    if declaration and declaration.exact and parsed.host != settings.handle_provider_domain:
        raise _error(422, "invalid_service", "WBA Handle provider host must match the DID hostname")
    return ValidatedDocument(
        parsed=parsed,
        authentication_ids=authentication,
        assertion_ids=assertion,
        declaration=declaration,
    )


def declaration_satisfies(
    current: HandleDeclaration | None,
    *,
    local_part: str,
    exact: bool,
    provider_domain: str,
) -> bool:
    """Return whether a document still satisfies one binding's method rule."""
    if current is None:
        return False
    parsed = urlsplit(current.endpoint)
    if parsed.scheme != "https" or (parsed.hostname or "").lower() != provider_domain:
        return False
    if exact:
        expected = f"https://{provider_domain}/.well-known/handle/{local_part}"
        return current.exact and current.local_part == local_part and current.endpoint == expected
    if current.local_part and current.local_part != local_part:
        return False
    return True
