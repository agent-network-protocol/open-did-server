"""Local WBA E1 and Web identity construction. Private keys stay with the caller."""

from __future__ import annotations

from typing import Any

from anp.authentication.did_wba import create_did_wba_document
from anp.authentication.http_signatures import generate_http_signature_headers
from anp.proof.proof import generate_w3c_proof
from anp.wns.binding import build_handle_service_entry
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat, load_pem_private_key

import base64


def create_wba_identity(
    hostname: str,
    path_segments: list[str],
    handle_local: str,
    provider_domain: str,
    port: int | None = None,
) -> tuple[dict[str, Any], Ed25519PrivateKey]:
    """Build an E1 document whose proof already covers the Handle service entry.

    ``port`` is the public DID port. It is omitted from the DID when it is 443.
    The Handle resolution URL stays on the provider hostname with no port.
    """
    services = [
        {
            "id": "#handle",
            "type": "ANPHandleService",
            "serviceEndpoint": f"https://{provider_domain}/.well-known/handle/{handle_local}",
        }
    ]
    document, keys = create_did_wba_document(
        hostname,
        port=None if port in (None, 443) else port,
        path_segments=list(path_segments),
        services=services,
        did_profile="e1",
        enable_e2ee=False,
    )
    private = load_pem_private_key(keys["key-1"][0], password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise TypeError("WBA E1 authentication key must be Ed25519")
    return document, private


def create_web_identity(
    hostname: str,
    path_segments: list[str],
    handle_local: str,
    provider_domain: str,
    private_key: Ed25519PrivateKey | None = None,
    port: int | None = None,
) -> tuple[dict[str, Any], Ed25519PrivateKey]:
    """Build the one Web document shape this server accepts."""
    private = private_key or Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    x_value = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    authority = hostname if port in (None, 443) else f"{hostname}%3A{port}"
    did = "did:web:" + ":".join([authority, *path_segments])
    key_id = f"{did}#key-1"
    document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": key_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": {"crv": "Ed25519", "kty": "OKP", "x": x_value},
            }
        ],
        "authentication": [key_id],
        "assertionMethod": [key_id],
        "service": [build_handle_service_entry(did, handle_local, provider_domain)],
    }
    return document, private


def resign_wba_document(
    document: dict[str, Any],
    private_key: Ed25519PrivateKey,
    verification_method: str | None = None,
) -> dict[str, Any]:
    """Re-prove a changed WBA document. The HTTP signature does not replace this proof."""
    method_id = verification_method or _first_authentication(document)
    payload = {key: value for key, value in document.items() if key != "proof"}
    return generate_w3c_proof(
        payload,
        private_key,
        verification_method=method_id,
        proof_purpose="assertionMethod",
        proof_type="DataIntegrityProof",
        cryptosuite="eddsa-jcs-2022",
    )


def sign_headers(
    document: dict[str, Any],
    private_key: Ed25519PrivateKey,
    method: str,
    url: str,
    components: tuple[str, ...] | list[str],
    body: bytes | None = None,
    extra_headers: dict[str, str] | None = None,
    keyid: str | None = None,
) -> dict[str, str]:
    """Return the business headers merged with the SDK signature headers."""
    headers = dict(extra_headers or {})
    signed = generate_http_signature_headers(
        document,
        url,
        method,
        lambda data, _fragment: private_key.sign(data),
        headers=headers,
        body=body,
        covered_components=list(components),
        keyid=keyid,
    )
    merged = dict(headers)
    merged.update(signed)
    return merged


def private_key_pem(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def _first_authentication(document: dict[str, Any]) -> str:
    authentication = document.get("authentication") or []
    first = authentication[0]
    if isinstance(first, str):
        return first
    return str(first["id"])
