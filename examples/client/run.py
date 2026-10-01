"""Separate-process client for the local Open DID Server demo.

The DID authority stays a DNS name. Signatures use the loopback base URL.
Resolution through ``base_url_override`` is labeled a development demo.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from open_did_server.identity import (
    create_wba_identity,
    create_web_identity,
    private_key_pem,
    resign_wba_document,
    sign_headers,
)
from open_did_server.signatures import PROFILE_CREATE, PROFILE_ECHO, PROFILE_UPDATE, PROFILE_WHOAMI


def main() -> None:
    parser = argparse.ArgumentParser(description="Publish two demo DIDs and send signed requests")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--out", default="./data/demo")
    parser.add_argument("--domain", default="example.test")
    parser.add_argument("--provider", default=None)
    parser.add_argument("--wba-handle", default="alice")
    parser.add_argument("--web-handle", default="bob")
    parser.add_argument("--verify-https", action="store_true")
    args = parser.parse_args()
    provider = args.provider or args.domain
    base = args.base_url.rstrip("/")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    os.chmod(out, 0o700)
    # Ambient proxies, including SOCKS ALL_PROXY, must not intercept loopback.
    for name in (
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
    ):
        os.environ.pop(name, None)

    wba, wba_key = create_wba_identity(
        args.domain,
        ["identities", "wba", args.wba_handle],
        args.wba_handle,
        provider,
    )
    web, web_key = create_web_identity(
        args.domain,
        ["identities", "web", args.web_handle],
        args.web_handle,
        provider,
    )
    _write_secret(out / "wba-private.pem", private_key_pem(wba_key))
    _write_secret(out / "web-private.pem", private_key_pem(web_key))
    (out / "wba-did.json").write_text(json.dumps(wba, indent=2) + "\n", encoding="utf-8")
    (out / "web-did.json").write_text(json.dumps(web, indent=2) + "\n", encoding="utf-8")
    _emit("wba_create", _created(wba))
    _emit("web_create", _created(web))

    wba_meta = _publish(base, args.token, wba, wba_key)
    web_meta = _publish(base, args.token, web, web_key)
    _emit("wba_publish", {**wba_meta, "published": True})
    _emit("web_publish", {**web_meta, "published": True})
    wba_doc = _get_json(base + wba_meta["content_path"])
    web_doc = _get_json(base + web_meta["content_path"])
    if wba_doc["id"] != wba["id"] or web_doc["id"] != web["id"]:
        raise SystemExit("served document id does not match the uploaded DID")
    _emit("wba_document", {"id": wba_doc["id"], "matched": True})
    _emit("web_document", {"id": web_doc["id"], "matched": True})

    wba_handle = _bind(base, args.token, args.wba_handle, wba, wba_key)
    web_handle = _bind(base, args.token, args.web_handle, web, web_key)
    _emit("wba_handle", wba_handle)
    _emit("web_handle", web_handle)
    _emit("wba_forward", _get_json(f"{base}/.well-known/handle/{args.wba_handle}"))
    _emit("web_forward", _get_json(f"{base}/.well-known/handle/{args.web_handle}"))
    _emit("wba_reverse", _get_json(f"{base}/api/v1/handles/by-did?did={urllib.parse.quote(wba['id'], safe='')}"))
    _emit("web_reverse", _get_json(f"{base}/api/v1/handles/by-did?did={urllib.parse.quote(web['id'], safe='')}"))

    updated = dict(wba_doc)
    updated["alsoKnownAs"] = [f"https://{provider}/.well-known/handle/{args.wba_handle}"]
    updated = resign_wba_document(updated, wba_key)
    update_body = _dumps(updated)
    update_url = f"{base}/api/v1/did-documents/{wba_meta['document_id']}"
    update_headers = sign_headers(
        wba,
        wba_key,
        "PUT",
        update_url,
        PROFILE_UPDATE,
        update_body,
        {
            "Content-Type": "application/json",
            "If-Match": wba_meta["etag"],
            "ANP-Publication-Token": args.token,
        },
    )
    updated_meta = _request("PUT", update_url, update_body, update_headers)
    _emit("wba_update", updated_meta)

    for label, document, key in (("wba", wba, wba_key), ("web", web, web_key)):
        whoami_url = f"{base}/examples/auth/whoami"
        whoami = _request(
            "GET",
            whoami_url,
            None,
            sign_headers(document, key, "GET", whoami_url, PROFILE_WHOAMI),
        )
        _emit(f"{label}_whoami", whoami)
        echo_url = f"{base}/examples/auth/echo"
        echo_body = _dumps({"hello": label})
        echo = _request(
            "POST",
            echo_url,
            echo_body,
            sign_headers(
                document,
                key,
                "POST",
                echo_url,
                PROFILE_ECHO,
                echo_body,
                {"Content-Type": "application/json"},
            ),
        )
        _emit(f"{label}_echo", echo)

    _resolve_demo(wba["id"], web["id"], base)
    if args.verify_https:
        _verify_https(provider, args.wba_handle)
    else:
        _emit(
            "production_https",
            {
                "status": "not-run",
                "note": "Local HTTP and base_url_override are a development demo, not production HTTPS acceptance.",
            },
        )


def _created(document: dict) -> dict:
    """Public fields of a DID that exists only on the client so far."""
    authentication = document.get("authentication") or []
    return {
        "did": document.get("id"),
        "authentication": authentication[0] if authentication else None,
        "published": False,
    }


def signed_publish(base: str, token: str, document: dict, key) -> tuple[int, dict]:
    """POST a candidate document. Callers share this request with the demo client."""
    body = _dumps(document)
    url = f"{base}/api/v1/did-documents"
    headers = sign_headers(
        document,
        key,
        "POST",
        url,
        PROFILE_CREATE,
        body,
        {"Content-Type": "application/json", "ANP-Publication-Token": token},
    )
    return exchange("POST", url, body, headers)


def signed_bind(base: str, token: str, local_part: str, document: dict, key) -> tuple[int, dict]:
    """PUT a Handle binding with the same request the demo client sends."""
    body = _dumps({"did": document["id"], "status": "active"})
    url = f"{base}/api/v1/handles/{local_part}"
    headers = sign_headers(
        document,
        key,
        "PUT",
        url,
        PROFILE_CREATE,
        body,
        {"Content-Type": "application/json", "ANP-Publication-Token": token},
    )
    return exchange("PUT", url, body, headers)


def _publish(base: str, token: str, document: dict, key) -> dict:
    return _require_success(*signed_publish(base, token, document, key), "POST", f"{base}/api/v1/did-documents")


def _bind(base: str, token: str, local_part: str, document: dict, key) -> dict:
    return _require_success(
        *signed_bind(base, token, local_part, document, key),
        "PUT",
        f"{base}/api/v1/handles/{local_part}",
    )


def _resolve_demo(wba_did: str, web_did: str, base: str) -> None:
    from anp.authentication.did_resolver import resolve_did_document_sync

    for label, did in (("wba", wba_did), ("web", web_did)):
        resolved = resolve_did_document_sync(did, base_url_override=base, verify_ssl=True)
        _emit(
            f"{label}_resolve",
            {
                "id": resolved.get("id"),
                "resolution": "development-demo",
                "base_url_override": base,
                "matched": resolved.get("id") == did,
            },
        )


def _verify_https(provider: str, local_part: str) -> None:
    url = f"https://{provider}/.well-known/handle/{local_part}"
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            _emit("production_https", {"status": response.status, "url": url})
    except Exception as exc:
        _emit(
            "production_https",
            {
                "status": "not-completed",
                "url": url,
                "note": "Public HTTPS verification did not succeed. Local results are not a substitute.",
                "error": exc.__class__.__name__,
            },
        )
        raise SystemExit(2)


def exchange(method: str, url: str, body: bytes | None, headers: dict[str, str], timeout: int = 20) -> tuple[int, dict]:
    """Send one HTTP request. Certificate checks stay at the interpreter default."""
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            status = response.status
            payload = response.read()
    except urllib.error.HTTPError as exc:
        status = exc.code
        payload = exc.read()
    text = payload.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text) if text else {}
    except json.JSONDecodeError:
        parsed = {"raw": text}
    if not isinstance(parsed, dict):
        parsed = {"value": parsed}
    return status, parsed


def _require_success(status: int, payload: dict, method: str, url: str) -> dict:
    if status >= 400:
        raise SystemExit(f"{method} {url} failed: {status} {json.dumps(payload, ensure_ascii=False)}")
    return payload


def _request(method: str, url: str, body: bytes | None, headers: dict[str, str]) -> dict:
    return _require_success(*exchange(method, url, body, headers), method, url)


def _get_json(url: str) -> dict:
    return _request("GET", url, None, {"Accept": "application/did+json"})


def _dumps(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _write_secret(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    os.chmod(path, 0o600)


def _emit(step: str, payload: dict) -> None:
    print(json.dumps({"step": step, **payload}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
