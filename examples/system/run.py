"""Named system-test cases against a running Open DID Server.

This process only speaks HTTP. It reuses the demo client's publish and bind
requests, then reads the standard document, queries the Handle, and sends a
signed whoami. The same whoami signature is sent again and must be rejected.

HTTPS calls keep the default certificate verification. Document resolution does
not use ``base_url_override``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "examples" / "client"))

import run as demo  # noqa: E402

from open_did_server.identity import create_wba_identity, create_web_identity, private_key_pem, sign_headers
from open_did_server.signatures import PROFILE_ECHO, PROFILE_WHOAMI


def main() -> None:
    parser = argparse.ArgumentParser(description="Run named Open DID Server system-test cases over HTTP")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--domain", default="example.test")
    parser.add_argument("--provider", default=None)
    parser.add_argument("--wba-handle", default="alice")
    parser.add_argument("--web-handle", default="bob")
    parser.add_argument("--out", default="./data/system-demo")
    args = parser.parse_args()
    for name in (
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
    ):
        os.environ.pop(name, None)

    provider = args.provider or args.domain
    base = args.base_url.rstrip("/")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    os.chmod(out, 0o700)
    failures = 0

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
    demo._write_secret(out / "wba-private.pem", private_key_pem(wba_key))
    demo._write_secret(out / "web-private.pem", private_key_pem(web_key))

    wba_whoami_headers: dict[str, str] | None = None
    for label, document, key, handle in (
        ("wba", wba, wba_key, args.wba_handle),
        ("web", web, web_key, args.web_handle),
    ):
        created = demo._created(document)
        if not _report(
            f"{label}-create",
            created["did"] == document["id"] and bool(created["authentication"]),
            id=created["did"],
            authentication=created["authentication"],
            published=False,
        ):
            failures += 1
            continue
        status, uploaded = demo.signed_publish(base, args.token, document, key)
        uploaded_id = uploaded.get("did")
        if not _report(
            f"{label}-publish",
            status == 201 and uploaded_id == document["id"],
            http=status,
            id=uploaded_id,
            published=True,
        ):
            failures += 1
            continue
        read_url = base + str(uploaded["content_path"])
        read_status, served = demo.exchange("GET", read_url, None, {"Accept": "application/did+json"})
        served_id = served.get("id")
        if not _report(
            f"{label}-read",
            read_status == 200 and served_id == document["id"],
            http=read_status,
            id=served_id,
            matched=served_id == document["id"],
        ):
            failures += 1
        bind_status, bound = demo.signed_bind(base, args.token, handle, document, key)
        if bind_status not in {200, 201}:
            failures += int(
                not _report(f"{label}-handle", False, http=bind_status, error=bound.get("error"))
            )
            continue
        handle_status, forward = demo.exchange(
            "GET",
            f"{base}/.well-known/handle/{handle}",
            None,
            {"Accept": "application/json"},
        )
        if not _report(
            f"{label}-handle",
            handle_status == 200 and forward.get("did") == document["id"] and forward.get("status") == "active",
            http=handle_status,
            did=forward.get("did"),
            status=forward.get("status"),
            matched=forward.get("did") == document["id"],
        ):
            failures += 1
        whoami_url = f"{base}/examples/auth/whoami"
        headers = sign_headers(document, key, "GET", whoami_url, PROFILE_WHOAMI)
        whoami_status, whoami = demo.exchange("GET", whoami_url, None, headers)
        authenticated = (
            whoami_status == 200
            and whoami.get("did") == document["id"]
            and whoami.get("auth_scheme") == "http_signatures"
        )
        if not _report(
            f"{label}-whoami",
            authenticated,
            http=whoami_status,
            did=whoami.get("did"),
            auth_scheme=whoami.get("auth_scheme"),
            authenticated=authenticated,
        ):
            failures += 1
        echo_url = f"{base}/examples/auth/echo"
        echo_body = demo._dumps({"hello": label})
        echo_status, echo = demo.exchange(
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
        if not _report(
            f"{label}-echo",
            echo_status == 200
            and echo.get("did") == document["id"]
            and echo.get("auth_scheme") == "http_signatures"
            and echo.get("body") == {"hello": label},
            http=echo_status,
            did=echo.get("did"),
            auth_scheme=echo.get("auth_scheme"),
            body=echo.get("body"),
        ):
            failures += 1
        if label == "wba":
            wba_whoami_headers = headers

    if wba_whoami_headers is None:
        failures += int(not _report("whoami-replay", False, http=0, error="missing-signature"))
    else:
        replay_status, replay = demo.exchange(
            "GET",
            f"{base}/examples/auth/whoami",
            None,
            wba_whoami_headers,
        )
        rejected = replay_status == 401 and replay.get("error") == "invalid_nonce"
        _report(
            "whoami-replay",
            rejected,
            http=replay_status,
            error=replay.get("error"),
            outcome="rejected" if rejected else "fail",
        )
        if not rejected:
            failures += 1
    if failures:
        raise SystemExit(1)


def _report(case: str, ok: bool, **fields) -> bool:
    outcome = fields.pop("outcome", None)
    if outcome is None:
        outcome = "pass" if ok else "fail"
    print(json.dumps({"case": case, "result": outcome, **fields}, ensure_ascii=False), flush=True)
    return ok


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
