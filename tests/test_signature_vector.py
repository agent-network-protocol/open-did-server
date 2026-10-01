"""Signature vectors whose base and digest are not produced by the SDK signer."""

import base64
import hashlib
import time
from urllib.parse import urlsplit

from open_did_server.signatures import PROFILE_ECHO
from tests.harness import started
from tests.test_http_api import _grant, _publish, _web

BODY = b'{"hello":"vector"}'
DIGEST = "sha-256=:pY6BR0NZSvSfPExR0TrlXPyGrAwda96+tKyvsnJWEpk=:"


def _params(components, created, expires, nonce, keyid, order) -> str:
    values = {
        "created": f"created={created}",
        "expires": f"expires={expires}",
        "nonce": f'nonce="{nonce}"',
        "keyid": f'keyid="{keyid}"',
    }
    covered = " ".join(f'"{component}"' for component in components)
    return f"({covered});" + ";".join(values[name] for name in order)


def _base(method, url, created, expires, nonce, keyid) -> bytes:
    """RFC 9421 signature base built in this test, not by generate_http_signature_headers."""
    headers = {
        "@method": method.upper(),
        "@target-uri": url,
        "@authority": urlsplit(url).netloc,
        "content-digest": DIGEST,
        "content-type": "application/json",
    }
    params = _params(PROFILE_ECHO, created, expires, nonce, keyid, ("created", "expires", "nonce", "keyid"))
    lines = [f'"{name}": {headers[name]}' for name in PROFILE_ECHO]
    lines.append(f'"@signature-params": {params}')
    return "\n".join(lines).encode("utf-8"), params


def _wire(key, base: bytes, params: str) -> dict[str, str]:
    signature = base64.b64encode(key.sign(base)).decode("ascii")
    return {
        "Content-Type": "application/json",
        "Content-Digest": DIGEST,
        "Signature-Input": f"sig1={params}",
        "Signature": f"sig1=:{signature}:",
    }


def test_independent_echo_vector_and_reordered_parameters():
    digest = "sha-256=:" + base64.b64encode(hashlib.sha256(BODY).digest()).decode("ascii") + ":"
    assert digest == DIGEST
    with started() as server:
        _grant_id, token = _grant(server, web=["identities/web/bob"])
        web, key = _web()
        assert _publish(server, web, key, token)[0].status_code == 201
        url = server.base + "/examples/auth/echo"
        created = int(time.time())
        keyid = web["authentication"][0]
        base, params = _base("POST", url, created, created + 300, "ab" * 16, keyid)
        assert f'"content-digest": {DIGEST}'.encode() in base
        print("SIGNATURE_BASE_BEGIN")
        print(base.decode("utf-8"))
        print("SIGNATURE_BASE_END")
        print(f"CONTENT_DIGEST {DIGEST}")
        accepted = server.client.post(url, content=BODY, headers=_wire(key, base, params))
        assert accepted.status_code == 200, accepted.text
        assert accepted.json()["body"] == {"hello": "vector"}
        assert accepted.json()["did"] == web["id"]

        reordered_base, _canonical = _base("POST", url, created, created + 300, "cd" * 16, keyid)
        reordered_params = _params(
            PROFILE_ECHO,
            created,
            created + 300,
            "cd" * 16,
            keyid,
            ("keyid", "created", "expires", "nonce"),
        )
        rejected = server.client.post(url, content=BODY, headers=_wire(key, reordered_base, reordered_params))
        assert rejected.status_code == 401, rejected.text
        assert rejected.json()["error"] == "invalid_request"
