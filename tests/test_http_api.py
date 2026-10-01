import json
import socket

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from open_did_server.identity import create_wba_identity, create_web_identity, resign_wba_document, sign_headers
from open_did_server.signatures import PROFILE_CREATE, PROFILE_ECHO, PROFILE_UPDATE, PROFILE_WHOAMI
from tests.harness import started

import base64


def _dumps(value) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _grant(server, owner="owner-a", wba=None, web=None, handles=None):
    return server.service.create_grant(
        owner,
        wba_paths=wba or [],
        web_paths=web or [],
        handles=handles or [],
    )


def _publish(server, document, key, token, extra_headers=None):
    body = _dumps(document)
    url = server.base + "/api/v1/did-documents"
    headers = {"Content-Type": "application/json", "ANP-Publication-Token": token}
    if extra_headers:
        headers.update(extra_headers)
    signed = sign_headers(document, key, "POST", url, PROFILE_CREATE, body, headers)
    response = server.client.post(url, content=body, headers=signed)
    return response, body


def _web(local="bob", segments=None):
    return create_web_identity("example.test", segments or ["identities", "web", local], local, "example.test")


def _wba(local="alice"):
    return create_wba_identity("example.test", ["identities", "wba", local], local, "example.test")


def test_wba_and_web_publish_read_handle_and_whoami():
    with started() as server:
        _grant_id, token = _grant(
            server,
            wba=["identities/wba/alice"],
            web=["identities/web/bob"],
            handles=["alice.example.test", "bob.example.test"],
        )
        wba, wba_key = _wba()
        web, web_key = _web()
        published, raw = _publish(server, wba, wba_key, token)
        assert published.status_code == 201, published.text
        meta = published.json()
        fetched = server.client.get(server.base + meta["content_path"])
        assert fetched.status_code == 200
        assert fetched.headers["content-type"].startswith("application/did+json")
        assert fetched.json()["id"] == wba["id"]
        assert fetched.content == raw
        head = server.client.head(server.base + meta["content_path"])
        assert head.status_code == 200
        assert head.headers["etag"] == fetched.headers["etag"]
        assert int(head.headers["content-length"]) == len(raw)
        cached = server.client.get(
            server.base + meta["content_path"],
            headers={"If-None-Match": fetched.headers["etag"]},
        )
        assert cached.status_code == 304

        web_response, _web_raw = _publish(server, web, web_key, token)
        assert web_response.status_code == 201, web_response.text
        assert server.client.get(server.base + web_response.json()["content_path"]).json()["id"] == web["id"]

        handle_body = _dumps({"did": wba["id"], "status": "active"})
        handle_url = server.base + "/api/v1/handles/alice"
        handle_headers = sign_headers(
            wba,
            wba_key,
            "PUT",
            handle_url,
            PROFILE_CREATE,
            handle_body,
            {"Content-Type": "application/json", "ANP-Publication-Token": token},
        )
        created = server.client.put(handle_url, content=handle_body, headers=handle_headers)
        assert created.status_code == 201, created.text
        assert created.json()["verification"] == "declaration-consistent"
        assert created.json()["binding_generation"] == "1"
        forward = server.client.get(server.base + "/.well-known/handle/alice")
        reverse = server.client.get(server.base + "/api/v1/handles/by-did", params={"did": wba["id"]})
        assert forward.status_code == reverse.status_code == 200
        assert forward.json()["did"] == reverse.json()["did"] == wba["id"]

        whoami_url = server.base + "/examples/auth/whoami"
        whoami_headers = sign_headers(wba, wba_key, "GET", whoami_url, PROFILE_WHOAMI)
        whoami_headers["ANP-Publication-Token"] = "not-a-did-credential"
        whoami = server.client.get(whoami_url, headers=whoami_headers)
        assert whoami.status_code == 200
        assert whoami.json()["did"] == wba["id"]
        assert "token" not in whoami.text
        replay = server.client.get(whoami_url, headers=whoami_headers)
        assert replay.status_code == 401
        assert replay.json()["error"] == "invalid_nonce"
        assert 'error="invalid_nonce"' in replay.headers["www-authenticate"]


def test_conflicts_permissions_tampering_and_handle_state():
    with started() as server:
        _grant_id, token = _grant(
            server,
            wba=["identities/wba/alice"],
            web=["identities/web/bob", "identities/web/carol"],
            handles=["alice.example.test", "bob.example.test"],
        )
        _other, other_token = _grant(server, owner="owner-b", web=["identities/web/carol"], handles=["carol.example.test"])
        wba, wba_key = _wba()
        first, _raw = _publish(server, wba, wba_key, token)
        assert first.status_code == 201
        second_doc, second_key = _wba()
        second, _raw = _publish(server, second_doc, second_key, token)
        assert second.status_code == 409
        assert second.json()["error"] == "stable_subject_path_reserved"

        web, web_key = _web()
        web_response, web_raw = _publish(server, web, web_key, token)
        assert web_response.status_code == 201, web_response.text
        upper = json.loads(web_raw)
        upper["id"] = upper["id"].replace("example.test", "Example.Test")
        for method in upper["verificationMethod"]:
            method["id"] = method["id"].replace("example.test", "Example.Test")
            method["controller"] = upper["id"]
        upper["authentication"] = [item.replace("example.test", "Example.Test") for item in upper["authentication"]]
        upper["assertionMethod"] = [item.replace("example.test", "Example.Test") for item in upper["assertionMethod"]]
        upper["service"][0]["id"] = upper["service"][0]["id"].replace("example.test", "Example.Test")
        collided, _raw = _publish(server, upper, web_key, token)
        assert collided.status_code == 409
        assert collided.json()["error"] == "canonical_url_conflict"

        ported = json.loads(web_raw)
        ported["id"] = "did:web:example.test%3A443:identities:web:carol"
        ported["verificationMethod"][0]["id"] = ported["id"] + "#key-1"
        ported["verificationMethod"][0]["controller"] = ported["id"]
        ported["authentication"] = [ported["id"] + "#key-1"]
        ported["assertionMethod"] = [ported["id"] + "#key-1"]
        ported["service"][0]["id"] = ported["id"] + "#handle"
        # carol path is different, so use bob's canonical collision instead
        ported["id"] = web["id"].replace("did:web:example.test", "did:web:example.test%3A443")
        ported["verificationMethod"][0]["id"] = ported["id"] + "#key-1"
        ported["verificationMethod"][0]["controller"] = ported["id"]
        ported["authentication"] = [ported["id"] + "#key-1"]
        ported["assertionMethod"] = [ported["id"] + "#key-1"]
        ported["service"][0]["id"] = ported["id"] + "#handle"
        explicit_port, _raw = _publish(server, ported, web_key, token)
        assert explicit_port.status_code == 409
        assert explicit_port.json()["error"] == "canonical_url_conflict"

        stolen, _raw = _publish(server, web, web_key, other_token)
        assert stolen.status_code == 403
        assert stolen.json()["error"] == "publication_forbidden"

        broken = json.loads(web_raw)
        broken["proof"] = {"type": "Ed25519Signature2020"}
        # Web documents do not require a proof. Break the WBA document instead.
        broken_wba = json.loads(_dumps(wba))
        broken_wba["proof"]["proofValue"] = "AAAA"
        rejected, _raw = _publish(server, broken_wba, wba_key, token)
        assert rejected.status_code == 422
        assert rejected.json()["error"] == "invalid_proof"

        meta = web_response.json()
        updated = json.loads(web_raw)
        updated["alsoKnownAs"] = ["https://example.test/bob"]
        update_body = _dumps(updated)
        update_url = server.base + "/api/v1/did-documents/" + meta["document_id"]
        missing = server.client.put(
            update_url,
            content=update_body,
            headers=sign_headers(
                web,
                web_key,
                "PUT",
                update_url,
                PROFILE_CREATE,
                update_body,
                {"Content-Type": "application/json", "ANP-Publication-Token": token},
            ),
        )
        assert missing.status_code == 428
        assert missing.json()["error"] == "precondition_required"

        good_headers = sign_headers(
            web,
            web_key,
            "PUT",
            update_url,
            PROFILE_UPDATE,
            update_body,
            {
                "Content-Type": "application/json",
                "If-Match": meta["etag"],
                "ANP-Publication-Token": token,
            },
        )
        tampered = dict(good_headers)
        tampered["If-Match"] = '"v9"'
        changed_match = server.client.put(update_url, content=update_body, headers=tampered)
        assert changed_match.status_code == 401
        assert changed_match.json()["error"] == "invalid_signature"

        tampered_type = dict(good_headers)
        tampered_type["Content-Type"] = "text/plain"
        changed_type = server.client.put(update_url, content=update_body, headers=tampered_type)
        assert changed_type.status_code == 401

        changed_body = server.client.put(update_url, content=update_body + b" ", headers=good_headers)
        assert changed_body.status_code == 401
        assert changed_body.json()["error"] == "invalid_content_digest"

        wrong_token_headers = sign_headers(
            web,
            web_key,
            "PUT",
            update_url,
            PROFILE_UPDATE,
            update_body,
            {
                "Content-Type": "application/json",
                "If-Match": meta["etag"],
                "ANP-Publication-Token": "wrong-token",
            },
        )
        wrong_token = server.client.put(update_url, content=update_body, headers=wrong_token_headers)
        assert wrong_token.status_code == 403

        other_url = server.base + "/api/v1/did-documents/" + meta["document_id"] + "-elsewhere"
        signed_elsewhere = sign_headers(
            web,
            web_key,
            "PUT",
            other_url,
            PROFILE_UPDATE,
            update_body,
            {
                "Content-Type": "application/json",
                "If-Match": meta["etag"],
                "ANP-Publication-Token": token,
            },
        )
        wrong_target = server.client.put(update_url, content=update_body, headers=signed_elsewhere)
        assert wrong_target.status_code == 401
        assert wrong_target.json()["error"] == "invalid_signature"

        fresh_key = Ed25519PrivateKey.generate()
        raw_public = fresh_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        x_value = base64.urlsafe_b64encode(raw_public).decode("ascii").rstrip("=")
        foreign = json.loads(web_raw)
        foreign_id = foreign["id"] + "-candidate"
        # Keep the published id; the new key is only in the update body.
        new_key_id = foreign["id"] + "#key-candidate"
        foreign["verificationMethod"].append(
            {
                "id": new_key_id,
                "type": "JsonWebKey2020",
                "controller": foreign["id"],
                "publicKeyJwk": {"crv": "Ed25519", "kty": "OKP", "x": x_value},
            }
        )
        foreign["authentication"] = [new_key_id]
        candidate_body = _dumps(foreign)
        candidate_headers = sign_headers(
            foreign,
            fresh_key,
            "PUT",
            update_url,
            PROFILE_UPDATE,
            candidate_body,
            {
                "Content-Type": "application/json",
                "If-Match": meta["etag"],
                "ANP-Publication-Token": token,
            },
            keyid=new_key_id,
        )
        candidate = server.client.put(update_url, content=candidate_body, headers=candidate_headers)
        assert candidate.status_code == 401
        assert candidate.json()["error"] == "invalid_verification_method"

        applied = server.client.put(update_url, content=update_body, headers=good_headers)
        assert applied.status_code == 200, applied.text
        assert applied.json()["version"] == 2

        outsider = json.loads(web_raw)
        second_key = Ed25519PrivateKey.generate()
        second_raw = second_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        second_x = base64.urlsafe_b64encode(second_raw).decode("ascii").rstrip("=")
        second_id = outsider["id"] + "#key-2"
        outsider["verificationMethod"].append(
            {
                "id": second_id,
                "type": "JsonWebKey2020",
                "controller": outsider["id"],
                "publicKeyJwk": {"crv": "Ed25519", "kty": "OKP", "x": second_x},
            }
        )
        purpose_body = _dumps(outsider)
        purpose_url = server.base + "/api/v1/did-documents/" + applied.json()["document_id"]
        purpose_headers = sign_headers(
            outsider,
            web_key,
            "PUT",
            purpose_url,
            PROFILE_UPDATE,
            purpose_body,
            {
                "Content-Type": "application/json",
                "If-Match": applied.json()["etag"],
                "ANP-Publication-Token": token,
            },
        )
        # The request is signed by the published authentication key while adding key-2.
        added = server.client.put(purpose_url, content=purpose_body, headers=purpose_headers)
        assert added.status_code == 200, added.text
        whoami_url = server.base + "/examples/auth/whoami"
        unauthenticated = sign_headers(outsider, second_key, "GET", whoami_url, PROFILE_WHOAMI, keyid=second_id)
        denied = server.client.get(whoami_url, headers=unauthenticated)
        assert denied.status_code == 401
        assert denied.json()["error"] == "invalid_verification_method"

        bind_body = _dumps({"did": wba["id"], "status": "active"})
        bind_url = server.base + "/api/v1/handles/alice"
        bound = server.client.put(
            bind_url,
            content=bind_body,
            headers=sign_headers(
                wba,
                wba_key,
                "PUT",
                bind_url,
                PROFILE_CREATE,
                bind_body,
                {"Content-Type": "application/json", "ANP-Publication-Token": token},
            ),
        )
        assert bound.status_code == 201, bound.text
        removed = json.loads(_dumps(wba))
        removed.pop("service")
        removed = resign_wba_document(removed, wba_key)
        remove_body = _dumps(removed)
        remove_url = server.base + "/api/v1/did-documents/" + first.json()["document_id"]
        blocked = server.client.put(
            remove_url,
            content=remove_body,
            headers=sign_headers(
                wba,
                wba_key,
                "PUT",
                remove_url,
                PROFILE_UPDATE,
                remove_body,
                {
                    "Content-Type": "application/json",
                    "If-Match": first.json()["etag"],
                    "ANP-Publication-Token": token,
                },
            ),
        )
        assert blocked.status_code == 409
        assert blocked.json()["error"] == "active_handle_declaration_conflict"

        suspend_body = _dumps({"did": wba["id"], "status": "suspended"})
        suspended = server.client.put(
            bind_url,
            content=suspend_body,
            headers=sign_headers(
                wba,
                wba_key,
                "PUT",
                bind_url,
                PROFILE_UPDATE,
                suspend_body,
                {
                    "Content-Type": "application/json",
                    "If-Match": bound.json()["etag"],
                    "ANP-Publication-Token": token,
                },
            ),
        )
        assert suspended.status_code == 200, suspended.text
        assert suspended.json()["binding_generation"] == "2"
        visible = server.client.get(server.base + "/.well-known/handle/alice")
        assert visible.status_code == 200
        assert visible.json()["status"] == "suspended"
        from anp.wns.models import HandleResolutionDocument

        parsed = HandleResolutionDocument.model_validate(visible.json())
        assert parsed.status.value == "suspended"
        repeat_body = _dumps({"did": wba["id"], "status": "suspended"})
        repeated = server.client.put(
            bind_url,
            content=repeat_body,
            headers=sign_headers(
                wba,
                wba_key,
                "PUT",
                bind_url,
                PROFILE_UPDATE,
                repeat_body,
                {
                    "Content-Type": "application/json",
                    "If-Match": suspended.json()["etag"],
                    "ANP-Publication-Token": token,
                },
            ),
        )
        assert repeated.status_code == 200
        assert repeated.json()["binding_generation"] == "2"
        stale = server.client.put(
            bind_url,
            content=repeat_body,
            headers=sign_headers(
                wba,
                wba_key,
                "PUT",
                bind_url,
                PROFILE_UPDATE,
                repeat_body,
                {
                    "Content-Type": "application/json",
                    "If-Match": '"g01"',
                    "ANP-Publication-Token": token,
                },
            ),
        )
        assert stale.status_code == 400
        assert stale.json()["error"] == "invalid_precondition"

        revoke_body = _dumps({"did": wba["id"], "status": "revoked"})
        revoked = server.client.put(
            bind_url,
            content=revoke_body,
            headers=sign_headers(
                wba,
                wba_key,
                "PUT",
                bind_url,
                PROFILE_UPDATE,
                revoke_body,
                {
                    "Content-Type": "application/json",
                    "If-Match": suspended.json()["etag"],
                    "ANP-Publication-Token": token,
                },
            ),
        )
        assert revoked.status_code == 200, revoked.text
        assert server.client.get(server.base + "/.well-known/handle/alice").status_code == 410
        assert server.client.get(server.base + "/api/v1/handles/by-did", params={"did": wba["id"]}).status_code == 410
        restore_body = _dumps({"did": wba["id"], "status": "active"})
        restored = server.client.put(
            bind_url,
            content=restore_body,
            headers=sign_headers(
                wba,
                wba_key,
                "PUT",
                bind_url,
                PROFILE_UPDATE,
                restore_body,
                {
                    "Content-Type": "application/json",
                    "If-Match": revoked.json()["etag"],
                    "ANP-Publication-Token": token,
                },
            ),
        )
        assert restored.status_code == 409
        assert restored.json()["error"] == "handle_revoked"


def test_local_suspension_does_not_resume_the_handle_and_maintenance_keeps_documents():
    with started() as server:
        _grant_id, token = _grant(
            server,
            web=["identities/web/bob"],
            handles=["bob.example.test"],
        )
        web, web_key = _web()
        published, _raw = _publish(server, web, web_key, token)
        assert published.status_code == 201
        bind_body = _dumps({"did": web["id"], "status": "active"})
        bind_url = server.base + "/api/v1/handles/bob"
        bound = server.client.put(
            bind_url,
            content=bind_body,
            headers=sign_headers(
                web,
                web_key,
                "PUT",
                bind_url,
                PROFILE_CREATE,
                bind_body,
                {"Content-Type": "application/json", "ANP-Publication-Token": token},
            ),
        )
        assert bound.status_code == 201
        assert bound.json()["verification"] == "web-provider-domain"
        assert server.service.set_auth_status(web["id"], "suspended") == 1
        visible = server.client.get(server.base + "/.well-known/handle/bob")
        assert visible.json()["status"] == "suspended"
        document = server.client.get(server.base + published.json()["content_path"])
        assert document.status_code == 200
        whoami_url = server.base + "/examples/auth/whoami"
        denied = server.client.get(whoami_url, headers=sign_headers(web, web_key, "GET", whoami_url, PROFILE_WHOAMI))
        assert denied.status_code == 403
        assert denied.json()["error"] == "local_auth_suspended"
        assert server.service.set_auth_status(web["id"], "active") == 0
        assert server.client.get(server.base + "/.well-known/handle/bob").json()["status"] == "suspended"
        resume_body = _dumps({"did": web["id"], "status": "active"})
        resumed = server.client.put(
            bind_url,
            content=resume_body,
            headers=sign_headers(
                web,
                web_key,
                "PUT",
                bind_url,
                PROFILE_UPDATE,
                resume_body,
                {
                    "Content-Type": "application/json",
                    "If-Match": '"g2"',
                    "ANP-Publication-Token": token,
                },
            ),
        )
        assert resumed.status_code == 200, resumed.text
        assert resumed.json()["status"] == "active"
        assert resumed.json()["binding_generation"] == "3"

        server.service.mark_maintenance("test")
        health = server.client.get(server.base + "/healthz")
        assert health.json()["maintenance"] is True
        assert server.client.get(server.base + published.json()["content_path"]).status_code == 200
        blocked = server.client.get(whoami_url, headers=sign_headers(web, web_key, "GET", whoami_url, PROFILE_WHOAMI))
        assert blocked.status_code == 503
        assert blocked.json()["error"] == "maintenance"
        try:
            server.service.clear_maintenance()
        except Exception as exc:
            assert "signature window" in str(exc)
        else:
            raise AssertionError("maintenance cleared too early")


def test_duplicate_signature_header_is_rejected_on_the_raw_socket():
    with started() as server:
        request = (
            f"GET /examples/auth/whoami HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{server.settings.port}\r\n"
            "Signature-Input: sig1=(\"@method\");created=1;expires=2;nonce=\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\";keyid=\"did:web:example.test:identities:web:bob#key-1\"\r\n"
            "Signature-Input: sig1=(\"@method\");created=1;expires=2;nonce=\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\";keyid=\"did:web:example.test:identities:web:bob#key-1\"\r\n"
            "Signature: sig1=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==:\r\n"
            "\r\n"
        ).encode()
        with socket.create_connection(("127.0.0.1", server.settings.port), timeout=5) as sock:
            sock.sendall(request)
            response = b""
            while b"\r\n\r\n" not in response:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        assert response.startswith(b"HTTP/1.1 401")
        assert b"invalid_request" in response


def test_untrusted_forwarded_host_does_not_change_the_signed_url():
    with started() as server:
        _grant_id, token = _grant(server, web=["identities/web/bob"])
        web, web_key = _web()
        published, _raw = _publish(server, web, web_key, token)
        assert published.status_code == 201
        whoami_url = server.base + "/examples/auth/whoami"
        headers = sign_headers(web, web_key, "GET", whoami_url, PROFILE_WHOAMI)
        headers["X-Forwarded-Host"] = "evil.example"
        headers["X-Forwarded-Proto"] = "https"
        accepted = server.client.get(whoami_url, headers=headers)
        assert accepted.status_code == 200, accepted.text
        evil_url = "https://evil.example/examples/auth/whoami"
        evil_headers = sign_headers(web, web_key, "GET", evil_url, PROFILE_WHOAMI)
        evil_headers["X-Forwarded-Host"] = "evil.example"
        evil_headers["X-Forwarded-Proto"] = "https"
        rejected = server.client.get(whoami_url, headers=evil_headers)
        assert rejected.status_code == 401


def test_public_port_stays_in_the_did_and_out_of_the_handle_url():
    with started(public_did_port=8443) as server:
        _grant_id, token = _grant(
            server,
            wba=["identities/wba/alice"],
            handles=["alice.example.test"],
        )
        document, key = create_wba_identity(
            "example.test",
            ["identities", "wba", "alice"],
            "alice",
            "example.test",
            port=8443,
        )
        assert "%3A8443" in document["id"]
        assert document["service"][0]["serviceEndpoint"] == "https://example.test/.well-known/handle/alice"
        published, raw = _publish(server, document, key, token)
        assert published.status_code == 201, published.text
        fetched = server.client.get(server.base + published.json()["content_path"])
        assert fetched.status_code == 200
        assert fetched.content == raw
        assert fetched.json()["id"] == document["id"]
        handle_body = _dumps({"did": document["id"], "status": "active"})
        handle_url = server.base + "/api/v1/handles/alice"
        response = server.client.put(
            handle_url,
            content=handle_body,
            headers=sign_headers(
                document,
                key,
                "PUT",
                handle_url,
                PROFILE_CREATE,
                handle_body,
                {"Content-Type": "application/json", "ANP-Publication-Token": token},
            ),
        )
        assert response.status_code == 201, response.text
        assert response.json()["verification"] == "declaration-consistent"
        assert "8443" not in response.json()["verification_note"]


def test_trusted_proxy_rebuilds_the_external_https_url():
    with started(trusted_proxies=("127.0.0.1/32",)) as server:
        _grant_id, token = _grant(server, web=["identities/web/bob"])
        web, web_key = _web()
        local_host = server.base.removeprefix("http://")
        published, _raw = _publish(
            server,
            web,
            web_key,
            token,
            extra_headers={"X-Forwarded-Proto": "http", "X-Forwarded-Host": local_host},
        )
        assert published.status_code == 201, published.text
        external = "https://did.example.test/examples/auth/whoami"
        headers = sign_headers(web, web_key, "GET", external, PROFILE_WHOAMI)
        headers["X-Forwarded-Proto"] = "https"
        headers["X-Forwarded-Host"] = "did.example.test"
        accepted = server.client.get(server.base + "/examples/auth/whoami", headers=headers)
        assert accepted.status_code == 200, accepted.text
        assert accepted.json()["did"] == web["id"]
