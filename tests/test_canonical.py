from open_did_server.canonical import canonical_url_for_http_path, parse_did
from open_did_server.errors import ApiError


def test_host_case_and_default_port_share_one_canonical_url():
    plain = parse_did("did:web:Example.Test:identities:web:bob")
    explicit = parse_did("did:web:example.test%3A443:identities:web:bob")
    encoded = parse_did("did:web:example.test:identities:web:%62ob")
    assert plain.canonical_url == explicit.canonical_url == encoded.canonical_url
    assert plain.original == "did:web:Example.Test:identities:web:bob"
    assert plain.host == "example.test"
    assert plain.port is None


def test_path_case_and_non_default_port_stay_distinct():
    lower = parse_did("did:web:example.test:identities:web:bob")
    upper = parse_did("did:web:example.test:identities:web:Bob")
    port = parse_did("did:web:example.test%3A8443:identities:web:bob")
    assert lower.canonical_url != upper.canonical_url
    assert port.canonical_url == "https://example.test:8443/identities/web/bob/did.json"
    assert port.host == "example.test"


def test_wba_stable_subject_drops_only_the_fingerprint():
    parsed = parse_did("did:wba:example.test:identities:wba:alice:e1_" + "A" * 43)
    assert parsed.stable_path_key == "example.test|443|identities/wba/alice"
    assert parsed.is_e1_path


def test_rejects_ip_reserved_double_encoding_and_non_e1_wba():
    for did in (
        "did:wba:127.0.0.1:identities:alice",
        "did:web:example.test:api:bob",
        "did:web:example.test:identities:%2520:bob",
        "did:wba:example.test:identities:alice",
    ):
        try:
            parse_did(did)
        except ApiError as exc:
            assert exc.status == 422
            assert exc.error == "invalid_did"
        else:
            raise AssertionError(did)


def test_http_path_uses_the_same_canonical_key():
    did = parse_did("did:web:example.test:identities:web:%7Ebob")
    path = canonical_url_for_http_path("/identities/web/~bob/did.json", host="example.test", port=443)
    assert path == did.canonical_url
