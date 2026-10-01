import base64

import pytest

from open_did_server.config import Settings
from open_did_server.errors import ApiError
from open_did_server.signatures import PROFILE_ECHO, parse_limited_signature


def _settings() -> Settings:
    return Settings(
        data_dir="/tmp/unused",
        host="127.0.0.1",
        port=8000,
        public_did_domain="example.test",
        public_did_port=443,
        handle_provider_domain="example.test",
        request_base_url="http://127.0.0.1:8000",
        local_demo=True,
        resolution_override=None,
        trusted_proxies=(),
        root_method=None,
    )


def _headers(signature_input: str) -> list[tuple[str, str]]:
    signature = "sig1=:" + base64.b64encode(b"\x00" * 64).decode("ascii") + ":"
    return [
        ("content-type", "application/json"),
        ("content-digest", "sha-256=:pY6BR0NZSvSfPExR0TrlXPyGrAwda96+tKyvsnJWEpk=:"),
        ("signature-input", signature_input),
        ("signature", signature),
    ]


def _input(created: int, expires: int, nonce: str, keyid: str, *, order: str = "normal") -> str:
    prefix = 'sig1=("@method" "@target-uri" "@authority" "content-digest" "content-type");'
    if order == "normal":
        return f'{prefix}created={created};expires={expires};nonce="{nonce}";keyid="{keyid}"'
    return f'{prefix}keyid="{keyid}";created={created};expires={expires};nonce="{nonce}"'


def test_reordered_parameters_are_rejected_before_verification():
    keyid = "did:web:example.test:identities:web:bob#key-1"
    ordered = _input(100, 200, "ab" * 16, keyid)
    reordered = _input(100, 200, "ab" * 16, keyid, order="keyid-first")
    parse_limited_signature(
        _headers(ordered),
        body=b'{"hello":"vector"}',
        profile=PROFILE_ECHO,
        settings=_settings(),
        now=150,
        require_json=True,
    )
    with pytest.raises(ApiError) as caught:
        parse_limited_signature(
            _headers(reordered),
            body=b'{"hello":"vector"}',
            profile=PROFILE_ECHO,
            settings=_settings(),
            now=150,
            require_json=True,
        )
    assert caught.value.status == 401
    assert caught.value.error == "invalid_request"


def test_duplicate_signature_input_and_component_parameters_are_rejected():
    keyid = "did:web:example.test:identities:web:bob#key-1"
    signature_input = _input(100, 200, "cd" * 16, keyid)
    headers = _headers(signature_input)
    headers.append(("signature-input", signature_input))
    with pytest.raises(ApiError) as caught:
        parse_limited_signature(
            headers,
            body=b'{"hello":"vector"}',
            profile=PROFILE_ECHO,
            settings=_settings(),
            now=150,
            require_json=True,
        )
    assert caught.value.error == "invalid_request"

    parameterized = signature_input.replace('"content-type"', '"content-type";sf')
    with pytest.raises(ApiError) as caught:
        parse_limited_signature(
            _headers(parameterized),
            body=b'{"hello":"vector"}',
            profile=PROFILE_ECHO,
            settings=_settings(),
            now=150,
            require_json=True,
        )
    assert caught.value.error == "invalid_request"


def test_time_window_rejects_expired_and_overlong_signatures():
    keyid = "did:web:example.test:identities:web:bob#key-1"
    expired = _input(1000, 1100, "ef" * 16, keyid)
    with pytest.raises(ApiError) as caught:
        parse_limited_signature(
            _headers(expired),
            body=b'{"hello":"vector"}',
            profile=PROFILE_ECHO,
            settings=_settings(),
            now=2000,
            require_json=True,
        )
    assert caught.value.error == "invalid_timestamp"

    too_long = _input(1000, 1401, "11" * 16, keyid)
    with pytest.raises(ApiError) as caught:
        parse_limited_signature(
            _headers(too_long),
            body=b'{"hello":"vector"}',
            profile=PROFILE_ECHO,
            settings=_settings(),
            now=1000,
            require_json=True,
        )
    assert caught.value.error == "invalid_timestamp"
