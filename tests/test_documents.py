import copy

import pytest

from open_did_server.config import Settings
from open_did_server.documents import validate_document
from open_did_server.errors import ApiError
from open_did_server.identity import create_wba_identity, create_web_identity
from open_did_server.service import next_generation


def settings(**overrides) -> Settings:
    values = dict(
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
    values.update(overrides)
    return Settings(**values)


def test_wba_proof_covers_the_handle_service_before_upload():
    document, _key = create_wba_identity("example.test", ["identities", "wba", "alice"], "alice", "example.test")
    validated = validate_document(document, settings())
    assert validated.declaration is not None
    assert validated.declaration.exact
    assert document["service"][0]["id"].startswith(document["id"] + "#")
    assert document["proof"]["type"] == "DataIntegrityProof"
    assert document["proof"]["cryptosuite"] == "eddsa-jcs-2022"
    assert document["proof"]["proofPurpose"] == "assertionMethod"
    assert document["proof"]["verificationMethod"] in validated.assertion_ids


def test_relative_lifecycle_and_private_material_are_rejected():
    document, _key = create_web_identity("example.test", ["identities", "web", "bob"], "bob", "example.test")
    relative = copy.deepcopy(document)
    relative["authentication"] = ["#key-1"]
    with pytest.raises(ApiError) as caught:
        validate_document(relative, settings())
    assert caught.value.error == "unsupported_relative_did_url"

    deactivated = copy.deepcopy(document)
    deactivated["deactivated"] = True
    with pytest.raises(ApiError) as caught:
        validate_document(deactivated, settings())
    assert caught.value.error == "unsupported_did_lifecycle"

    successor = copy.deepcopy(document)
    successor["successorDid"] = document["id"]
    with pytest.raises(ApiError) as caught:
        validate_document(successor, settings())
    assert caught.value.error == "unsupported_did_lifecycle"

    private = copy.deepcopy(document)
    private["verificationMethod"][0]["publicKeyJwk"]["d"] = "secret"
    with pytest.raises(ApiError) as caught:
        validate_document(private, settings())
    assert caught.value.error == "private_key_rejected"


def test_wba_proof_mismatch_is_not_repaired():
    document, _key = create_wba_identity("example.test", ["identities", "wba", "alice"], "alice", "example.test")
    original_id = document["id"]
    value = document["proof"]["proofValue"]
    index = len(value) // 2
    replacement = "A" if value[index] != "A" else "B"
    document["proof"]["proofValue"] = value[:index] + replacement + value[index + 1 :]
    with pytest.raises(ApiError) as caught:
        validate_document(document, settings())
    assert caught.value.error == "invalid_proof"
    assert document["id"] == original_id


def test_generation_has_no_leading_zero_and_grows_past_nine():
    assert next_generation(None) == "1"
    assert next_generation("9") == "10"
    with pytest.raises(ValueError):
        next_generation("01")
