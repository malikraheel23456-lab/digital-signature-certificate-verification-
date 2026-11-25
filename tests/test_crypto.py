import json
import pytest
from crypto_utils import (
    generate_key_pair, sign_document, verify_signature,
    evaluate_trust, public_key_fingerprint
)


@pytest.fixture
def signer():
    return generate_key_pair("Test University")


def test_valid_signature(signer):
    private_pem, public_pem, record_bytes, _ = signer
    message = b"Official university notice"
    signature = sign_document(message, private_pem)
    assert verify_signature(message, signature, public_pem) is True


def test_modified_document_is_rejected(signer):
    private_pem, public_pem, _, _ = signer
    signature = sign_document(b"Original document", private_pem)
    assert verify_signature(b"Modified document", signature, public_pem) is False


def test_modified_signature_is_rejected(signer):
    private_pem, public_pem, _, _ = signer
    signature = bytearray(sign_document(b"Document", private_pem))
    signature[0] ^= 1
    assert verify_signature(b"Document", bytes(signature), public_pem) is False


def test_wrong_public_key_is_rejected(signer):
    private_pem, _, _, _ = signer
    _, wrong_public, _, _ = generate_key_pair("Different University")
    signature = sign_document(b"Document", private_pem)
    assert verify_signature(b"Document", signature, wrong_public) is False


def test_active_trust_record_matches(signer):
    _, public_pem, record_bytes, _ = signer
    result = evaluate_trust(public_pem, record_bytes)
    assert result["trusted"] is True


def test_different_key_does_not_match_trust_record(signer):
    _, _, record_bytes, _ = signer
    _, another_public, _, _ = generate_key_pair("Another signer")
    result = evaluate_trust(another_public, record_bytes)
    assert result["trusted"] is False


def test_inactive_record_is_not_trusted(signer):
    _, public_pem, record_bytes, record = signer
    record["status"] = "REVOKED"
    altered_record = json.dumps(record).encode()
    result = evaluate_trust(public_pem, altered_record)
    assert result["trusted"] is False


def test_missing_record_is_not_claimed_as_trusted(signer):
    _, public_pem, _, _ = signer
    result = evaluate_trust(public_pem, None)
    assert result["trusted"] is None
