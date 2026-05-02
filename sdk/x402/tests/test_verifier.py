"""Test the AttestationVerifier against a fake DID resolver."""
import base64
from datetime import datetime, timedelta, timezone

import nacl.signing
import nacl.encoding
import pytest

from attestseal_x402.attestation import Attestation
from attestseal_x402.client import AttestationVerifier
from attestseal_x402.headers import build_headers
from attestseal_x402.did_resolver import DIDResolver


class FakeResolver:
    """In-memory DID resolver: hand it a verify key, it acts as the issuer."""
    def __init__(self, did: str, key_id: str, verify_key: nacl.signing.VerifyKey):
        self.did = did
        self.key_id = key_id
        self.verify_key = verify_key

    def verify_key_for(self, did: str, key_id: str, *, force_refresh: bool = False):
        if did != self.did or key_id != self.key_id:
            raise ValueError(f"{did}/{key_id} not configured")
        return self.verify_key


def _signed_headers(sk, *, domain="merchant.example", expires_at=None, **extra):
    if expires_at is None:
        expires_at = (datetime.now(timezone.utc) + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    a = Attestation(
        domain=domain,
        issuer="did:web:test.example",
        issued_at="2026-05-02T14:00:00Z",
        expires_at=expires_at,
        trust_score=78,
        recommendation="PROCEED",
        confidence="high",
        assurance_basis="earned_proceed",
        scoring_model="attestseal-v1.5.1-weights",
        signature="",
        signature_key_id="did:web:test.example#k1",
        parent_floor_inherited=False,
        agent_policy_hint="proceed_earned",
        **extra,
    )
    sig = sk.sign(a.signable_digest()).signature
    a = Attestation(**{**a.__dict__, "signature": "M" + base64.b64encode(sig).decode()})
    return build_headers(a)


def _verifier_for(sk):
    fake = FakeResolver(did="did:web:test.example", key_id="did:web:test.example#k1",
                       verify_key=sk.verify_key)
    return AttestationVerifier(allowed_issuers={"did:web:test.example"}, resolver=fake)


def test_happy_path_verifies():
    sk = nacl.signing.SigningKey.generate()
    headers = _signed_headers(sk)
    verifier = _verifier_for(sk)
    result = verifier.verify_response_headers(headers, request_url="https://merchant.example/x")
    assert result.ok is True
    assert result.attestation.recommendation == "PROCEED"


def test_domain_mismatch_rejected():
    sk = nacl.signing.SigningKey.generate()
    headers = _signed_headers(sk, domain="merchant.example")
    verifier = _verifier_for(sk)
    result = verifier.verify_response_headers(headers, request_url="https://attacker.example/x")
    assert result.ok is False
    assert result.reason == "domain_mismatch"


def test_expired_rejected():
    sk = nacl.signing.SigningKey.generate()
    past = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    headers = _signed_headers(sk, expires_at=past)
    verifier = _verifier_for(sk)
    result = verifier.verify_response_headers(headers, request_url="https://merchant.example/x")
    assert result.ok is False
    assert result.reason == "expired"


def test_unknown_issuer_rejected():
    sk = nacl.signing.SigningKey.generate()
    headers = _signed_headers(sk)
    fake = FakeResolver(did="did:web:test.example", key_id="did:web:test.example#k1",
                        verify_key=sk.verify_key)
    verifier = AttestationVerifier(allowed_issuers={"did:web:other.example"}, resolver=fake)
    result = verifier.verify_response_headers(headers, request_url="https://merchant.example/x")
    assert result.ok is False
    assert result.reason == "issuer_not_allowed"


def test_tampered_score_breaks_signature():
    sk = nacl.signing.SigningKey.generate()
    headers = _signed_headers(sk)
    headers["X-AttestSeal-Score"] = "100"  # bump the score after signing
    verifier = _verifier_for(sk)
    result = verifier.verify_response_headers(headers, request_url="https://merchant.example/x")
    assert result.ok is False
    assert result.reason == "bad_signature"


def test_missing_required_header_rejected():
    sk = nacl.signing.SigningKey.generate()
    headers = _signed_headers(sk)
    headers.pop("X-AttestSeal-Score")
    verifier = _verifier_for(sk)
    result = verifier.verify_response_headers(headers, request_url="https://merchant.example/x")
    assert result.ok is False
    assert result.reason == "missing_required_header"
