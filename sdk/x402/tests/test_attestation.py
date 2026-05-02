"""End-to-end test of Attestation -> sign -> headers -> parse -> verify."""
import base64
import json

import nacl.signing
import nacl.encoding
import pytest

from attestseal_x402.attestation import Attestation
from attestseal_x402.headers import build_headers, parse_headers


def _build_signed_attestation(sk: nacl.signing.SigningKey, **overrides) -> Attestation:
    base = dict(
        domain="merchant.example",
        issuer="did:web:test.example",
        issued_at="2026-05-02T14:00:00Z",
        expires_at="2026-05-09T14:00:00Z",
        trust_score=78,
        recommendation="PROCEED",
        confidence="high",
        assurance_basis="earned_proceed",
        scoring_model="attestseal-v1.5.1-weights",
        signature="",
        signature_key_id="did:web:test.example#k1",
        parent_floor_inherited=False,
        agent_policy_hint="proceed_earned",
    )
    base.update(overrides)
    a = Attestation(**base)
    sig_bytes = sk.sign(a.signable_digest()).signature
    return Attestation(**{**base, "signature": "M" + base64.b64encode(sig_bytes).decode()})


def test_signing_form_includes_required_fields():
    sk = nacl.signing.SigningKey.generate()
    a = _build_signed_attestation(sk)
    payload = json.loads(a.signable_bytes())
    for required in (
        "domain", "issuer", "issuedAt", "expiresAt", "trustScore",
        "recommendation", "confidence", "assuranceBasis", "scoringModel",
    ):
        assert required in payload


def test_signing_form_stable_across_header_roundtrip():
    sk = nacl.signing.SigningKey.generate()
    a = _build_signed_attestation(sk)
    headers = build_headers(a)
    parsed = parse_headers(headers)
    assert parsed is not None
    assert parsed.signable_digest() == a.signable_digest()


def test_signature_verifies_after_header_roundtrip():
    sk = nacl.signing.SigningKey.generate()
    pk = sk.verify_key
    a = _build_signed_attestation(sk)
    headers = build_headers(a)
    parsed = parse_headers(headers)
    sig = base64.b64decode(parsed.signature[1:])
    pk.verify(parsed.signable_digest(), sig)  # raises on mismatch


def test_parse_headers_returns_none_when_required_absent():
    headers = {"X-AttestSeal-Domain": "merchant.example"}  # everything else missing
    assert parse_headers(headers) is None


def test_optional_fields_round_trip():
    sk = nacl.signing.SigningKey.generate()
    a = _build_signed_attestation(
        sk,
        site_category="tenant_platform",
        caution_reason=None,
        parent_company="Vercel",
    )
    headers = build_headers(a)
    parsed = parse_headers(headers)
    assert parsed.site_category == "tenant_platform"
    assert parsed.parent_company == "Vercel"


def test_parent_floor_inherited_round_trips_as_string():
    sk = nacl.signing.SigningKey.generate()
    a = _build_signed_attestation(sk, parent_floor_inherited=False)
    headers = build_headers(a)
    assert headers["X-AttestSeal-Parent-Floor-Inherited"] == "false"
    parsed = parse_headers(headers)
    assert parsed.parent_floor_inherited is False


def test_signature_does_not_verify_with_wrong_key():
    sk = nacl.signing.SigningKey.generate()
    other_sk = nacl.signing.SigningKey.generate()
    a = _build_signed_attestation(sk)
    headers = build_headers(a)
    parsed = parse_headers(headers)
    sig = base64.b64decode(parsed.signature[1:])
    with pytest.raises(Exception):
        other_sk.verify_key.verify(parsed.signable_digest(), sig)


def test_signing_form_changes_when_domain_changes():
    sk = nacl.signing.SigningKey.generate()
    a1 = _build_signed_attestation(sk, domain="merchant-a.example")
    a2 = _build_signed_attestation(sk, domain="merchant-b.example")
    assert a1.signable_digest() != a2.signable_digest()
