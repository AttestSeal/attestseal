"""did:web resolver with in-process TTL cache.

Resolves a DID like ``did:web:attestseal.com`` to its DID document by fetching
``https://attestseal.com/.well-known/did.json`` over HTTPS and parsing the
verification methods. Caches resolved documents for 24 hours by default.
"""
from __future__ import annotations

import base64
import threading
import time
from dataclasses import dataclass
from typing import Optional

import httpx
import nacl.signing


_DEFAULT_TTL_SECONDS = 24 * 3600
_DEFAULT_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True)
class _CacheEntry:
    document: dict
    fetched_at: float


def _did_to_url(did: str) -> str:
    """Map ``did:web:<host>`` to the conventional ``.well-known/did.json``
    URL. Path-style DIDs (``did:web:host:path``) are not supported; the
    AttestSeal issuer DID is host-only."""
    if not did.startswith("did:web:"):
        raise ValueError(f"unsupported DID method: {did}")
    host_and_path = did.removeprefix("did:web:")
    if ":" in host_and_path:
        raise ValueError(f"path-style did:web not supported: {did}")
    return f"https://{host_and_path}/.well-known/did.json"


def _multibase_decode(value: str) -> bytes:
    """Decode an 'M'-prefix base64pad multibase string (and accept legacy
    'z' prefix that some pre-2026-04 attestations used; both encode the
    same base64pad bytes)."""
    if not value:
        raise ValueError("empty multibase value")
    prefix, data = value[0], value[1:]
    if prefix not in ("M", "z"):
        raise ValueError(f"unsupported multibase prefix: {prefix!r}")
    return base64.b64decode(data)


class DIDResolver:
    """Thread-safe DID resolver with TTL caching.

    The resolver is intended to be a long-lived singleton inside a process
    (or per-process) so the cache survives across many verifications.
    Construct one per agent, hand it to your :class:`AttestationVerifier`,
    and reuse it.
    """

    def __init__(
        self,
        *,
        ttl_seconds: float = _DEFAULT_TTL_SECONDS,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self._ttl = ttl_seconds
        self._timeout = timeout_seconds
        self._cache: dict[str, _CacheEntry] = {}
        self._lock = threading.Lock()
        self._client = client  # None -> create per-call (kept for testability)

    def resolve(self, did: str, *, force_refresh: bool = False) -> dict:
        """Return the DID document for ``did``, fetching if not cached or stale.

        ``force_refresh`` bypasses the cache. Use this when a signature
        verification fails for what should be a valid attestation; that's
        the canonical signal that the cached DID document is stale because
        of a key rotation.
        """
        now = time.time()
        if not force_refresh:
            with self._lock:
                entry = self._cache.get(did)
                if entry is not None and (now - entry.fetched_at) < self._ttl:
                    return entry.document

        url = _did_to_url(did)
        if self._client is not None:
            doc = self._fetch(self._client, url)
        else:
            with httpx.Client(timeout=self._timeout) as client:
                doc = self._fetch(client, url)

        with self._lock:
            self._cache[did] = _CacheEntry(document=doc, fetched_at=now)
        return doc

    @staticmethod
    def _fetch(client: httpx.Client, url: str) -> dict:
        resp = client.get(url, follow_redirects=False)
        resp.raise_for_status()
        return resp.json()

    def verify_key_for(self, did: str, key_id: str, *, force_refresh: bool = False) -> nacl.signing.VerifyKey:
        """Look up ``key_id`` in the DID document for ``did`` and return its
        Ed25519 VerifyKey.

        Raises :class:`ValueError` if the key is not present or is not Ed25519.
        """
        doc = self.resolve(did, force_refresh=force_refresh)
        for vm in doc.get("verificationMethod", []):
            if vm.get("id") != key_id:
                continue
            mb = vm.get("publicKeyMultibase")
            if not mb:
                raise ValueError(f"verification method {key_id} has no publicKeyMultibase")
            raw = _multibase_decode(mb)
            return nacl.signing.VerifyKey(raw)
        raise ValueError(f"key {key_id} not found in DID document for {did}")

    def clear_cache(self) -> None:
        """Drop every cached DID document. Mostly useful for tests."""
        with self._lock:
            self._cache.clear()


# A process-wide default resolver. Most consumers want this; advanced users
# (multiple agents per process, custom TTL) should construct their own.
default_resolver = DIDResolver()
