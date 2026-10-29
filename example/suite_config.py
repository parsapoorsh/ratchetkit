"""Shared crypto suite for the Alice/Bob demo.

Both processes must use the same suite. Use CryptoSuiteDoubleRatchet for
classical Double Ratchet, or CryptoSuiteTripleRatchet for PQ hybrid.
"""

from __future__ import annotations

from ratchetkit.suite import (
    SigningAlg,
    CipherAlg,
    CryptoSuiteDoubleRatchet,
    CryptoSuiteTripleRatchet,
    HashAlg,
    KeyExchangeAlg,
)


def demo_suite() -> CryptoSuiteDoubleRatchet:
    """Classical Double Ratchet demo (X25519 + AES-256 + SHA-256)."""
    return CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
        signing=SigningAlg.ED25519,
    )


def demo_suite_triple() -> CryptoSuiteTripleRatchet:
    """Triple Ratchet demo: classical X25519 + sparse ML-KEM-768."""
    return CryptoSuiteTripleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
        signing=SigningAlg.ED25519,
        pq_key_exchange=KeyExchangeAlg.MLKEM768,
        scka_chunks=4,
    )


# Flip to demo_suite_triple for PQ / Triple Ratchet.
ACTIVE_SUITE = demo_suite_triple
