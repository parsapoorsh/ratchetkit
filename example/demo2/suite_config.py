"""Shared crypto suite for the resume / out-of-order demo.

Both phases must use the same suite. Flip ACTIVE_SUITE to switch Double vs Triple.
"""

from __future__ import annotations

from ratchetkit.suite import (
    CipherAlg,
    HashAlg,
    KeyExchangeAlg,
    SigningAlg,
)
from ratchetkit.suite.double import CryptoSuiteDoubleRatchet
from ratchetkit.suite.triple import CryptoSuiteTripleRatchet


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


# Flip to demo_suite for classical Double Ratchet only.
ACTIVE_SUITE = demo_suite_triple
