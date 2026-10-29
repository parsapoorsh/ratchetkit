"""Crypto suites and algorithm enums."""

from ratchetkit.suite.algs import (
    DEFAULT_SCKA_CHUNKS,
    DEFAULT_TAG_SIZE,
    MIN_CIPHER_KEY_BYTES,
    MIN_TAG_SIZE,
    Alg,
    ChainKeySeed,
    CipherAlg,
    HashAlg,
    KdfLabel,
    KeyExchangeAlg,
)
from ratchetkit.suite.double import CryptoSuiteDoubleRatchet
from ratchetkit.suite.triple import CryptoSuiteTripleRatchet

# Type-hint alias: Double is the shared base (Triple subclasses it).
CryptoSuite = CryptoSuiteDoubleRatchet

__all__ = [
    "DEFAULT_SCKA_CHUNKS",
    "DEFAULT_TAG_SIZE",
    "MIN_CIPHER_KEY_BYTES",
    "MIN_TAG_SIZE",
    "Alg",
    "ChainKeySeed",
    "CipherAlg",
    "CryptoSuite",
    "CryptoSuiteDoubleRatchet",
    "CryptoSuiteTripleRatchet",
    "HashAlg",
    "KdfLabel",
    "KeyExchangeAlg",
]
