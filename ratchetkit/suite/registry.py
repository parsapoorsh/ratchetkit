"""Backend class lookup tables filled by ``ratchetkit.suite.backends``.

Kept free of algorithm-backend imports so other modules can resolve backends
without circular imports. Tables are filled on first lookup.
"""

from __future__ import annotations

from ratchetkit.errors import SerializationError
from ratchetkit.suite.algs import CipherAlg, HashAlg, KeyExchangeAlg, SigningAlg

# Populated by ratchetkit.suite.backends on first backend lookup.
HASH: dict[HashAlg, type] = {}
CIPHER: dict[CipherAlg, type] = {}
KEY_EXCHANGE: dict[KeyExchangeAlg, type] = {}
SIGNING: dict[SigningAlg, type] = {}


def ensure_backends() -> None:
    """Load concrete backends once (after KeyPair is fully defined)."""
    if HASH:
        return
    import ratchetkit.suite.backends  # noqa: F401


def hash_backend(alg: HashAlg):
    """Concrete hash algorithm class for ``alg``."""
    ensure_backends()
    try:
        return HASH[alg]
    except KeyError as exc:
        raise SerializationError(f"hash backend not registered for {alg!r}") from exc


def cipher_backend(alg: CipherAlg):
    """Concrete cipher algorithm class for ``alg``."""
    ensure_backends()
    try:
        return CIPHER[alg]
    except KeyError as exc:
        raise SerializationError(f"cipher backend not registered for {alg!r}") from exc


def key_exchange_backend(alg: KeyExchangeAlg):
    """Concrete KEM/DH algorithm class for ``alg``."""
    ensure_backends()
    try:
        return KEY_EXCHANGE[alg]
    except KeyError as exc:
        raise SerializationError(
            f"key-exchange backend not registered for {alg!r}"
        ) from exc


def signing_backend(alg: SigningAlg):
    """Concrete signature algorithm class for ``alg``."""
    ensure_backends()
    try:
        return SIGNING[alg]
    except KeyError as exc:
        raise SerializationError(
            f"signing backend not registered for {alg!r}"
        ) from exc
