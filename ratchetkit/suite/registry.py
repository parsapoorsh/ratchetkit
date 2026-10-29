"""Static backend class tables for suite algorithm enums.

Maps are built at import time. ``keys.keypair`` must not import this module
at top level (only inside ``KeyPair.public`` / ``SigningKeyPair.public``) so
KEM modules can import ``KeyPair`` while this module imports those KEMs.
"""

from __future__ import annotations

from ratchetkit.algorithms.cipher.aes128 import Aes128
from ratchetkit.algorithms.cipher.aes256 import Aes256
from ratchetkit.algorithms.cipher.camellia128 import Camellia128
from ratchetkit.algorithms.cipher.camellia256 import Camellia256
from ratchetkit.algorithms.cipher.chacha20 import ChaCha20
from ratchetkit.algorithms.hash.blake2b import Blake2b
from ratchetkit.algorithms.hash.sha256 import Sha256
from ratchetkit.algorithms.hash.sha384 import Sha384
from ratchetkit.algorithms.hash.sha3256 import Sha3256
from ratchetkit.algorithms.hash.sha512 import Sha512
from ratchetkit.algorithms.kem.mlkem1024 import Mlkem1024
from ratchetkit.algorithms.kem.mlkem768 import Mlkem768
from ratchetkit.algorithms.kem.rsa2048 import Rsa2048
from ratchetkit.algorithms.kem.rsa3072 import Rsa3072
from ratchetkit.algorithms.kem.rsa4096 import Rsa4096
from ratchetkit.algorithms.kem.secp256r1 import Secp256r1
from ratchetkit.algorithms.kem.secp384r1 import Secp384r1
from ratchetkit.algorithms.kem.secp521r1 import Secp521r1
from ratchetkit.algorithms.kem.x25519 import X25519
from ratchetkit.algorithms.kem.x448 import X448
from ratchetkit.algorithms.signing.ecdsa import (
    EcdsaSecp256r1,
    EcdsaSecp384r1,
    EcdsaSecp521r1,
)
from ratchetkit.algorithms.signing.ed25519 import Ed25519
from ratchetkit.algorithms.signing.ed448 import Ed448
from ratchetkit.algorithms.signing.mldsa import Mldsa65, Mldsa87
from ratchetkit.algorithms.signing.rsa_pss import RsaPss2048, RsaPss3072, RsaPss4096
from ratchetkit.errors import SerializationError
from ratchetkit.suite.algs import CipherAlg, HashAlg, KeyExchangeAlg, SigningAlg

HASH = {
    HashAlg.SHA256: Sha256,
    HashAlg.SHA384: Sha384,
    HashAlg.SHA512: Sha512,
    HashAlg.SHA3_256: Sha3256,
    HashAlg.BLAKE2B: Blake2b,
}

CIPHER = {
    CipherAlg.AES128: Aes128,
    CipherAlg.AES256: Aes256,
    CipherAlg.CAMELLIA128: Camellia128,
    CipherAlg.CAMELLIA256: Camellia256,
    CipherAlg.CHACHA20: ChaCha20,
}

KEY_EXCHANGE = {
    KeyExchangeAlg.X25519: X25519,
    KeyExchangeAlg.X448: X448,
    KeyExchangeAlg.SECP256R1: Secp256r1,
    KeyExchangeAlg.SECP384R1: Secp384r1,
    KeyExchangeAlg.SECP521R1: Secp521r1,
    KeyExchangeAlg.RSA2048: Rsa2048,
    KeyExchangeAlg.RSA3072: Rsa3072,
    KeyExchangeAlg.RSA4096: Rsa4096,
    KeyExchangeAlg.MLKEM768: Mlkem768,
    KeyExchangeAlg.MLKEM1024: Mlkem1024,
}

SIGNING = {
    SigningAlg.ED25519: Ed25519,
    SigningAlg.ED448: Ed448,
    SigningAlg.ECDSA_SECP256R1: EcdsaSecp256r1,
    SigningAlg.ECDSA_SECP384R1: EcdsaSecp384r1,
    SigningAlg.ECDSA_SECP521R1: EcdsaSecp521r1,
    SigningAlg.RSA_PSS_2048: RsaPss2048,
    SigningAlg.RSA_PSS_3072: RsaPss3072,
    SigningAlg.RSA_PSS_4096: RsaPss4096,
    SigningAlg.MLDSA65: Mldsa65,
    SigningAlg.MLDSA87: Mldsa87,
}


def hash_backend(alg: HashAlg):
    """Concrete hash algorithm class for ``alg``."""
    try:
        return HASH[alg]
    except KeyError as exc:
        raise SerializationError(f"hash backend not registered for {alg!r}") from exc


def cipher_backend(alg: CipherAlg):
    """Concrete cipher algorithm class for ``alg``."""
    try:
        return CIPHER[alg]
    except KeyError as exc:
        raise SerializationError(f"cipher backend not registered for {alg!r}") from exc


def key_exchange_backend(alg: KeyExchangeAlg):
    """Concrete KEM/DH algorithm class for ``alg``."""
    try:
        return KEY_EXCHANGE[alg]
    except KeyError as exc:
        raise SerializationError(
            f"key-exchange backend not registered for {alg!r}"
        ) from exc


def signing_backend(alg: SigningAlg):
    """Concrete signature algorithm class for ``alg``."""
    try:
        return SIGNING[alg]
    except KeyError as exc:
        raise SerializationError(
            f"signing backend not registered for {alg!r}"
        ) from exc
