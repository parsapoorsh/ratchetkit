"""Algorithm enums and KDF labels for crypto suites.

Suite dumps write each algorithm as a fixed ``u32`` id (the enum value).
Ids are permanent once published; add new algorithms with new ids only.
"""

from __future__ import annotations

from enum import IntEnum

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
from ratchetkit.errors import SerializationError


class Alg(IntEnum):
    """Base for suite algorithm enums dumped as permanent ``u32`` ids."""

    @classmethod
    def from_id(cls, alg_id: int):
        """Resolve a wire ``u32`` id to a member of this enum."""
        try:
            return cls(alg_id)
        except ValueError as exc:
            raise SerializationError(
                f"unknown {cls.__name__} id {alg_id}"
            ) from exc


class HashAlg(Alg):
    """Hash algorithm for HKDF, HMAC, and signature digests."""

    SHA256 = 1
    SHA384 = 2
    SHA512 = 3
    SHA3_256 = 4
    BLAKE2B = 5

    @property
    def impl(self):
        """Concrete hash algorithm class."""
        HASH_IMPL = {
            HashAlg.SHA256: Sha256,
            HashAlg.SHA384: Sha384,
            HashAlg.SHA512: Sha512,
            HashAlg.SHA3_256: Sha3256,
            HashAlg.BLAKE2B: Blake2b,
        }
        return HASH_IMPL[self]


class CipherAlg(Alg):
    """Symmetric cipher (key/nonce sizes live on the class)."""

    AES128 = 1
    AES256 = 2
    CAMELLIA128 = 3
    CAMELLIA256 = 4
    CHACHA20 = 5

    @property
    def impl(self):
        """Concrete cipher algorithm class."""
        CIPHER_IMPL = {
            CipherAlg.AES128: Aes128,
            CipherAlg.AES256: Aes256,
            CipherAlg.CAMELLIA128: Camellia128,
            CipherAlg.CAMELLIA256: Camellia256,
            CipherAlg.CHACHA20: ChaCha20,
        }
        return CIPHER_IMPL[self]


class KeyExchangeAlg(Alg):
    """KEM-capable asymmetric algorithm."""

    X25519 = 1
    X448 = 2
    SECP256R1 = 3
    SECP384R1 = 4
    SECP521R1 = 5
    RSA2048 = 6
    RSA3072 = 10
    RSA4096 = 7
    # Post-quantum (FIPS 203 ML-KEM + FIPS 204 ML-DSA for identity signing)
    MLKEM768 = 8
    MLKEM1024 = 9

    @property
    def impl(self):
        """Concrete KEM/DH algorithm class."""
        KEX_IMPL = {
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
        return KEX_IMPL[self]


class KdfLabel:
    """One-byte HKDF info values for domain separation."""

    X3DH = b"\x01"
    ROOT_CHAIN = b"\x02"  # root-key -> (root, chain) ratchet step
    MESSAGE_KEYS = b"\x03"  # chain-key seed -> cipher/mac/iv
    SPQR_INIT = b"\x04"  # Sparse PQ Ratchet chain start
    SPQR_EPOCH = b"\x05"  # Sparse PQ Ratchet add epoch
    TR_SPLIT = b"\x06"  # Triple Ratchet SK -> (SKec, SKscka)
    TR_HYBRID = b"\x07"  # Triple Ratchet KDF_HYBRID(ec_mk, pq_mk)
    PQXDH = b"\x08"  # Post-Quantum Extended Diffie-Hellman handshake


class ChainKeySeed:
    """HMAC seeds for KDF_CK (libsignal ChainKey)."""

    MESSAGE_KEY_SEED = b"\x01"
    CHAIN_KEY_SEED = b"\x02"


# Spec §7.2 recommends AES-256 (or equivalent). 128-bit ciphers remain in
# CipherAlg for completeness but are rejected by default at suite build.
MIN_CIPHER_KEY_BYTES = 32

# HMAC tag on the wire (truncated output). Floor matches libsignal's 10-byte
# content MAC; max is the suite digest size (full HMAC). Default 16.
MIN_TAG_SIZE = 10
DEFAULT_TAG_SIZE = 16

# Default SCKA amortization: split each PQ KEM payload across this many
# application messages (ePrint 2025/078 / Signal SPQR-style chunking).
DEFAULT_SCKA_CHUNKS = 8
