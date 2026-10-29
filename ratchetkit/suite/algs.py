"""Algorithm enums and KDF labels for crypto suites.

Suite dumps write each algorithm as a fixed ``u32`` id (the enum value).
Ids are permanent once published; add new algorithms with new ids only.
"""
from __future__ import annotations


from enum import IntEnum

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


class CipherAlg(Alg):
    """Symmetric cipher (key/nonce sizes live on the class)."""

    AES128 = 1
    AES256 = 2
    CAMELLIA128 = 3
    CAMELLIA256 = 4
    CHACHA20 = 5


class KeyExchangeAlg(Alg):
    """KEM / DH agreement algorithms (confidentiality, ratchet)."""

    X25519 = 1
    X448 = 2
    SECP256R1 = 3
    SECP384R1 = 4
    SECP521R1 = 5
    RSA2048 = 6
    RSA3072 = 10
    RSA4096 = 7
    # Post-quantum KEM (FIPS 203)
    MLKEM768 = 8
    MLKEM1024 = 9


class SigningAlg(Alg):
    """Signature algorithms (identity / prekey authenticity)."""

    ED25519 = 1
    ED448 = 2
    ECDSA_SECP256R1 = 3
    ECDSA_SECP384R1 = 4
    ECDSA_SECP521R1 = 5
    RSA_PSS_2048 = 6
    RSA_PSS_3072 = 10
    RSA_PSS_4096 = 7
    # Post-quantum signatures (FIPS 204)
    MLDSA65 = 8
    MLDSA87 = 9


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
