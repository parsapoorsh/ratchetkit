"""Shared ML-KEM encapsulation (agreement only)."""
from __future__ import annotations


from typing import Any

from cryptography.hazmat.primitives.asymmetric import mlkem

from ratchetkit.errors import InvalidKey
from ratchetkit.algorithms.kem.base import KemBackend
from ratchetkit.keys.keypair import KeyPair, PublicKey
from ratchetkit.suite.algs import KeyExchangeAlg


class MlkemBackend(KemBackend):
    """Post-quantum KEM-only backend (FIPS 203).

    Private keys are stored as the FIPS seed (``private_bytes_raw`` /
    ``from_seed_bytes``), not the expanded secret key.
    """

    algorithm: KeyExchangeAlg
    supports_dh = False
    kem_private_cls: Any
    kem_public_cls: Any

    def generate_keypair(self) -> KeyPair:
        raw = self.kem_private_cls.generate()
        private = raw.private_bytes_raw()
        return KeyPair(
            private=private,
            public=PublicKey(self.derive_public(private), self.algorithm),
        )

    def derive_public(self, private: bytes) -> bytes:
        key = self.kem_private_cls.from_seed_bytes(private)
        return key.public_key().public_bytes_raw()

    def encapsulate(self, their_public: PublicKey) -> tuple[bytes, bytes]:
        public = self.kem_public_cls.from_public_bytes(their_public.data)
        secret, ciphertext = public.encapsulate()
        return secret, ciphertext

    def decapsulate(self, our_private: KeyPair, ciphertext: bytes) -> bytes:
        try:
            private = self.kem_private_cls.from_seed_bytes(our_private.private)
            return private.decapsulate(ciphertext)
        except Exception as exc:
            raise InvalidKey(
                f"{self.algorithm.name} decapsulation failed"
            ) from exc


class Mlkem768(MlkemBackend):
    algorithm = KeyExchangeAlg.MLKEM768
    kem_private_cls = mlkem.MLKEM768PrivateKey
    kem_public_cls = mlkem.MLKEM768PublicKey


class Mlkem1024(MlkemBackend):
    algorithm = KeyExchangeAlg.MLKEM1024
    kem_private_cls = mlkem.MLKEM1024PrivateKey
    kem_public_cls = mlkem.MLKEM1024PublicKey
