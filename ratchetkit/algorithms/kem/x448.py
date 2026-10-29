"""X448 DH-as-KEM (agreement only)."""
from __future__ import annotations


from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from ratchetkit.errors import InvalidKey
from ratchetkit.algorithms.kem.base import KemBackend
from ratchetkit.keys.keypair import KeyPair, PublicKey
from ratchetkit.suite.algs import KeyExchangeAlg


class X448(KemBackend):
    algorithm = KeyExchangeAlg.X448
    supports_dh = True

    def generate_keypair(self) -> KeyPair:
        private = x448.X448PrivateKey.generate()
        return KeyPair(
            private=private.private_bytes(
                Encoding.Raw,
                PrivateFormat.Raw,
                NoEncryption(),
            ),
            algorithm=self.algorithm,
        )

    def derive_public(self, private: bytes) -> bytes:
        key = x448.X448PrivateKey.from_private_bytes(private)
        return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def encapsulate(self, their_public: PublicKey) -> tuple[bytes, bytes]:
        ephemeral = self.generate_keypair()
        secret = self.dh(ephemeral, their_public)
        return secret, ephemeral.public.data

    def decapsulate(self, our_private: KeyPair, ciphertext: bytes) -> bytes:
        return self.dh(
            our_private,
            PublicKey(ciphertext, self.algorithm),
        )

    def dh(self, our_private: KeyPair, their_public: PublicKey) -> bytes:
        try:
            private = x448.X448PrivateKey.from_private_bytes(our_private.private)
            public = x448.X448PublicKey.from_public_bytes(their_public.data)
            shared = private.exchange(public)
        except Exception as exc:
            raise InvalidKey(
                "X448 DH failed (invalid or low-order public key)"
            ) from exc
        if not any(shared):
            raise InvalidKey("X448 DH produced an all-zero shared secret")
        return shared
