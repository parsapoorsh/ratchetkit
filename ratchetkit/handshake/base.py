"""Shared base for X3DH / PQXDH handshakes."""
from __future__ import annotations


from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ratchetkit.errors import InvalidKey, InvalidSignature
from ratchetkit.kdf import Kdf
from ratchetkit.suite.registry import hash_backend

if TYPE_CHECKING:
    from ratchetkit.handshake.message import InitialMessageX3DH
    from ratchetkit.keys.identity import IdentityKeyPair
    from ratchetkit.keys.keypair import KeyPair
    from ratchetkit.keys.prekey import (
        OneTimePreKey,
        PreKeyBundle,
        SignedPqPreKey,
        SignedPreKey,
    )
    from ratchetkit.suite.double import CryptoSuiteDoubleRatchet as CryptoSuite


@dataclass
class HandshakeResult:
    """Outcome of :meth:`Handshake.initiate` (shared secret + first wire msg)."""

    shared_secret: bytes
    initial_message: InitialMessageX3DH
    # Initiator-side ratchet key used to seed the Double Ratchet sending chain.
    ratchet_key: KeyPair | None = None


class Handshake(ABC):
    """Bundle publish / initiate / respond for a key-agreement protocol.

    Subclasses supply protocol-specific secret collection and the HKDF
    ``info`` label via :attr:`kdf_info`.
    """

    # HKDF info bound into :meth:`derive_secret` (e.g. KdfLabel.X3DH).
    kdf_info: bytes

    def __init__(self, suite: CryptoSuite):
        self.suite = suite
        self.kdf = Kdf(suite.digest)
        self.kem = suite.kem

    @abstractmethod
    def create_bundle(
        self,
        identity: IdentityKeyPair,
        signed_prekey: SignedPreKey,
        one_time_prekey: OneTimePreKey | None = None,
        pq_prekey: SignedPqPreKey | None = None,
    ) -> PreKeyBundle:
        """Build and verify a publishable prekey bundle for this protocol."""

    @abstractmethod
    def initiate(
        self,
        our_identity: IdentityKeyPair,
        their_bundle: PreKeyBundle,
    ) -> HandshakeResult:
        """Alice: derive shared secret and produce the signed initial message."""

    @abstractmethod
    def respond(
        self,
        our_identity: IdentityKeyPair,
        our_signed_prekey: SignedPreKey,
        initial_message: InitialMessageX3DH,
        our_one_time_prekey: OneTimePreKey | None = None,
        our_pq_prekey: SignedPqPreKey | None = None,
    ) -> bytes:
        """Bob: verify initiator and derive the matching shared secret."""

    def validate_initial_algorithms(self, initial_message: InitialMessageX3DH) -> None:
        """Reject initiator keys whose algorithms do not match this suite."""
        if initial_message.identity_signing.algorithm != self.suite.signing:
            raise InvalidKey(
                f"initial message identity signing algorithm "
                f"{initial_message.identity_signing.algorithm!r} "
                f"does not match suite {self.suite.signing!r}"
            )
        expected = self.kem.algorithm
        checks = [
            ("ephemeral", initial_message.ephemeral_public.algorithm),
        ]
        if initial_message.identity_agreement is not None:
            checks.append(
                ("identity agreement", initial_message.identity_agreement.algorithm)
            )
        for label, algorithm in checks:
            if algorithm != expected:
                raise InvalidKey(
                    f"initial message {label} algorithm {algorithm!r} "
                    f"does not match suite {expected!r}"
                )

    @staticmethod
    def initial_signed_material(
        identity_agreement_data: bytes,
        ephemeral_public: bytes,
        signed_prekey_public: bytes,
        kem_ciphertexts: list[bytes],
        ratchet_public: bytes,
        pq_ciphertext: bytes | None = None,
    ) -> bytes:
        """Bytes covered by the initiator signature on the initial message.

        Includes the initiator identity-agreement public key so a MitM cannot
        swap it without breaking the signature. PQXDH also binds the PQ
        ciphertext when present.
        """
        material = (
            identity_agreement_data
            + ephemeral_public
            + signed_prekey_public
            + b"".join(kem_ciphertexts)
            + ratchet_public
        )
        if pq_ciphertext is not None:
            material = material + pq_ciphertext
        return material

    def check_prekey_ids(
        self,
        initial_message: InitialMessageX3DH,
        our_signed_prekey: SignedPreKey,
        our_one_time_prekey: OneTimePreKey | None,
    ) -> None:
        """Require SPK/OPK ids on the initial message to match local keys."""
        if initial_message.signed_prekey_id != our_signed_prekey.key_id:
            raise InvalidKey("signed prekey id mismatch")
        if our_one_time_prekey is not None:
            if initial_message.one_time_prekey_id != our_one_time_prekey.key_id:
                raise InvalidKey("one-time prekey id mismatch")
        elif initial_message.one_time_prekey_id is not None:
            raise InvalidKey("one-time prekey was used but not provided")

    def verify_initial_signature(
        self,
        initial_message: InitialMessageX3DH,
        signed_prekey_public: bytes,
        *,
        pq_ciphertext: bytes | None = None,
    ) -> None:
        """Verify the initiator signature over :meth:`initial_signed_material`."""
        agreement_data = (
            initial_message.identity_agreement.data
            if initial_message.identity_agreement is not None
            else b""
        )
        to_verify = self.initial_signed_material(
            identity_agreement_data=agreement_data,
            ephemeral_public=initial_message.ephemeral_public.data,
            signed_prekey_public=signed_prekey_public,
            kem_ciphertexts=list(initial_message.kem_ciphertexts),
            ratchet_public=initial_message.ratchet_public or b"",
            pq_ciphertext=pq_ciphertext,
        )
        try:
            self.suite.signer.verify(
                initial_message.identity_signing,
                to_verify,
                initial_message.signature,
                hash_backend(self.suite.digest),
            )
        except InvalidSignature:
            raise

    def sign_initial_material(
        self,
        our_identity: IdentityKeyPair,
        material: bytes,
    ) -> bytes:
        """Sign initiator material with the local identity signing key."""
        return self.suite.signer.sign(
            our_identity.signing,
            material,
            hash_backend(self.suite.digest),
        )

    def derive_secret(self, secrets: list[bytes]) -> bytes:
        """HKDF-combine DH/KEM secrets with this protocol's ``kdf_info`` label."""
        name = type(self).__name__
        if not secrets:
            raise InvalidKey(f"no {name} secrets to combine")
        for index, secret in enumerate(secrets):
            if not isinstance(secret, (bytes, bytearray)) or not secret:
                raise InvalidKey(f"{name} secret {index} is empty")
            if not any(secret):
                raise InvalidKey(f"{name} secret {index} is all zeros")
        size = hash_backend(self.suite.digest).digest_size
        prefix = b"\xff" * size
        ikm = prefix + b"".join(bytes(s) for s in secrets)
        return self.kdf.hkdf(
            ikm,
            size,
            salt=None,
            info=self.kdf_info,
        )
