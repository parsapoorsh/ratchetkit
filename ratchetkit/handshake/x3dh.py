"""Extended Triple Diffie-Hellman (X3DH) key agreement.

Classical (or KEM-only) handshake over the suite's ``key_exchange`` backend.
Post-quantum hybrid is a separate peer protocol in ``pqxdh.py``.
"""

from __future__ import annotations

from ratchetkit.suite.registry import hash_backend


from dataclasses import dataclass
from typing import TYPE_CHECKING

from ratchetkit.errors import InvalidKey, InvalidSignature
from ratchetkit.kdf import Kdf
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.keypair import KeyPair
from ratchetkit.keys.prekey import (
    OneTimePreKey,
    PreKeyBundle,
    SignedPqPreKey,
    SignedPreKey,
)
from ratchetkit.suite import KdfLabel
from ratchetkit.handshake.message import InitialMessagePQXDH, InitialMessageX3DH

if TYPE_CHECKING:
    from ratchetkit.suite import CryptoSuite


@dataclass
class ExtendedTripleDiffieHellmanResult:
    shared_secret: bytes
    initial_message: InitialMessageX3DH
    # Initiator-side ratchet key used to seed the Double Ratchet sending chain.
    ratchet_key: KeyPair | None = None


class ExtendedTripleDiffieHellman:
    """X3DH handshake: bundle creation, initiate, respond."""

    def __init__(self, suite: CryptoSuite):
        self.suite = suite
        self.kdf = Kdf(suite.digest)
        self.kem = suite.kem

    def create_bundle(
        self,
        identity: IdentityKeyPair,
        signed_prekey: SignedPreKey,
        one_time_prekey: OneTimePreKey | None = None,
    ) -> PreKeyBundle:
        bundle = PreKeyBundle.from_local(identity, signed_prekey, one_time_prekey)
        bundle.verify(self.suite)
        return bundle

    def initiate(
        self,
        our_identity: IdentityKeyPair,
        their_bundle: PreKeyBundle,
    ) -> ExtendedTripleDiffieHellmanResult:
        their_bundle.verify(self.suite)
        if their_bundle.pq_prekey is not None:
            raise InvalidKey(
                "X3DH cannot use a PQ prekey bundle; "
                "use PostQuantumExtendedDiffieHellman"
            )

        secrets: list[bytes] = []
        kem_ciphertexts: list[bytes] = []
        ephemeral = self.kem.generate_keypair()

        if self.kem.supports_dh:
            if our_identity.agreement is None:
                raise InvalidKey("DH suite requires identity agreement key")
            if their_bundle.identity_agreement is None:
                raise InvalidKey("bundle missing identity agreement key")
            secrets.append(
                self.kem.dh(our_identity.agreement, their_bundle.signed_prekey)
            )
            secrets.append(
                self.kem.dh(ephemeral, their_bundle.identity_agreement)
            )
            secrets.append(
                self.kem.dh(ephemeral, their_bundle.signed_prekey)
            )
            if their_bundle.one_time_prekey is not None:
                secrets.append(
                    self.kem.dh(ephemeral, their_bundle.one_time_prekey)
                )
        else:
            # KEM-only: encapsulate to SPK + required OPK.
            if their_bundle.one_time_prekey is None:
                raise InvalidKey(
                    "KEM suites require a one-time prekey for forward secrecy"
                )
            secret, ct = self.kem.encapsulate(their_bundle.signed_prekey)
            secrets.append(secret)
            kem_ciphertexts.append(ct)
            secret, ct = self.kem.encapsulate(their_bundle.one_time_prekey)
            secrets.append(secret)
            kem_ciphertexts.append(ct)

        shared = self.derive_secret(secrets)
        ratchet_key = self.kem.generate_keypair()

        identity_agreement = (
            our_identity.agreement.public
            if our_identity.agreement is not None
            else None
        )
        to_sign = self.initial_signed_material(
            identity_agreement_data=(
                identity_agreement.data if identity_agreement is not None else b""
            ),
            ephemeral_public=ephemeral.public.data,
            signed_prekey_public=their_bundle.signed_prekey.data,
            kem_ciphertexts=kem_ciphertexts,
            ratchet_public=ratchet_key.public.data,
        )
        signature = self.suite.signer.sign(
            our_identity.signing,
            to_sign,
            hash_backend(self.suite.digest),
        )

        message = InitialMessageX3DH(
            identity_signing=our_identity.signing.public,
            identity_agreement=identity_agreement,
            ephemeral_public=ephemeral.public,
            kem_ciphertexts=tuple(kem_ciphertexts),
            signed_prekey_id=their_bundle.signed_prekey_id,
            one_time_prekey_id=their_bundle.one_time_prekey_id,
            signature=signature,
            ratchet_public=ratchet_key.public.data,
        )
        return ExtendedTripleDiffieHellmanResult(
            shared_secret=shared,
            initial_message=message,
            ratchet_key=ratchet_key,
        )

    def respond(
        self,
        our_identity: IdentityKeyPair,
        our_signed_prekey: SignedPreKey,
        initial_message: InitialMessageX3DH,
        our_one_time_prekey: OneTimePreKey | None = None,
        our_pq_prekey: SignedPqPreKey | None = None,
    ) -> bytes:
        # Same signature as PQXDH.respond so Session.accept has one call path.
        if our_pq_prekey is not None:
            raise InvalidKey("X3DH does not use a PQ prekey")
        if isinstance(initial_message, InitialMessagePQXDH):
            raise InvalidKey(
                "X3DH cannot accept a PQXDH initial message; "
                "use PostQuantumExtendedDiffieHellman"
            )
        if initial_message.signed_prekey_id != our_signed_prekey.key_id:
            raise InvalidKey("signed prekey id mismatch")
        if our_one_time_prekey is not None:
            if initial_message.one_time_prekey_id != our_one_time_prekey.key_id:
                raise InvalidKey("one-time prekey id mismatch")
        elif initial_message.one_time_prekey_id is not None:
            raise InvalidKey("one-time prekey was used but not provided")

        self.validate_initial_algorithms(initial_message)

        agreement_data = (
            initial_message.identity_agreement.data
            if initial_message.identity_agreement is not None
            else b""
        )
        to_verify = self.initial_signed_material(
            identity_agreement_data=agreement_data,
            ephemeral_public=initial_message.ephemeral_public.data,
            signed_prekey_public=our_signed_prekey.key_pair.public.data,
            kem_ciphertexts=list(initial_message.kem_ciphertexts),
            ratchet_public=initial_message.ratchet_public or b"",
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

        secrets: list[bytes] = []
        if self.kem.supports_dh:
            if our_identity.agreement is None:
                raise InvalidKey("DH suite requires identity agreement key")
            if initial_message.identity_agreement is None:
                raise InvalidKey("initial message missing identity agreement key")
            secrets.append(
                self.kem.dh(our_signed_prekey.key_pair,
                    initial_message.identity_agreement,
                )
            )
            secrets.append(
                self.kem.dh(our_identity.agreement,
                    initial_message.ephemeral_public,
                )
            )
            secrets.append(
                self.kem.dh(our_signed_prekey.key_pair,
                    initial_message.ephemeral_public,
                )
            )
            if our_one_time_prekey is not None:
                secrets.append(
                    self.kem.dh(our_one_time_prekey.key_pair,
                        initial_message.ephemeral_public,
                    )
                )
        else:
            if our_one_time_prekey is None:
                raise InvalidKey(
                    "KEM suites require a one-time prekey for forward secrecy"
                )
            cts = list(initial_message.kem_ciphertexts)
            if len(cts) < 2:
                raise InvalidKey("KEM initial message missing SPK/OPK ciphertexts")
            secrets.append(
                self.kem.decapsulate(our_signed_prekey.key_pair, cts[0])
            )
            secrets.append(
                self.kem.decapsulate(our_one_time_prekey.key_pair, cts[1])
            )

        return self.derive_secret(secrets)

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

    def derive_secret(self, secrets: list[bytes]) -> bytes:
        if not secrets:
            raise InvalidKey("no ExtendedTripleDiffieHellman secrets to combine")
        for index, secret in enumerate(secrets):
            if not isinstance(secret, (bytes, bytearray)) or not secret:
                raise InvalidKey(f"ExtendedTripleDiffieHellman secret {index} is empty")
            if not any(secret):
                raise InvalidKey(
                    f"ExtendedTripleDiffieHellman secret {index} is all zeros"
                )
        size = hash_backend(self.suite.digest).digest_size
        prefix = b"\xff" * size
        ikm = prefix + b"".join(bytes(s) for s in secrets)
        return self.kdf.hkdf(
            ikm,
            size,
            salt=None,
            info=KdfLabel.X3DH,
        )
