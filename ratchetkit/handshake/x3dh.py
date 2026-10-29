"""Extended Triple Diffie-Hellman (X3DH) key agreement.

Classical (or KEM-only) handshake over the suite's ``key_exchange`` backend.
Post-quantum hybrid is a separate peer protocol in ``pqxdh.py``.
"""

from __future__ import annotations


from typing import TYPE_CHECKING

from ratchetkit.errors import InvalidKey
from ratchetkit.handshake.base import Handshake, HandshakeResult
from ratchetkit.handshake.message import InitialMessagePQXDH, InitialMessageX3DH
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.prekey import (
    OneTimePreKey,
    PreKeyBundle,
    SignedPqPreKey,
    SignedPreKey,
)
from ratchetkit.suite import KdfLabel

if TYPE_CHECKING:
    from ratchetkit.suite.double import CryptoSuiteDoubleRatchet as CryptoSuite


class ExtendedTripleDiffieHellman(Handshake):
    """X3DH handshake: bundle creation, initiate, respond."""

    kdf_info = KdfLabel.X3DH

    def __init__(self, suite: CryptoSuite):
        super().__init__(suite)

    def create_bundle(
        self,
        identity: IdentityKeyPair,
        signed_prekey: SignedPreKey,
        one_time_prekey: OneTimePreKey | None = None,
        pq_prekey: SignedPqPreKey | None = None,
    ) -> PreKeyBundle:
        if pq_prekey is not None:
            raise InvalidKey(
                "X3DH cannot use a PQ prekey bundle; "
                "use PostQuantumExtendedDiffieHellman"
            )
        bundle = PreKeyBundle.from_local(identity, signed_prekey, one_time_prekey)
        bundle.verify(self.suite)
        return bundle

    def initiate(
        self,
        our_identity: IdentityKeyPair,
        their_bundle: PreKeyBundle,
    ) -> HandshakeResult:
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
        signature = self.sign_initial_material(our_identity, to_sign)

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
        return HandshakeResult(
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
        self.check_prekey_ids(
            initial_message,
            our_signed_prekey,
            our_one_time_prekey,
        )
        self.validate_initial_algorithms(initial_message)
        self.verify_initial_signature(
            initial_message,
            our_signed_prekey.key_pair.public.data,
        )

        secrets: list[bytes] = []
        if self.kem.supports_dh:
            if our_identity.agreement is None:
                raise InvalidKey("DH suite requires identity agreement key")
            if initial_message.identity_agreement is None:
                raise InvalidKey("initial message missing identity agreement key")
            secrets.append(
                self.kem.dh(
                    our_signed_prekey.key_pair,
                    initial_message.identity_agreement,
                )
            )
            secrets.append(
                self.kem.dh(
                    our_identity.agreement,
                    initial_message.ephemeral_public,
                )
            )
            secrets.append(
                self.kem.dh(
                    our_signed_prekey.key_pair,
                    initial_message.ephemeral_public,
                )
            )
            if our_one_time_prekey is not None:
                secrets.append(
                    self.kem.dh(
                        our_one_time_prekey.key_pair,
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
