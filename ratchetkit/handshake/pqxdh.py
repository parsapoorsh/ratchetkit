"""Post-Quantum Extended Diffie-Hellman (PQXDH) key agreement.

Peer protocol to :class:`~ratchetkit.handshake.x3dh.ExtendedTripleDiffieHellman`.
Classical X3DH DH secrets plus one encapsulation to the peer's signed PQ
prekey (typically ML-KEM).

Native ratchetkit framing - not Signal protobuf / wire-compatible.

  SK = KDF_PQXDH(0xFF*n || DH1 || DH2 || DH3 || [DH4] || SS_pq)
"""

from __future__ import annotations


from typing import TYPE_CHECKING

from ratchetkit.errors import InvalidKey
from ratchetkit.handshake.base import Handshake, HandshakeResult
from ratchetkit.handshake.message import InitialMessagePQXDH
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.prekey import (
    OneTimePreKey,
    PreKeyBundle,
    SignedPqPreKey,
    SignedPreKey,
)
from ratchetkit.suite import KdfLabel

if TYPE_CHECKING:
    from ratchetkit.algorithms.kem.base import KemBackend
    from ratchetkit.suite.double import CryptoSuiteDoubleRatchet as CryptoSuite


class PostQuantumExtendedDiffieHellman(Handshake):
    """PQXDH: classical DH X3DH + required PQ KEM encapsulation.

    Requires a DH-capable classical ``suite.kem`` and a separate ``pq_kem``.
    """

    kdf_info = KdfLabel.PQXDH

    def __init__(
        self,
        suite: CryptoSuite,
        pq_kem: KemBackend,
    ):
        if not suite.kem.supports_dh:
            raise InvalidKey(
                "PQXDH requires a DH-capable classical key_exchange "
                f"(got {suite.kem.algorithm!r})"
            )
        super().__init__(suite)
        self.pq_kem = pq_kem

    def create_bundle(
        self,
        identity: IdentityKeyPair,
        signed_prekey: SignedPreKey,
        one_time_prekey: OneTimePreKey | None = None,
        pq_prekey: SignedPqPreKey | None = None,
    ) -> PreKeyBundle:
        if pq_prekey is None:
            raise InvalidKey("PQXDH bundle requires a signed PQ prekey")
        if pq_prekey.key_pair.public.algorithm != self.pq_kem.algorithm:
            raise InvalidKey(
                f"PQ prekey algorithm {pq_prekey.key_pair.public.algorithm!r} "
                f"does not match pq_kem {self.pq_kem.algorithm!r}"
            )
        bundle = PreKeyBundle.from_local(
            identity,
            signed_prekey,
            one_time_prekey,
            pq_prekey,
        )
        bundle.verify(self.suite)
        return bundle

    def initiate(
        self,
        our_identity: IdentityKeyPair,
        their_bundle: PreKeyBundle,
    ) -> HandshakeResult:
        their_bundle.verify(self.suite)
        if their_bundle.pq_prekey is None or their_bundle.pq_prekey_id is None:
            raise InvalidKey("PQXDH requires a PQ prekey on the bundle")
        if their_bundle.pq_prekey.algorithm != self.pq_kem.algorithm:
            raise InvalidKey(
                f"bundle PQ prekey algorithm {their_bundle.pq_prekey.algorithm!r} "
                f"does not match pq_kem {self.pq_kem.algorithm!r}"
            )
        if our_identity.agreement is None:
            raise InvalidKey("DH suite requires identity agreement key")
        if their_bundle.identity_agreement is None:
            raise InvalidKey("bundle missing identity agreement key")

        ephemeral = self.kem.generate_keypair()
        secrets: list[bytes] = [
            self.kem.dh(our_identity.agreement, their_bundle.signed_prekey),
            self.kem.dh(ephemeral, their_bundle.identity_agreement),
            self.kem.dh(ephemeral, their_bundle.signed_prekey),
        ]
        if their_bundle.one_time_prekey is not None:
            secrets.append(
                self.kem.dh(ephemeral, their_bundle.one_time_prekey)
            )

        pq_secret, pq_ciphertext = self.pq_kem.encapsulate(their_bundle.pq_prekey)
        secrets.append(pq_secret)

        shared = self.derive_secret(secrets)
        ratchet_key = self.kem.generate_keypair()
        identity_agreement = our_identity.agreement.public

        to_sign = InitialMessagePQXDH.signed_material(
            identity_agreement_data=identity_agreement.data,
            ephemeral_public=ephemeral.public.data,
            signed_prekey_public=their_bundle.signed_prekey.data,
            kem_ciphertexts=[],
            ratchet_public=ratchet_key.public.data,
            pq_ciphertext=pq_ciphertext,
        )
        signature = self.sign_initial_material(our_identity, to_sign)

        message = InitialMessagePQXDH(
            identity_signing=our_identity.signing.public,
            identity_agreement=identity_agreement,
            ephemeral_public=ephemeral.public,
            kem_ciphertexts=(),
            signed_prekey_id=their_bundle.signed_prekey_id,
            one_time_prekey_id=their_bundle.one_time_prekey_id,
            signature=signature,
            ratchet_public=ratchet_key.public.data,
            pq_prekey_id=their_bundle.pq_prekey_id,
            pq_ciphertext=pq_ciphertext,
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
        initial_message: InitialMessagePQXDH,
        our_one_time_prekey: OneTimePreKey | None = None,
        our_pq_prekey: SignedPqPreKey | None = None,
    ) -> bytes:
        if our_pq_prekey is None:
            raise InvalidKey("PQXDH respond requires our_pq_prekey")
        if not initial_message.pq_ciphertext:
            raise InvalidKey("PQXDH initial message missing pq_ciphertext")
        if our_pq_prekey.key_pair.public.algorithm != self.pq_kem.algorithm:
            raise InvalidKey(
                f"local PQ prekey algorithm "
                f"{our_pq_prekey.key_pair.public.algorithm!r} "
                f"does not match pq_kem {self.pq_kem.algorithm!r}"
            )
        if our_identity.agreement is None:
            raise InvalidKey("DH suite requires identity agreement key")
        if initial_message.identity_agreement is None:
            raise InvalidKey("initial message missing identity agreement key")

        initial_message.check_prekey_ids(
            our_signed_prekey,
            our_one_time_prekey,
            our_pq_prekey_id=our_pq_prekey.key_id,
        )
        self.validate_initial_algorithms(initial_message)
        initial_message.verify_initial_signature(
            self.suite,
            our_signed_prekey.key_pair.public.data,
        )

        secrets: list[bytes] = [
            self.kem.dh(
                our_signed_prekey.key_pair,
                initial_message.identity_agreement,
            ),
            self.kem.dh(
                our_identity.agreement,
                initial_message.ephemeral_public,
            ),
            self.kem.dh(
                our_signed_prekey.key_pair,
                initial_message.ephemeral_public,
            ),
        ]
        if our_one_time_prekey is not None:
            secrets.append(
                self.kem.dh(
                    our_one_time_prekey.key_pair,
                    initial_message.ephemeral_public,
                )
            )
        secrets.append(
            self.pq_kem.decapsulate(
                our_pq_prekey.key_pair,
                initial_message.pq_ciphertext,
            )
        )
        return self.derive_secret(secrets)
