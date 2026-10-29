"""ExtendedTripleDiffieHellman handshake tests."""

import pytest

from ratchetkit.errors import InvalidSignature
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.prekey import OneTimePreKey, SignedPreKey
from ratchetkit.suite import (
    CipherAlg,
    HashAlg,
    KeyExchangeAlg,
    SigningAlg,
)
from ratchetkit.suite.double import CryptoSuiteDoubleRatchet
from ratchetkit.suite.registry import hash_backend
from ratchetkit.handshake import ExtendedTripleDiffieHellman


def test_x3dh_both_sides_same_secret():
    suite = CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
        signing=SigningAlg.ED25519,
    )
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(bob)
    opk = OneTimePreKey.generate(suite)
    x3dh = ExtendedTripleDiffieHellman(suite)
    bundle = x3dh.create_bundle(bob, spk, opk)
    result = x3dh.initiate(alice, bundle)
    bob_secret = x3dh.respond(bob, spk, result.initial_message, opk)
    assert result.shared_secret == bob_secret
    assert len(result.shared_secret) == hash_backend(suite.digest).digest_size



def test_x3dh_rejects_tampered_spk_signature():
    suite = CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
        signing=SigningAlg.ED25519,
    )
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(bob)
    opk = OneTimePreKey.generate(suite)
    x3dh = ExtendedTripleDiffieHellman(suite)
    bundle = x3dh.create_bundle(bob, spk, opk)
    bad = type(bundle)(
        identity_signing=bundle.identity_signing,
        identity_agreement=bundle.identity_agreement,
        signed_prekey=bundle.signed_prekey,
        signed_prekey_signature=bytes(
            b ^ 0xFF for b in bundle.signed_prekey_signature
        ),
        one_time_prekey=bundle.one_time_prekey,
    )
    with pytest.raises(InvalidSignature):
        x3dh.initiate(alice, bad)
