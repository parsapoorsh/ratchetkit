"""ExtendedTripleDiffieHellman handshake tests."""

import pytest

from ratchetkit.errors import InvalidSignature
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.prekey import OneTimePreKey, SignedPreKey
from ratchetkit.suite import CipherAlg, CryptoSuiteDoubleRatchet, HashAlg, KeyExchangeAlg
from ratchetkit.handshake import ExtendedTripleDiffieHellman


def test_x3dh_both_sides_same_secret():
    suite = CryptoSuiteDoubleRatchet(digest=HashAlg.SHA256, cipher=CipherAlg.AES256, key_exchange=KeyExchangeAlg.X25519)
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob)
    opk = OneTimePreKey.generate(7, suite)
    x3dh = ExtendedTripleDiffieHellman(suite)
    bundle = x3dh.create_bundle(bob, spk, opk)

    result = x3dh.initiate(alice, bundle)
    bob_secret = x3dh.respond(bob, spk, result.initial_message, opk)
    assert result.shared_secret == bob_secret
    assert len(result.shared_secret) == suite.digest.impl.digest_size


def test_x3dh_without_one_time_prekey():
    suite = CryptoSuiteDoubleRatchet(digest=HashAlg.SHA256, cipher=CipherAlg.AES256, key_exchange=KeyExchangeAlg.X25519)
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob)
    x3dh = ExtendedTripleDiffieHellman(suite)
    bundle = x3dh.create_bundle(bob, spk)
    result = x3dh.initiate(alice, bundle)
    bob_secret = x3dh.respond(bob, spk, result.initial_message)
    assert result.shared_secret == bob_secret


def test_x3dh_bad_signature_rejected():
    suite = CryptoSuiteDoubleRatchet(digest=HashAlg.SHA256, cipher=CipherAlg.AES256, key_exchange=KeyExchangeAlg.X25519)
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob)
    x3dh = ExtendedTripleDiffieHellman(suite)
    bundle = x3dh.create_bundle(bob, spk)
    # Corrupt signature on the bundle.
    bad = type(bundle)(
        identity_signing=bundle.identity_signing,
        identity_agreement=bundle.identity_agreement,
        signed_prekey_id=bundle.signed_prekey_id,
        signed_prekey=bundle.signed_prekey,
        signed_prekey_signature=b"\x00" * len(bundle.signed_prekey_signature),
        one_time_prekey_id=bundle.one_time_prekey_id,
        one_time_prekey=bundle.one_time_prekey,
    )
    with pytest.raises(InvalidSignature):
        x3dh.initiate(alice, bad)
