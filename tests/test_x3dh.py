"""X3DH handshake tests via the suite public API."""

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


def test_x3dh_both_sides_same_secret():
    suite = CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
        signing=SigningAlg.ED25519,
    )
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob, suite)
    opk = OneTimePreKey.generate(7, suite)
    bundle = suite.create_bundle(bob, spk, opk)
    alice_sess, initial = suite.initiate(alice, bundle)
    first = alice_sess.encrypt(b"hello")
    bob_sess, plain = suite.accept(bob, spk, initial, first, opk)
    assert plain == b"hello"
    assert alice_sess.decrypt(bob_sess.encrypt(b"ack")) == b"ack"


def test_x3dh_without_one_time_prekey():
    suite = CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
        signing=SigningAlg.ED25519,
    )
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob, suite)
    bundle = suite.create_bundle(bob, spk, None)
    alice_sess, initial = suite.initiate(alice, bundle)
    first = alice_sess.encrypt(b"hello")
    bob_sess, plain = suite.accept(bob, spk, initial, first, None)
    assert plain == b"hello"


def test_x3dh_rejects_tampered_spk_signature():
    suite = CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
        signing=SigningAlg.ED25519,
    )
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob, suite)
    bundle = suite.create_bundle(bob, spk, None)
    bad = type(bundle)(
        identity_signing=bundle.identity_signing,
        identity_agreement=bundle.identity_agreement,
        signed_prekey_id=bundle.signed_prekey_id,
        signed_prekey=bundle.signed_prekey,
        signed_prekey_signature=bytes(
            b ^ 0xFF for b in bundle.signed_prekey_signature
        ),
        one_time_prekey_id=bundle.one_time_prekey_id,
        one_time_prekey=bundle.one_time_prekey,
    )
    with pytest.raises(InvalidSignature):
        suite.initiate(alice, bad)
