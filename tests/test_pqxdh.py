"""PQXDH handshake and bundle integration tests."""

import pytest

from ratchetkit.errors import InvalidKey, InvalidSignature
from ratchetkit.handshake.message import InitialMessagePQXDH
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.prekey import OneTimePreKey, SignedPreKey

from ratchetkit.suite import (
    SigningAlg,
    CipherAlg,
    HashAlg,
    KeyExchangeAlg,
)
from ratchetkit.suite.double import CryptoSuiteDoubleRatchet
from ratchetkit.suite.triple import CryptoSuiteTripleRatchet


def triple_suite():
    return CryptoSuiteTripleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
        signing=SigningAlg.ED25519,
        pq_key_exchange=KeyExchangeAlg.MLKEM768,
        scka_chunks=2,
    )


def test_suite_create_bundle_double():
    suite = CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
        signing=SigningAlg.ED25519,
    )
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob, suite)
    opk = OneTimePreKey.generate(1, suite)
    bundle = suite.create_bundle(bob, spk, opk)
    assert bundle.pq_prekey is None


def test_suite_create_bundle_triple_requires_pq_prekey():
    suite = triple_suite()
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob, suite)
    opk = OneTimePreKey.generate(1, suite)
    with pytest.raises(TypeError):
        suite.create_bundle(bob, spk)  # type: ignore[call-arg]
    pq = suite.generate_pq_prekey(7, bob)
    bundle = suite.create_bundle(bob, spk, pq, opk)
    assert bundle.pq_prekey_id == 7
    assert bundle.pq_prekey is not None


def test_pqxdh_both_sides_same_secret():
    suite = triple_suite()
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob, suite)
    opk = OneTimePreKey.generate(1, suite)
    pq = suite.generate_pq_prekey(1, bob)
    bundle = suite.create_bundle(bob, spk, pq, opk)
    alice_sess, initial = suite.initiate(alice, bundle)
    first = alice_sess.encrypt(b"hello")
    bob_sess, plain = suite.accept(
        bob,
        spk,
        initial,
        first,
        opk,
        our_pq_prekey=pq,
    )
    assert plain == b"hello"
    assert initial.pq_ciphertext is not None
    assert initial.pq_prekey_id == 1
    assert alice_sess.decrypt(bob_sess.encrypt(b"ack")) == b"ack"


def test_pqxdh_without_one_time_prekey():
    suite = triple_suite()
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob, suite)
    pq = suite.generate_pq_prekey(1, bob)
    bundle = suite.create_bundle(bob, spk, pq, None)
    alice_sess, initial = suite.initiate(alice, bundle)
    first = alice_sess.encrypt(b"hello")
    bob_sess, plain = suite.accept(
        bob,
        spk,
        initial,
        first,
        None,
        our_pq_prekey=pq,
    )
    assert plain == b"hello"


def test_pqxdh_bad_signature_rejected():
    suite = triple_suite()
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob, suite)
    opk = OneTimePreKey.generate(1, suite)
    pq = suite.generate_pq_prekey(1, bob)
    bundle = suite.create_bundle(bob, spk, pq, opk)
    alice_sess, initial = suite.initiate(alice, bundle)
    first = alice_sess.encrypt(b"x")
    bad = InitialMessagePQXDH(
        identity_signing=initial.identity_signing,
        identity_agreement=initial.identity_agreement,
        ephemeral_public=initial.ephemeral_public,
        kem_ciphertexts=initial.kem_ciphertexts,
        signed_prekey_id=initial.signed_prekey_id,
        one_time_prekey_id=initial.one_time_prekey_id,
        signature=bytes([initial.signature[0] ^ 0xFF]) + initial.signature[1:],
        ratchet_public=initial.ratchet_public,
        pq_prekey_id=initial.pq_prekey_id,
        pq_ciphertext=initial.pq_ciphertext,
    )
    with pytest.raises(InvalidSignature):
        suite.accept(bob, spk, bad, first, opk, our_pq_prekey=pq)


def test_pqxdh_ciphertext_swap_rejected():
    suite = triple_suite()
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob, suite)
    opk = OneTimePreKey.generate(1, suite)
    pq = suite.generate_pq_prekey(1, bob)
    bundle = suite.create_bundle(bob, spk, pq, opk)
    alice_sess, initial = suite.initiate(alice, bundle)
    first = alice_sess.encrypt(b"x")
    _, other_ct = suite.pq_kem.encapsulate(pq.key_pair.public)
    swapped = InitialMessagePQXDH(
        identity_signing=initial.identity_signing,
        identity_agreement=initial.identity_agreement,
        ephemeral_public=initial.ephemeral_public,
        kem_ciphertexts=initial.kem_ciphertexts,
        signed_prekey_id=initial.signed_prekey_id,
        one_time_prekey_id=initial.one_time_prekey_id,
        signature=initial.signature,
        ratchet_public=initial.ratchet_public,
        pq_prekey_id=initial.pq_prekey_id,
        pq_ciphertext=other_ct,
    )
    with pytest.raises(InvalidSignature):
        suite.accept(bob, spk, swapped, first, opk, our_pq_prekey=pq)


def test_x3dh_rejects_pq_bundle():
    suite = triple_suite()
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob, suite)
    opk = OneTimePreKey.generate(1, suite)
    pq = suite.generate_pq_prekey(1, bob)
    bundle = suite.create_bundle(bob, spk, pq, opk)
    alice = IdentityKeyPair.generate(suite)
    double = CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
        signing=SigningAlg.ED25519,
    )
    with pytest.raises(InvalidKey, match="PQ prekey"):
        double.initiate(alice, bundle)


def test_session_triple_via_pqxdh():
    suite = triple_suite()
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob, suite)
    opk = OneTimePreKey.generate(1, suite)
    pq = suite.generate_pq_prekey(1, bob)
    bundle = suite.create_bundle(bob, spk, pq, opk)
    a_sess, initial = suite.initiate(alice, bundle)
    assert initial.pq_ciphertext is not None
    first = a_sess.encrypt(b"pq-session")
    b_sess, plain = suite.accept(
        bob,
        spk,
        initial,
        first,
        opk,
        our_pq_prekey=pq,
    )
    assert plain == b"pq-session"
    assert a_sess.decrypt(b_sess.encrypt(b"ack")) == b"ack"


def test_bundle_and_initial_roundtrip_with_pq_fields():
    suite = triple_suite()
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob, suite)
    opk = OneTimePreKey.generate(3, suite)
    pq = suite.generate_pq_prekey(9, bob)
    bundle = suite.create_bundle(bob, spk, pq, opk)
    restored = type(bundle).from_bytes(bundle.to_bytes())
    assert restored.pq_prekey_id == 9
    assert restored.pq_prekey == bundle.pq_prekey
    assert restored.pq_prekey_signature == bundle.pq_prekey_signature

    alice = IdentityKeyPair.generate(suite)
    _sess, initial = suite.initiate(alice, restored)
    init2 = InitialMessagePQXDH.from_bytes(initial.to_bytes())
    assert init2.pq_prekey_id == 9
    assert init2.pq_ciphertext == initial.pq_ciphertext
