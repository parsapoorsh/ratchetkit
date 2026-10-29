"""Triple Ratchet (Double Ratchet + SPQR) tests."""

import pytest

from ratchetkit.errors import InvalidMessage
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.prekey import OneTimePreKey, SignedPreKey
from ratchetkit.ratchet import TripleRatchet, TripleRatchetMessage
from ratchetkit.session import Session
from ratchetkit.suite import (
    SigningAlg,
    CipherAlg,
    CryptoSuiteTripleRatchet,
    HashAlg,
    KeyExchangeAlg,
)


def triple_suite(n_chunks=2):
    return CryptoSuiteTripleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
        signing=SigningAlg.ED25519,
        pq_key_exchange=KeyExchangeAlg.MLKEM768,
        scka_chunks=n_chunks,
    )


def setup_triple(n_chunks=2):
    suite = triple_suite(n_chunks)
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob)
    opk = OneTimePreKey.generate(1, suite)
    pq = suite.generate_pq_prekey(1, bob)
    bundle = suite.create_bundle(bob, spk, opk, pq)
    alice_sess, initial = Session.initiate(alice, bundle)
    assert isinstance(alice_sess.ratchet, TripleRatchet)
    first = alice_sess.encrypt(b"hi")
    assert isinstance(first, TripleRatchetMessage)
    bob_sess, plain = Session.accept(
        bob,
        spk,
        initial,
        first,
        opk,
        our_pq_prekey=pq,
    )
    assert plain == b"hi"
    assert isinstance(bob_sess.ratchet, TripleRatchet)
    return alice_sess, bob_sess, suite


def test_triple_session_ping_pong():
    alice, bob = setup_triple(n_chunks=2)[:2]
    for i in range(8):
        m = alice.encrypt(f"a{i}".encode())
        assert bob.decrypt(m) == f"a{i}".encode()
        m = bob.encrypt(f"b{i}".encode())
        assert alice.decrypt(m) == f"b{i}".encode()


def test_triple_out_of_order():
    alice, bob = setup_triple(n_chunks=4)[:2]
    messages = [alice.encrypt(f"m{i}".encode()) for i in range(4)]
    for idx in [1, 3, 0, 2]:
        assert bob.decrypt(messages[idx]) == f"m{idx}".encode()


def test_triple_forged_mac_does_not_desync():
    alice, bob = setup_triple(n_chunks=2)[:2]
    real = alice.encrypt(b"real")
    forged = TripleRatchetMessage(
        ec_message=real.ec_message,
        spqr_header=real.spqr_header,
        ciphertext=b"\x00" * len(real.ciphertext),
        mac=b"\x00" * len(real.mac),
    )
    with pytest.raises(InvalidMessage):
        bob.decrypt(forged)
    assert bob.decrypt(real) == b"real"


def test_triple_message_bytes_roundtrip():
    alice, bob = setup_triple(n_chunks=2)[:2]
    m = alice.encrypt(b"wire")
    restored = TripleRatchetMessage.from_bytes(m.to_bytes())
    assert bob.decrypt(restored) == b"wire"


def test_triple_with_mlkem1024():
    suite = CryptoSuiteTripleRatchet(
        digest=HashAlg.SHA3_256,
        cipher=CipherAlg.CHACHA20,
        key_exchange=KeyExchangeAlg.X25519,
        signing=SigningAlg.ED25519,
        pq_key_exchange=KeyExchangeAlg.MLKEM1024,
        scka_chunks=2,
    )
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob)
    opk = OneTimePreKey.generate(1, suite)
    pq = suite.generate_pq_prekey(1, bob)
    bundle = suite.create_bundle(bob, spk, opk, pq)
    a_sess, initial = Session.initiate(alice, bundle)
    first = a_sess.encrypt(b"pq")
    b_sess, plain = Session.accept(
        bob,
        spk,
        initial,
        first,
        opk,
        our_pq_prekey=pq,
    )
    assert plain == b"pq"
    assert a_sess.decrypt(b_sess.encrypt(b"ack")) == b"ack"
