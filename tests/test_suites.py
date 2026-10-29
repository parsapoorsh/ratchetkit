"""Pluggability matrix across CryptoSuite combinations."""

import pytest

from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.prekey import OneTimePreKey, SignedPreKey
from ratchetkit.session import Session
from ratchetkit.suite import (
    SigningAlg,
    DEFAULT_TAG_SIZE,
    MIN_TAG_SIZE,
    CipherAlg,
    HashAlg,
    KeyExchangeAlg,
)
from ratchetkit.suite.double import CryptoSuiteDoubleRatchet
from ratchetkit.suite.triple import CryptoSuiteTripleRatchet
from tests.helpers import msg_counter


SUITES = [
    CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
        signing=SigningAlg.ED25519,
    ),
    CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA512,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X448,
        signing=SigningAlg.ED448,
    ),
    CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.CHACHA20,
        key_exchange=KeyExchangeAlg.X25519,
        signing=SigningAlg.ED25519,
    ),
    CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.SECP256R1,
        signing=SigningAlg.ECDSA_SECP256R1,
    ),
    CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.RSA3072,
        signing=SigningAlg.RSA_PSS_3072,
    ),
    # Post-quantum identity path: ML-KEM agreement + ML-DSA (still Double Ratchet)
    CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA3_256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.MLKEM768,
        signing=SigningAlg.MLDSA65,
    ),
    CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA512,
        cipher=CipherAlg.CHACHA20,
        key_exchange=KeyExchangeAlg.MLKEM1024,
        signing=SigningAlg.MLDSA87,
    ),
    # Triple Ratchet hybrids
    CryptoSuiteTripleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
        signing=SigningAlg.ED25519,
        pq_key_exchange=KeyExchangeAlg.MLKEM768,
        scka_chunks=2,
    ),
    CryptoSuiteTripleRatchet(
        digest=HashAlg.SHA3_256,
        cipher=CipherAlg.CHACHA20,
        key_exchange=KeyExchangeAlg.X25519,
        signing=SigningAlg.ED25519,
        pq_key_exchange=KeyExchangeAlg.MLKEM1024,
        scka_chunks=2,
    ),
]


def _open_suite(suite: CryptoSuite, plain: bytes = b"suite-hi"):
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(bob)
    opk = OneTimePreKey.generate(suite)
    if isinstance(suite, CryptoSuiteTripleRatchet):
        pq = suite.generate_pq_prekey(bob)
        bundle = suite.create_bundle(bob, spk, opk, pq)
        alice_sess, initial = Session.initiate(alice, bundle)
        first = alice_sess.encrypt(plain)
        bob_sess, got = Session.accept(
            bob,
            spk,
            initial,
            first,
            opk,
            our_pq_prekey=pq,
        )
    else:
        bundle = suite.create_bundle(bob, spk, opk)
        alice_sess, initial = Session.initiate(alice, bundle)
        first = alice_sess.encrypt(plain)
        bob_sess, got = Session.accept(bob, spk, initial, first, opk)
    assert got == plain
    return alice_sess, bob_sess, first


@pytest.mark.parametrize("suite", SUITES, ids=lambda s: repr(s))
def test_suite_roundtrip(suite: CryptoSuite):
    alice_sess, bob_sess, first = _open_suite(suite)
    reply = bob_sess.encrypt(b"suite-ack")
    assert alice_sess.decrypt(reply) == b"suite-ack"
    assert len(first.mac) == suite.tag_size


def test_default_tag_size():
    suite = CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
        signing=SigningAlg.ED25519,
    )
    assert suite.tag_size == DEFAULT_TAG_SIZE
    triple = CryptoSuiteTripleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
        signing=SigningAlg.ED25519,
        pq_key_exchange=KeyExchangeAlg.MLKEM768,
        scka_chunks=2,
    )
    assert triple.tag_size == DEFAULT_TAG_SIZE


def test_tag_size_bounds():
    with pytest.raises(ValueError, match="tag_size"):
        CryptoSuiteDoubleRatchet(
            digest=HashAlg.SHA256,
            cipher=CipherAlg.AES256,
            key_exchange=KeyExchangeAlg.X25519,
        signing=SigningAlg.ED25519,
            tag_size=MIN_TAG_SIZE - 1,
        )
    with pytest.raises(ValueError, match="tag_size"):
        CryptoSuiteDoubleRatchet(
            digest=HashAlg.SHA256,
            cipher=CipherAlg.AES256,
            key_exchange=KeyExchangeAlg.X25519,
        signing=SigningAlg.ED25519,
            tag_size=33,
        )
    with pytest.raises(ValueError, match="tag_size"):
        CryptoSuiteTripleRatchet(
            digest=HashAlg.SHA256,
            cipher=CipherAlg.AES256,
            key_exchange=KeyExchangeAlg.X25519,
        signing=SigningAlg.ED25519,
            pq_key_exchange=KeyExchangeAlg.MLKEM768,
            scka_chunks=2,
            tag_size=MIN_TAG_SIZE - 1,
        )


def test_tag_size_roundtrip_and_wire():
    for kind_suite in (
        CryptoSuiteDoubleRatchet(
            digest=HashAlg.SHA256,
            cipher=CipherAlg.AES256,
            key_exchange=KeyExchangeAlg.X25519,
        signing=SigningAlg.ED25519,
            tag_size=MIN_TAG_SIZE,
        ),
        CryptoSuiteTripleRatchet(
            digest=HashAlg.SHA256,
            cipher=CipherAlg.AES256,
            key_exchange=KeyExchangeAlg.X25519,
        signing=SigningAlg.ED25519,
            pq_key_exchange=KeyExchangeAlg.MLKEM768,
            scka_chunks=2,
            tag_size=MIN_TAG_SIZE,
        ),
    ):
        if isinstance(kind_suite, CryptoSuiteTripleRatchet):
            restored = CryptoSuiteTripleRatchet.from_bytes(kind_suite.to_bytes())
        else:
            restored = CryptoSuiteDoubleRatchet.from_bytes(kind_suite.to_bytes())
        assert restored.tag_size == MIN_TAG_SIZE
        alice_sess, bob_sess, first = _open_suite(kind_suite, plain=b"tag-hi")
        assert len(first.mac) == MIN_TAG_SIZE
        assert msg_counter(first) == 0
