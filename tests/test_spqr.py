"""Sparse Post-Quantum Ratchet tests."""

import pytest

from ratchetkit.algorithms.kem.mlkem768 import Mlkem768
from ratchetkit.errors import InvalidMessage
from ratchetkit.ratchet import SparsePostQuantumRatchet
from ratchetkit.suite import (
    SigningAlg,
    CipherAlg,
    CryptoSuiteTripleRatchet,
    HashAlg,
    KeyExchangeAlg,
)


def setup_spqr(n_chunks=2):
    suite = CryptoSuiteTripleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
        signing=SigningAlg.ED25519,
        pq_key_exchange=KeyExchangeAlg.MLKEM768,
        scka_chunks=n_chunks,
    )
    sk = b"\x42" * 32
    kem = Mlkem768()
    alice = SparsePostQuantumRatchet.initiate(suite, sk, kem, n_chunks=n_chunks)
    bob = SparsePostQuantumRatchet.accept(suite, sk, kem, n_chunks=n_chunks)
    return alice, bob


def test_spqr_ping_pong():
    alice, bob = setup_spqr(n_chunks=2)
    for i in range(6):
        header, ct, mac = alice.encrypt(f"a{i}".encode())
        assert bob.decrypt(header, ct, mac) == f"a{i}".encode()
        header, ct, mac = bob.encrypt(f"b{i}".encode())
        assert alice.decrypt(header, ct, mac) == f"b{i}".encode()


def test_spqr_out_of_order_same_epoch():
    alice, bob = setup_spqr(n_chunks=4)
    # Stay on epoch 0 for several messages (bootstrap still in flight).
    messages = [alice.encrypt(f"m{i}".encode()) for i in range(3)]
    order = [2, 0, 1]
    for idx in order:
        header, ct, mac = messages[idx]
        assert bob.decrypt(header, ct, mac) == f"m{idx}".encode()


def test_spqr_bad_mac_rejected():
    alice, bob = setup_spqr(n_chunks=2)
    header, ct, mac = alice.encrypt(b"tamper")
    bad = bytes([mac[0] ^ 0xFF]) + mac[1:]
    with pytest.raises(InvalidMessage):
        bob.decrypt(header, ct, bad)
    # Real message still works (state not committed on failure).
    assert bob.decrypt(header, ct, mac) == b"tamper"
