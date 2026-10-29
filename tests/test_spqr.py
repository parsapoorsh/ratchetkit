"""Sparse Post-Quantum Ratchet tests."""

import pytest

from ratchetkit.algorithms.kem.mlkem768 import Mlkem768
from ratchetkit.errors import InvalidMessage
from ratchetkit.ratchet import SparsePostQuantumRatchet
from ratchetkit.suite import (
    SigningAlg,
    CipherAlg,
    HashAlg,
    KeyExchangeAlg,
)
from ratchetkit.suite.triple import CryptoSuiteTripleRatchet


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


def test_spqr_early_send_activation_on_ack():
    """Paper TR-Send: t_s advances once peer_ack + 1 >= n_chunks."""
    alice, bob = setup_spqr(n_chunks=2)

    # Epoch 0 messages while Alice bootstraps her PQ public key (2 chunks).
    h0, ct0, mac0 = alice.encrypt(b"boot0")
    assert h0.t_s == 0
    assert bob.decrypt(h0, ct0, mac0) == b"boot0"
    h1, ct1, mac1 = alice.encrypt(b"boot1")
    assert h1.t_s == 0
    assert bob.decrypt(h1, ct1, mac1) == b"boot1"

    # Bob now owns CKA turn and will encapsulate (mix on first drip).
    assert bob.scka.is_cka_sender
    assert alice.t_s == 0 and bob.t_s == 0

    # Bob's first post-bootstrap send mixes epoch 1 but stays on t_s=0.
    hb0, ctb0, macb0 = bob.encrypt(b"ex0")
    assert bob.mixed_epoch == 1
    assert bob.t_curr == 1
    assert hb0.t_s == 0
    assert alice.decrypt(hb0, ctb0, macb0) == b"ex0"
    # Alice holds 1 of Bob's chunks after first drip.
    assert len(alice.scka.recv_chunks) == 1

    # Alice replies; her ack_count reflects the one chunk she holds.
    # Bob learns peer_ack and early-activates on the next send.
    ha, cta, maca = alice.encrypt(b"ack-chunk")
    assert bob.decrypt(ha, cta, maca) == b"ack-chunk"
    assert bob.scka.peer_ack >= 1

    # Bob's next send: peer_ack+1 >= 2 → activate t_s=1.
    hb1, ctb1, macb1 = bob.encrypt(b"ex1")
    assert hb1.t_s == 1
    assert bob.t_s == 1
    assert alice.decrypt(hb1, ctb1, macb1) == b"ex1"
    assert alice.t_r == 1
    # Alice also activates send once she mixed epoch 1 (full reconstruction).
    assert alice.mixed_epoch == 1
    assert alice.t_s == 1


def test_spqr_header_carries_epoch_schedule():
    alice, bob = setup_spqr(n_chunks=2)
    header, ct, mac = alice.encrypt(b"sched")
    assert header.t_s == 0
    assert header.previous_counter == 0
    assert header.previous2_counter == 0
    restored = type(header).from_bytes(header.to_bytes())
    assert restored.t_s == header.t_s
    assert restored.counter == header.counter
    assert bob.decrypt(restored, ct, mac) == b"sched"


def test_spqr_state_roundtrip():
    alice, bob = setup_spqr(n_chunks=2)
    for i in range(3):
        h, ct, mac = alice.encrypt(f"a{i}".encode())
        bob.decrypt(h, ct, mac)
        h, ct, mac = bob.encrypt(f"b{i}".encode())
        alice.decrypt(h, ct, mac)

    blob = alice.to_bytes()
    restored = type(alice).from_bytes(blob, alice.suite, alice.scka.kem)
    assert restored.t_s == alice.t_s
    assert restored.t_r == alice.t_r
    assert restored.t_curr == alice.t_curr
    assert restored.mixed_epoch == alice.mixed_epoch
    assert restored.previous_counter == alice.previous_counter
    assert restored.previous2_counter == alice.previous2_counter
    h, ct, mac = restored.encrypt(b"after-restore")
    assert bob.decrypt(h, ct, mac) == b"after-restore"
