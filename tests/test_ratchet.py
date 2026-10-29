"""Ratchet behavior tests (Double and Triple suites)."""

import pytest

from ratchetkit.errors import DuplicateMessage, InvalidMessage


def test_ping_pong(pair):
    kind, alice, bob, suite = pair
    for i in range(10):
        m = alice.encrypt(f"a{i}".encode())
        assert bob.decrypt(m) == f"a{i}".encode()
        m = bob.encrypt(f"b{i}".encode())
        assert alice.decrypt(m) == f"b{i}".encode()


def test_out_of_order(pair):
    kind, alice, bob, suite = pair
    messages = [alice.encrypt(f"m{i}".encode()) for i in range(5)]
    # Deliver out of order.
    order = [2, 0, 4, 1, 3]
    for idx in order:
        assert bob.decrypt(messages[idx]) == f"m{idx}".encode()


def test_duplicate_rejected(pair):
    kind, alice, bob, suite = pair
    m = alice.encrypt(b"once")
    assert bob.decrypt(m) == b"once"
    with pytest.raises((DuplicateMessage, InvalidMessage)):
        bob.decrypt(m)


def test_wrong_mac_rejected(pair):
    kind, alice, bob, suite = pair
    m = alice.encrypt(b"tamper")
    # Mutate ciphertext on the object, re-serialize path not required.
    m.ciphertext = bytes([m.ciphertext[0] ^ 0xFF]) + m.ciphertext[1:]
    with pytest.raises(InvalidMessage):
        bob.decrypt(m)


def test_message_bytes_roundtrip(pair):
    kind, alice, bob, suite = pair
    m = alice.encrypt(b"wire")
    restored = type(m).from_bytes(m.to_bytes())
    assert bob.decrypt(restored) == b"wire"
