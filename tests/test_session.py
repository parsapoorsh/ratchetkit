"""Session high-level API tests (Double and Triple suites)."""

import pytest

from ratchetkit.errors import InvalidMessage
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.prekey import OneTimePreKey, SignedPreKey
from ratchetkit.session import Session
from tests.helpers import (
    make_suite,
    message_type_for,
    msg_counter,
    open_pair,
)


def test_full_conversation(pair):
    kind = pair[0]
    alice, bob, suite, *_rest, first = open_pair(kind, first_plain=b"hello")
    assert msg_counter(first) == 0
    msg = alice.encrypt(b"again")
    assert bob.decrypt(msg) == b"again"
    reply = bob.encrypt(b"ack")
    assert alice.decrypt(reply) == b"ack"


def test_ratchet_message_bytes_roundtrip(pair):
    kind = pair[0]
    suite = make_suite(kind)
    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob_id)
    opk = OneTimePreKey.generate(1, suite)
    if kind == "triple":
        pq = suite.generate_pq_prekey(1, bob_id)
        bundle = suite.create_bundle(bob_id, spk, opk, pq)
        alice, initial = Session.initiate(alice_id, bundle)
        first = alice.encrypt(b"wire")
        restored = type(first).from_bytes(first.to_bytes())
        bob, plain = Session.accept(
            bob_id,
            spk,
            initial,
            restored,
            opk,
            our_pq_prekey=pq,
        )
    else:
        bundle = suite.create_bundle(bob_id, spk, opk)
        alice, initial = Session.initiate(alice_id, bundle)
        first = alice.encrypt(b"wire")
        restored = type(first).from_bytes(first.to_bytes())
        bob, plain = Session.accept(bob_id, spk, initial, restored, opk)
    assert plain == b"wire"


def test_session_bytes_roundtrip(pair):
    kind, alice, bob, suite = pair
    alice2 = Session.from_bytes(alice.to_bytes())
    bob2 = Session.from_bytes(bob.to_bytes())

    msg = alice2.encrypt(b"after restore")
    assert isinstance(msg, message_type_for(kind))
    assert bob2.decrypt(msg) == b"after restore"
    reply = bob2.encrypt(b"ack restore")
    assert alice2.decrypt(reply) == b"ack restore"


def test_session_bytes_out_of_order_after_restore(pair):
    kind, alice, bob, suite = pair
    pending = [alice.encrypt(f"m{i}".encode()) for i in range(3)]
    bob2 = Session.from_bytes(bob.to_bytes())
    for idx in (2, 0, 1):
        assert bob2.decrypt(pending[idx]) == f"m{idx}".encode()


def test_session_extra_associated_data(pair):
    kind, alice, bob, suite = pair
    extra = b"msg-id:42"
    msg = alice.encrypt(b"bound", associated_data=extra)
    # Wrong / missing extra AD fails MAC before state commit.
    with pytest.raises(InvalidMessage):
        bob.decrypt(msg, associated_data=b"wrong")
    with pytest.raises(InvalidMessage):
        bob.decrypt(msg)
    assert bob.decrypt(msg, associated_data=extra) == b"bound"


def test_session_accept_extra_associated_data(pair):
    kind = pair[0]
    suite = make_suite(kind)
    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob_id)
    opk = OneTimePreKey.generate(1, suite)
    extra = b"first-extra"
    if kind == "triple":
        pq = suite.generate_pq_prekey(1, bob_id)
        bundle = suite.create_bundle(bob_id, spk, opk, pq)
        alice, initial = Session.initiate(alice_id, bundle)
        first = alice.encrypt(b"hello-ad", associated_data=extra)
        bob, plain = Session.accept(
            bob_id,
            spk,
            initial,
            first,
            opk,
            associated_data=extra,
            our_pq_prekey=pq,
        )
    else:
        bundle = suite.create_bundle(bob_id, spk, opk)
        alice, initial = Session.initiate(alice_id, bundle)
        first = alice.encrypt(b"hello-ad", associated_data=extra)
        bob, plain = Session.accept(
            bob_id,
            spk,
            initial,
            first,
            opk,
            associated_data=extra,
        )
    assert plain == b"hello-ad"
    reply = bob.encrypt(b"ack", associated_data=b"r1")
    assert alice.decrypt(reply, associated_data=b"r1") == b"ack"
