"""Compromise and post-compromise security tests for Double Ratchet.

Models a one-shot state theft: attacker freezes a session snapshot, then
honest parties keep talking. The attacker may also see public wire messages.
These tests lock the properties discussed in the Double Ratchet design:

- Root-only leak is not enough to read later traffic.
- A stolen sending/receiving chain key opens that chain until the next DH step.
- A full live-state snapshot can follow traffic until a later DH ratchet
  installs a private key the snapshot never learned (PCS healing).
- Already-consumed message keys are gone from state (forward secrecy of past).
"""

from __future__ import annotations

import pytest

from ratchetkit.errors import DuplicateMessage, InvalidMessage
from ratchetkit.keys.chain import ChainKey
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.message import MessageKeys
from ratchetkit.keys.prekey import OneTimePreKey, SignedPreKey
from ratchetkit.keys.root import RootKey
from ratchetkit.ratchet.message import DoubleRatchetMessage
from ratchetkit.ratchet.protocol.double import DoubleRatchet
from ratchetkit.session import Session
from ratchetkit.suite import CipherAlg, CryptoSuiteDoubleRatchet, HashAlg, KeyExchangeAlg


def double_suite() -> CryptoSuiteDoubleRatchet:
    return CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
    )


def open_pair(first_plain: bytes = b"setup"):
    suite = double_suite()
    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob_id)
    opk = OneTimePreKey.generate(1, suite)
    bundle = suite.create_bundle(bob_id, spk, opk)
    alice, initial = Session.initiate(alice_id, bundle)
    first = alice.encrypt(first_plain)
    bob, plain = Session.accept(bob_id, spk, initial, first, opk)
    assert plain == first_plain
    return alice, bob, suite


def freeze(session: Session) -> Session:
    """One-shot device compromise: attacker keeps a frozen copy of state."""
    return Session.from_bytes(session.to_bytes())


def try_decrypt(session: Session, message: DoubleRatchetMessage) -> bytes | None:
    try:
        return session.decrypt(message)
    except (InvalidMessage, DuplicateMessage):
        return None


def chain_message_keys(chain: ChainKey, count: int) -> list[MessageKeys]:
    """Derive ``count`` successive message keys without mutating ``chain``."""
    keys = []
    current = ChainKey(chain.key, chain.index, chain.suite)
    for _ in range(count):
        keys.append(current.message_keys())
        current = current.next_chain_key()
    return keys


def decrypt_with_message_keys(
    keys: MessageKeys,
    message: DoubleRatchetMessage,
    suite: CryptoSuiteDoubleRatchet,
    associated_data: bytes,
) -> bytes | None:
    """Passive decrypt using a stolen message key (cipher + MAC check)."""
    expected = DoubleRatchet(
        suite=suite,
        root_key=RootKey(b"\x01" * suite.digest.value.digest_size, suite),
    ).compute_mac(
        keys,
        message.header_bytes(),
        associated_data,
        message.ciphertext,
    )
    if expected != message.mac:
        return None
    return keys.decrypt(message.ciphertext, suite)


def test_root_only_leak_cannot_decrypt_later_messages():
    """Stolen root bytes without chain keys or ratchet privates are useless."""
    alice, bob, suite = open_pair()
    assert bob.decrypt(alice.encrypt(b"before")) == b"before"

    stolen_root = bob.ratchet.root_key.key
    assert alice.decrypt(bob.encrypt(b"turn")) == b"turn"
    later = alice.encrypt(b"secret-later")

    # Attacker builds a hollow ratchet that only knows the old root.
    hollow = DoubleRatchet(
        suite=suite,
        root_key=RootKey(stolen_root, suite),
    )
    assert try_decrypt(
        Session(suite, hollow, bob.associated_data),
        later,
    ) is None
    assert bob.decrypt(later) == b"secret-later"


def test_old_root_after_dh_ratchet_still_useless():
    """Root from before a DH step does not open the post-ratchet root chain."""
    alice, bob, suite = open_pair()
    root_before = bytes(bob.ratchet.root_key.key)

    # Force DH ratchets both ways so the live root has moved.
    assert alice.decrypt(bob.encrypt(b"r0")) == b"r0"
    assert bob.decrypt(alice.encrypt(b"a0")) == b"a0"
    assert alice.decrypt(bob.encrypt(b"r1")) == b"r1"
    later = alice.encrypt(b"after-dh")

    assert bob.ratchet.root_key.key != root_before
    hollow = DoubleRatchet(
        suite=suite,
        root_key=RootKey(root_before, suite),
        our_ratchet_key=None,
    )
    assert try_decrypt(
        Session(suite, hollow, bob.associated_data),
        later,
    ) is None
    assert bob.decrypt(later) == b"after-dh"


def test_sender_chain_leak_opens_same_chain_only():
    """Stolen Alice send-chain key derives later MKs on that chain only."""
    alice, bob, suite = open_pair()
    assert alice.decrypt(bob.encrypt(b"sync")) == b"sync"

    # Alice now has a fresh sender chain after Bob's reply.
    assert alice.ratchet.sender_chain is not None
    stolen_ck = ChainKey(
        alice.ratchet.sender_chain.chain_key.key,
        alice.ratchet.sender_chain.chain_key.index,
        suite,
    )

    same_chain = [alice.encrypt(f"s{i}".encode()) for i in range(3)]
    derived = chain_message_keys(stolen_ck, 3)
    for msg, mk in zip(same_chain, derived):
        plain = decrypt_with_message_keys(
            mk,
            msg,
            suite,
            alice.associated_data,
        )
        assert plain == bob.decrypt(msg)

    # DH ratchet: Bob replies, Alice advances to a new send chain.
    assert alice.decrypt(bob.encrypt(b"heal")) == b"heal"
    post = alice.encrypt(b"post-heal")

    # Keys continued from the stolen pre-heal chain must not open post-heal.
    continued = chain_message_keys(stolen_ck, 6)
    opened = [
        decrypt_with_message_keys(mk, post, suite, alice.associated_data)
        for mk in continued
    ]
    assert all(p is None for p in opened)
    assert bob.decrypt(post) == b"post-heal"


def test_receiver_chain_leak_opens_future_on_that_chain():
    """Stolen Bob receive-chain key decrypts Alice's later same-chain messages."""
    alice, bob, suite = open_pair()
    assert bob.ratchet.receiver_chains
    stolen = ChainKey(
        bob.ratchet.receiver_chains[0].chain_key.key,
        bob.ratchet.receiver_chains[0].chain_key.index,
        suite,
    )

    messages = [alice.encrypt(f"m{i}".encode()) for i in range(4)]
    expected = [b"m0", b"m1", b"m2", b"m3"]
    for msg, mk, plain_expected in zip(
        messages,
        chain_message_keys(stolen, 4),
        expected,
    ):
        assert decrypt_with_message_keys(
            mk,
            msg,
            suite,
            bob.associated_data,
        ) == plain_expected
        assert bob.decrypt(msg) == plain_expected


def test_full_state_snapshot_reads_until_dh_heals():
    """Full Bob snapshot follows Alice on the current chain; DH reply heals."""
    alice, bob, _ = open_pair()

    # Establish bidirectional state, then freeze Bob.
    assert bob.decrypt(alice.encrypt(b"warm")) == b"warm"
    assert alice.decrypt(bob.encrypt(b"ack")) == b"ack"
    eve = freeze(bob)

    # Same receive chain: Eve's frozen Bob state still decrypts Alice.
    exposed = alice.encrypt(b"still-exposed")
    assert try_decrypt(eve, exposed) == b"still-exposed"
    assert bob.decrypt(exposed) == b"still-exposed"

    # Bob sends after compromise. His new ratchet private never enters Eve.
    heal_msg = bob.encrypt(b"bob-heals")
    assert alice.decrypt(heal_msg) == b"bob-heals"
    # Eve cannot usefully "be Bob" for sending; she never learns the new private.
    assert eve.ratchet.our_ratchet_key is not None
    assert bob.ratchet.our_ratchet_key is not None
    assert (
        eve.ratchet.our_ratchet_key.private.data
        != bob.ratchet.our_ratchet_key.private.data
    )

    # Alice's next send uses a new DH public mixed with Bob's post-heal private.
    healed = alice.encrypt(b"after-heal")
    assert try_decrypt(eve, healed) is None
    assert bob.decrypt(healed) == b"after-heal"


def test_full_alice_snapshot_heals_after_she_ratchets():
    """Stolen Alice state follows until she installs a new unshared DH private."""
    alice, bob, _ = open_pair()
    assert bob.decrypt(alice.encrypt(b"a0")) == b"a0"
    assert alice.decrypt(bob.encrypt(b"b0")) == b"b0"
    eve = freeze(alice)

    # Alice keeps sending on the current chain: Eve still has that send chain.
    leak = alice.encrypt(b"leak")
    # Eve is a frozen Alice; she does not decrypt her own send. She can derive
    # the same message keys by advancing a copy of the stolen sender chain.
    assert eve.ratchet.sender_chain is not None
    stolen_ck = ChainKey(
        eve.ratchet.sender_chain.chain_key.key,
        eve.ratchet.sender_chain.chain_key.index,
        alice.suite,
    )
    mk = chain_message_keys(stolen_ck, 1)[0]
    assert decrypt_with_message_keys(
        mk,
        leak,
        alice.suite,
        alice.associated_data,
    ) == b"leak"
    assert bob.decrypt(leak) == b"leak"

    # Bob replies -> Alice DH-ratchets and replaces our_ratchet_key.
    assert alice.decrypt(bob.encrypt(b"force-alice-ratchet")) == b"force-alice-ratchet"
    assert alice.ratchet.our_ratchet_key is not None
    assert eve.ratchet.our_ratchet_key is not None
    assert (
        alice.ratchet.our_ratchet_key.private.data
        != eve.ratchet.our_ratchet_key.private.data
    )

    post = alice.encrypt(b"fresh-send-chain")
    continued = chain_message_keys(stolen_ck, 8)
    assert all(
        decrypt_with_message_keys(mk, post, alice.suite, alice.associated_data) is None
        for mk in continued
    )
    assert bob.decrypt(post) == b"fresh-send-chain"


def test_forward_secrecy_consumed_keys_absent_from_state():
    """After decrypt, past message keys are not sitting in live Bob state."""
    alice, bob, suite = open_pair()
    past = [alice.encrypt(f"p{i}".encode()) for i in range(3)]
    for i, msg in enumerate(past):
        assert bob.decrypt(msg) == f"p{i}".encode()

    eve = freeze(bob)
    # No skipped entries for the consumed counters.
    for msg in past:
        assert eve.ratchet.skipped.peek(msg.ratchet_public, msg.counter) is None

    # Eve cannot decrypt past ciphertexts from post-decrypt state alone.
    for msg in past:
        assert try_decrypt(eve, msg) is None


def test_skipped_keys_in_compromised_state_still_open_those_messages():
    """State theft after a jump still exposes cached skipped message keys."""
    alice, bob, _ = open_pair()
    messages = [alice.encrypt(f"m{i}".encode()) for i in range(5)]
    # Deliver out of order so Bob caches skipped keys for m0..m3.
    assert bob.decrypt(messages[4]) == b"m4"
    assert bob.ratchet.skipped.peek(
        messages[1].ratchet_public,
        messages[1].counter,
    ) is not None

    eve = freeze(bob)
    assert try_decrypt(eve, messages[1]) == b"m1"
    assert try_decrypt(eve, messages[2]) == b"m2"
    # Honest Bob still has his own skipped cache.
    assert bob.decrypt(messages[1]) == b"m1"


def test_compromise_during_symmetric_stretch_then_heal():
    """Long same-chain stretch is exposed; one DH round-trip restores secrecy."""
    alice, bob, _ = open_pair()
    assert alice.decrypt(bob.encrypt(b"ready")) == b"ready"
    eve = freeze(bob)

    stretch = [alice.encrypt(f"x{i}".encode()) for i in range(6)]
    for msg, text in zip(stretch, [f"x{i}".encode() for i in range(6)]):
        assert try_decrypt(eve, msg) == text
        assert bob.decrypt(msg) == text

    # Eve's clone advanced with the stretch; Bob also advanced. Heal via Bob send.
    # Re-freeze Bob is not allowed: attacker lost access. Use the old eve copy
    # that already followed the stretch — still missing Bob's next DH private.
    assert alice.decrypt(bob.encrypt(b"pcs")) == b"pcs"
    secret = alice.encrypt(b"secret-again")
    assert try_decrypt(eve, secret) is None
    assert bob.decrypt(secret) == b"secret-again"


def test_root_plus_old_ratchet_private_without_chain_still_limited():
    """Old root + stale ratchet private cannot decrypt a post-heal message."""
    alice, bob, suite = open_pair()
    assert bob.decrypt(alice.encrypt(b"n0")) == b"n0"
    assert alice.decrypt(bob.encrypt(b"n1")) == b"n1"

    stolen_root = bob.ratchet.root_key.key
    stolen_our = bob.ratchet.our_ratchet_key
    assert stolen_our is not None

    # Live session heals onward.
    assert bob.decrypt(alice.encrypt(b"n2")) == b"n2"
    assert alice.decrypt(bob.encrypt(b"n3")) == b"n3"
    later = alice.encrypt(b"n4")

    stale = DoubleRatchet(
        suite=suite,
        root_key=RootKey(stolen_root, suite),
        our_ratchet_key=stolen_our,
    )
    assert try_decrypt(Session(suite, stale, bob.associated_data), later) is None
    assert bob.decrypt(later) == b"n4"


def test_message_key_leak_is_single_message():
    """One stolen MK decrypts only its message, not neighbors on the chain."""
    alice, bob, suite = open_pair()
    assert alice.decrypt(bob.encrypt(b"go")) == b"go"
    assert alice.ratchet.sender_chain is not None
    ck = ChainKey(
        alice.ratchet.sender_chain.chain_key.key,
        alice.ratchet.sender_chain.chain_key.index,
        suite,
    )
    m0, m1, m2 = [alice.encrypt(f"k{i}".encode()) for i in range(3)]
    mk0, mk1, mk2 = chain_message_keys(ck, 3)

    assert decrypt_with_message_keys(
        mk1,
        m1,
        suite,
        alice.associated_data,
    ) == b"k1"
    assert decrypt_with_message_keys(mk1, m0, suite, alice.associated_data) is None
    assert decrypt_with_message_keys(mk1, m2, suite, alice.associated_data) is None
    assert decrypt_with_message_keys(mk0, m0, suite, alice.associated_data) == b"k0"
    assert decrypt_with_message_keys(mk2, m2, suite, alice.associated_data) == b"k2"
    assert bob.decrypt(m0) == b"k0"
    assert bob.decrypt(m1) == b"k1"
    assert bob.decrypt(m2) == b"k2"


def test_eve_cannot_inject_with_stale_bob_send_chain():
    """Forged ciphertext under a pre-heal Bob snapshot fails against live Alice."""
    alice, bob, _ = open_pair()
    assert bob.decrypt(alice.encrypt(b"ping")) == b"ping"
    assert alice.decrypt(bob.encrypt(b"pong")) == b"pong"
    eve = freeze(bob)

    # Live Bob heals by sending again (new DH private).
    assert alice.decrypt(bob.encrypt(b"live-bob")) == b"live-bob"

    # Eve still has the pre-heal send state and tries to speak as Bob.
    forged = eve.encrypt(b"imposter")
    assert try_decrypt(alice, forged) is None
    # Honest traffic still works.
    assert bob.decrypt(alice.encrypt(b"ok")) == b"ok"
