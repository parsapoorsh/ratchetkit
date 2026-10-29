"""Compromise and post-compromise security tests for Double and Triple Ratchet.

Models a one-shot state theft: attacker freezes a session snapshot, then
honest parties keep talking. The attacker may also see public wire messages.
These tests lock the properties discussed in the Double Ratchet design:

- Root-only leak is not enough to read later traffic.
- A stolen sending/receiving chain key opens that chain until the next DH step.
- A full live-state snapshot can follow traffic until a later DH ratchet
  installs a private key the snapshot never learned (PCS healing).
- Already-consumed message keys are gone from state (forward secrecy of past).

Every case runs against both Double Ratchet and Triple Ratchet suites via the
``pair`` fixture. Triple branches use the EC half for root/DH state and hybrid
EC+SPQR keys where message-key theft is under test.
"""
from __future__ import annotations

from ratchetkit.suite.registry import hash_backend

import pytest

from ratchetkit.errors import DuplicateMessage, InvalidMessage
from ratchetkit.kdf import Kdf
from ratchetkit.keys.chain import ChainKey
from ratchetkit.keys.message import MessageKeys
from ratchetkit.keys.root import RootKey
from ratchetkit.ratchet.message import (
    DoubleRatchetMessage,
    RatchetMessage,
    TripleRatchetMessage,
)
from ratchetkit.ratchet.protocol.double import DoubleRatchet
from ratchetkit.ratchet.protocol.triple import TripleRatchet
from ratchetkit.ratchet.spqr import SparsePostQuantumRatchet
from ratchetkit.session import Session
from ratchetkit.suite.double import CryptoSuiteDoubleRatchet
from ratchetkit.suite.triple import CryptoSuiteTripleRatchet
from tests.helpers import ec_ratchet


def freeze(session: Session) -> Session:
    """One-shot device compromise: attacker keeps a frozen copy of state."""
    return Session.from_bytes(session.to_bytes())


def try_decrypt(session: Session, message: RatchetMessage) -> bytes | None:
    try:
        return session.decrypt(message)
    except (InvalidMessage, DuplicateMessage, TypeError):
        return None


def chain_message_keys(chain: ChainKey, count: int) -> list[MessageKeys]:
    """Derive ``count`` successive message keys without mutating ``chain``."""
    keys = []
    current = ChainKey(chain.key, chain.index, chain.suite)
    for _ in range(count):
        keys.append(current.message_keys())
        current = current.next_chain_key()
    return keys


def copy_chain(chain: ChainKey) -> ChainKey:
    return ChainKey(chain.key, chain.index, chain.suite)


def spqr_send_chain(session: Session) -> ChainKey:
    ratchet = session.ratchet
    assert isinstance(ratchet, TripleRatchet)
    spqr = ratchet.spqr
    chains = spqr.chains.get(spqr.sending_epoch)
    assert chains is not None and chains.send is not None
    return copy_chain(chains.send)


def spqr_recv_chain(session: Session) -> ChainKey:
    ratchet = session.ratchet
    assert isinstance(ratchet, TripleRatchet)
    spqr = ratchet.spqr
    chains = spqr.chains.get(spqr.receiving_epoch)
    assert chains is not None and chains.receive is not None
    return copy_chain(chains.receive)


def hybrid_message_keys(
    suite: CryptoSuite,
    triple: TripleRatchet,
    ec_chain: ChainKey,
    pq_chain: ChainKey,
    count: int,
) -> list[MessageKeys]:
    """Derive hybrid MKs from paired EC + SPQR chain positions."""
    ec_keys = chain_message_keys(ec_chain, count)
    pq_keys = chain_message_keys(pq_chain, count)
    out = []
    for ec_mk, pq_mk in zip(ec_keys, pq_keys):
        seed = triple.hybrid_message_key(ec_mk.cipher_key, pq_mk.cipher_key)
        out.append(MessageKeys.derive(seed, ec_mk.counter, suite))
    return out


def decrypt_with_message_keys(
    keys: MessageKeys,
    message: RatchetMessage,
    suite: CryptoSuite,
    associated_data: bytes,
) -> bytes | None:
    """Passive decrypt using a stolen message key (cipher + MAC check)."""
    material = associated_data + message.header_bytes() + message.ciphertext
    tag = Kdf(suite.digest).hmac_digest(keys.mac_key, material)[: suite.tag_size]
    if tag != message.mac:
        return None
    return keys.decrypt(message.ciphertext, suite)


def steal_sender_message_keys(
    kind: str,
    alice: Session,
    count: int,
) -> list[MessageKeys]:
    """Message keys Alice will use for her next ``count`` sends (from live state)."""
    ec = ec_ratchet(alice)
    assert ec.sender_chain is not None
    ec_ck = copy_chain(ec.sender_chain.chain_key)
    if kind == "double":
        return chain_message_keys(ec_ck, count)
    assert isinstance(alice.ratchet, TripleRatchet)
    pq_ck = spqr_send_chain(alice)
    return hybrid_message_keys(alice.suite, alice.ratchet, ec_ck, pq_ck, count)


def steal_receiver_message_keys(
    kind: str,
    bob: Session,
    count: int,
) -> list[MessageKeys]:
    """Message keys Bob expects for Alice's next ``count`` receives."""
    ec = ec_ratchet(bob)
    assert ec.receiver_chains
    ec_ck = copy_chain(ec.receiver_chains[0].chain_key)
    if kind == "double":
        return chain_message_keys(ec_ck, count)
    assert isinstance(bob.ratchet, TripleRatchet)
    pq_ck = spqr_recv_chain(bob)
    return hybrid_message_keys(bob.suite, bob.ratchet, ec_ck, pq_ck, count)


def hollow_from_root(
    kind: str,
    suite: CryptoSuite,
    root_bytes: bytes,
    our_ratchet_key=None,
    associated_data: bytes = b"",
) -> Session:
    """Attacker builds a hollow ratchet that only knows the old root."""
    root = RootKey(root_bytes, suite)
    if kind == "double":
        ratchet: DoubleRatchet | TripleRatchet = DoubleRatchet(
            suite=suite,
            root_key=root,
            our_ratchet_key=our_ratchet_key,
        )
    else:
        # Triple still needs an SPQR leaf; a dummy SPQR will not match live traffic.
        assert isinstance(suite, CryptoSuiteTripleRatchet)
        ec = DoubleRatchet(
            suite=suite,
            root_key=root,
            our_ratchet_key=our_ratchet_key,
        )
        size = hash_backend(suite.digest).digest_size
        spqr = SparsePostQuantumRatchet.initiate(
            suite,
            b"\x02" * size,
            suite.pq_kem,
            n_chunks=suite.scka_chunks,
        )
        ratchet = TripleRatchet(suite=suite, ec=ec, spqr=spqr)
    return Session(suite, ratchet, associated_data=associated_data)


def message_chain_id(kind: str, message: RatchetMessage) -> bytes:
    if kind == "double":
        assert isinstance(message, DoubleRatchetMessage)
        return message.ratchet_public
    assert isinstance(message, TripleRatchetMessage)
    return message.ec_message.ratchet_public


def message_counter(kind: str, message: RatchetMessage) -> int:
    if kind == "double":
        assert isinstance(message, DoubleRatchetMessage)
        return message.counter
    assert isinstance(message, TripleRatchetMessage)
    return message.ec_message.counter


def skipped_peek(kind: str, session: Session, message: RatchetMessage):
    ec = ec_ratchet(session)
    return ec.skipped.peek(
        message_chain_id(kind, message),
        message_counter(kind, message),
    )


def our_private(session: Session) -> bytes:
    key = ec_ratchet(session).our_ratchet_key
    assert key is not None
    return key.private


def test_root_only_leak_cannot_decrypt_later_messages(pair):
    """Stolen root bytes without chain keys or ratchet privates are useless."""
    kind, alice, bob, suite = pair
    assert bob.decrypt(alice.encrypt(b"before")) == b"before"

    stolen_root = bytes(ec_ratchet(bob).root_key.key)
    assert alice.decrypt(bob.encrypt(b"turn")) == b"turn"
    later = alice.encrypt(b"secret-later")

    # Attacker builds a hollow ratchet that only knows the old root.
    hollow = hollow_from_root(
        kind,
        suite,
        stolen_root,
        associated_data=bob.associated_data,
    )
    assert try_decrypt(hollow, later) is None
    assert bob.decrypt(later) == b"secret-later"


def test_old_root_after_dh_ratchet_still_useless(pair):
    """Root from before a DH step does not open the post-ratchet root chain."""
    kind, alice, bob, suite = pair
    root_before = bytes(ec_ratchet(bob).root_key.key)

    # Force DH ratchets both ways so the live root has moved.
    assert alice.decrypt(bob.encrypt(b"r0")) == b"r0"
    assert bob.decrypt(alice.encrypt(b"a0")) == b"a0"
    assert alice.decrypt(bob.encrypt(b"r1")) == b"r1"
    later = alice.encrypt(b"after-dh")

    assert ec_ratchet(bob).root_key.key != root_before
    hollow = hollow_from_root(
        kind,
        suite,
        root_before,
        associated_data=bob.associated_data,
    )
    assert try_decrypt(hollow, later) is None
    assert bob.decrypt(later) == b"after-dh"


def test_sender_chain_leak_opens_same_chain_only(pair):
    """Stolen Alice send-chain key derives later MKs on that chain only."""
    kind, alice, bob, suite = pair
    assert alice.decrypt(bob.encrypt(b"sync")) == b"sync"

    # Alice now has a fresh sender chain after Bob's reply.
    assert ec_ratchet(alice).sender_chain is not None
    stolen_mks = steal_sender_message_keys(kind, alice, 3)

    same_chain = [alice.encrypt(f"s{i}".encode()) for i in range(3)]
    for msg, mk in zip(same_chain, stolen_mks):
        plain = decrypt_with_message_keys(
            mk,
            msg,
            suite,
            alice.associated_data,
        )
        assert plain == bob.decrypt(msg)

    # Freeze Alice on the advanced pre-heal send chain, then force a DH ratchet.
    pre_heal = freeze(alice)
    # DH ratchet: Bob replies, Alice advances to a new send chain.
    assert alice.decrypt(bob.encrypt(b"heal")) == b"heal"
    post = alice.encrypt(b"post-heal")

    # Keys continued from the stolen pre-heal chain must not open post-heal.
    continued = steal_sender_message_keys(kind, pre_heal, 6)
    opened = [
        decrypt_with_message_keys(mk, post, suite, alice.associated_data)
        for mk in continued
    ]
    assert all(p is None for p in opened)
    assert bob.decrypt(post) == b"post-heal"


def test_receiver_chain_leak_opens_future_on_that_chain(pair):
    """Stolen Bob receive-chain key decrypts Alice's later same-chain messages."""
    kind, alice, bob, suite = pair
    assert ec_ratchet(bob).receiver_chains
    stolen = steal_receiver_message_keys(kind, bob, 4)

    messages = [alice.encrypt(f"m{i}".encode()) for i in range(4)]
    expected = [b"m0", b"m1", b"m2", b"m3"]
    for msg, mk, plain_expected in zip(messages, stolen, expected):
        assert decrypt_with_message_keys(
            mk,
            msg,
            suite,
            bob.associated_data,
        ) == plain_expected
        assert bob.decrypt(msg) == plain_expected


def test_full_state_snapshot_reads_until_dh_heals(pair):
    """Full Bob snapshot follows Alice on the current chain; DH reply heals."""
    kind, alice, bob, _ = pair

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
    assert our_private(eve) != our_private(bob)

    # Alice's next send uses a new DH public mixed with Bob's post-heal private.
    healed = alice.encrypt(b"after-heal")
    assert try_decrypt(eve, healed) is None
    assert bob.decrypt(healed) == b"after-heal"


def test_full_alice_snapshot_heals_after_she_ratchets(pair):
    """Stolen Alice state follows until she installs a new unshared DH private."""
    kind, alice, bob, suite = pair
    assert bob.decrypt(alice.encrypt(b"a0")) == b"a0"
    assert alice.decrypt(bob.encrypt(b"b0")) == b"b0"
    eve = freeze(alice)

    # Alice keeps sending on the current chain: Eve still has that send chain.
    leak = alice.encrypt(b"leak")
    # Eve is a frozen Alice; she does not decrypt her own send. She can derive
    # the same message keys by advancing a copy of the stolen sender chain.
    stolen_mks = steal_sender_message_keys(kind, eve, 1)
    assert decrypt_with_message_keys(
        stolen_mks[0],
        leak,
        suite,
        alice.associated_data,
    ) == b"leak"
    assert bob.decrypt(leak) == b"leak"

    # Bob replies -> Alice DH-ratchets and replaces our_ratchet_key.
    assert alice.decrypt(bob.encrypt(b"force-alice-ratchet")) == b"force-alice-ratchet"
    assert our_private(alice) != our_private(eve)

    post = alice.encrypt(b"fresh-send-chain")
    continued = steal_sender_message_keys(kind, eve, 8)
    assert all(
        decrypt_with_message_keys(mk, post, suite, alice.associated_data) is None
        for mk in continued
    )
    assert bob.decrypt(post) == b"fresh-send-chain"


def test_forward_secrecy_consumed_keys_absent_from_state(pair):
    """After decrypt, past message keys are not sitting in live Bob state."""
    kind, alice, bob, _ = pair
    past = [alice.encrypt(f"p{i}".encode()) for i in range(3)]
    for i, msg in enumerate(past):
        assert bob.decrypt(msg) == f"p{i}".encode()

    eve = freeze(bob)
    # No skipped entries for the consumed counters.
    for msg in past:
        assert skipped_peek(kind, eve, msg) is None

    # Eve cannot decrypt past ciphertexts from post-decrypt state alone.
    for msg in past:
        assert try_decrypt(eve, msg) is None


def test_skipped_keys_in_compromised_state_still_open_those_messages(pair):
    """State theft after a jump still exposes cached skipped message keys."""
    kind, alice, bob, _ = pair
    messages = [alice.encrypt(f"m{i}".encode()) for i in range(5)]
    # Deliver out of order so Bob caches skipped keys for m0..m3.
    assert bob.decrypt(messages[4]) == b"m4"
    assert skipped_peek(kind, bob, messages[1]) is not None

    eve = freeze(bob)
    assert try_decrypt(eve, messages[1]) == b"m1"
    assert try_decrypt(eve, messages[2]) == b"m2"
    # Honest Bob still has his own skipped cache.
    assert bob.decrypt(messages[1]) == b"m1"


def test_compromise_during_symmetric_stretch_then_heal(pair):
    """Long same-chain stretch is exposed; one DH round-trip restores secrecy."""
    kind, alice, bob, _ = pair
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


def test_root_plus_old_ratchet_private_without_chain_still_limited(pair):
    """Old root + stale ratchet private cannot decrypt a post-heal message."""
    kind, alice, bob, suite = pair
    assert bob.decrypt(alice.encrypt(b"n0")) == b"n0"
    assert alice.decrypt(bob.encrypt(b"n1")) == b"n1"

    stolen_root = bytes(ec_ratchet(bob).root_key.key)
    stolen_our = ec_ratchet(bob).our_ratchet_key
    assert stolen_our is not None

    # Live session heals onward.
    assert bob.decrypt(alice.encrypt(b"n2")) == b"n2"
    assert alice.decrypt(bob.encrypt(b"n3")) == b"n3"
    later = alice.encrypt(b"n4")

    stale = hollow_from_root(
        kind,
        suite,
        stolen_root,
        our_ratchet_key=stolen_our,
        associated_data=bob.associated_data,
    )
    assert try_decrypt(stale, later) is None
    assert bob.decrypt(later) == b"n4"


def test_message_key_leak_is_single_message(pair):
    """One stolen MK decrypts only its message, not neighbors on the chain."""
    kind, alice, bob, suite = pair
    assert alice.decrypt(bob.encrypt(b"go")) == b"go"
    assert ec_ratchet(alice).sender_chain is not None
    mk0, mk1, mk2 = steal_sender_message_keys(kind, alice, 3)
    m0, m1, m2 = [alice.encrypt(f"k{i}".encode()) for i in range(3)]

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


def test_eve_cannot_inject_with_stale_bob_send_chain(pair):
    """Forged ciphertext under a pre-heal Bob snapshot fails against live Alice."""
    kind, alice, bob, _ = pair
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
