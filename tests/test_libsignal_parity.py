"""libsignal-parity protocol scenarios on real Session / X3DH / ratchet APIs.

Maps applicable cases from libsignal rust/protocol/tests/session.rs (and
ratchet invalid-key intent) onto ratchetkit — not Signal wire/store APIs.

Session-level cases run on both Double and Triple suites. Handshake-only
cases stay classical Double (X3DH).
"""

import pytest

from ratchetkit.errors import (
    DuplicateMessage,
    InvalidKey,
    InvalidMessage,
    InvalidSignature,
    TooFarInFuture,
    TooManySkippedKeys,
)
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.prekey import OneTimePreKey, PreKeyBundle, SignedPreKey
from ratchetkit.ratchet.limits import RatchetLimits
from ratchetkit.session import Session
from ratchetkit.handshake import ExtendedTripleDiffieHellman
from ratchetkit.handshake.message import InitialMessagePQXDH, InitialMessageX3DH
from tests.helpers import (
    apply_limits,
    ec_ratchet,
    forge_tampered,
    make_suite,
    msg_counter,
    open_pair,
    snap_state,
)


def test_basic_session_multi_turn(pair):
    """libsignal test_basic_session / run_session_interaction subset."""
    kind, alice, bob, suite = pair
    for i in range(15):
        msg = alice.encrypt(f"alice-{i}".encode())
        assert bob.decrypt(msg) == f"alice-{i}".encode()
        reply = bob.encrypt(f"bob-{i}".encode())
        assert alice.decrypt(reply) == f"bob-{i}".encode()


def test_out_of_order_and_late_delivery(pair):
    """Out-of-order + late skipped-key delivery (session interaction style)."""
    kind, alice, bob, suite = pair
    batch = [alice.encrypt(f"m{i}".encode()) for i in range(6)]
    for idx in (4, 1, 5, 0, 3, 2):
        assert bob.decrypt(batch[idx]) == f"m{idx}".encode()

    held = alice.encrypt(b"held")
    more = [alice.encrypt(f"n{i}".encode()) for i in range(3)]
    assert bob.decrypt(more[2]) == b"n2"
    assert bob.decrypt(held) == b"held"
    assert bob.decrypt(more[0]) == b"n0"
    assert bob.decrypt(more[1]) == b"n1"


def test_duplicate_message_error_returned(pair):
    """libsignal test_duplicate_message_error_returned."""
    kind, alice, bob, suite = pair
    msg = alice.encrypt(b"once")
    assert bob.decrypt(msg) == b"once"
    snap = snap_state(bob)
    with pytest.raises((DuplicateMessage, InvalidMessage)):
        bob.decrypt(msg)
    assert snap_state(bob) == snap
    assert bob.decrypt(alice.encrypt(b"next")) == b"next"


def test_forward_jump_over_reduced_limit(pair):
    """libsignal test_chain_jump_over_limit with small MAX_FORWARD_JUMPS."""
    kind, alice, bob, suite = pair
    apply_limits(
        bob,
        RatchetLimits(
            MAX_RECEIVER_CHAINS=5,
            MAX_MESSAGE_KEYS=2000,
            MAX_FORWARD_JUMPS=4,
        ),
    )
    messages = [alice.encrypt(f"j{i}".encode()) for i in range(10)]
    index = ec_ratchet(bob).receiver_chains[0].chain_key.index
    # Find a counter that exceeds the forward-jump cap.
    too_far = None
    for msg in messages:
        if msg_counter(msg) - index > ec_ratchet(bob).limits.MAX_FORWARD_JUMPS:
            too_far = msg
            break
    assert too_far is not None
    snap = snap_state(bob)
    with pytest.raises(TooFarInFuture):
        bob.decrypt(too_far)
    assert snap_state(bob) == snap
    # Honest in-window message still works.
    near = messages[0]
    assert msg_counter(near) - index <= ec_ratchet(bob).limits.MAX_FORWARD_JUMPS
    assert bob.decrypt(near) == b"j0"


def test_message_key_limits_window(pair):
    """libsignal test_message_key_limits with reduced MAX_MESSAGE_KEYS."""
    kind, alice, bob, suite = pair
    apply_limits(
        bob,
        RatchetLimits(
            MAX_RECEIVER_CHAINS=5,
            MAX_MESSAGE_KEYS=8,
            MAX_FORWARD_JUMPS=1000,
        ),
    )
    inflight = [alice.encrypt(f"m{i}".encode()) for i in range(12)]
    # Decrypt a mid message: stores keys for earlier counters.
    assert bob.decrypt(inflight[5]) == b"m5"
    assert bob.decrypt(inflight[7]) == b"m7"
    # Keys still in the skipped cache decrypt.
    assert bob.decrypt(inflight[0]) == b"m0"
    assert bob.decrypt(inflight[2]) == b"m2"
    # Replay of a consumed message fails.
    with pytest.raises((DuplicateMessage, InvalidMessage)):
        bob.decrypt(inflight[5])


def test_message_key_limit_reject_does_not_commit(pair):
    """Skipping past MAX_MESSAGE_KEYS fails closed (no live state commit)."""
    kind, alice, bob, suite = pair
    apply_limits(
        bob,
        RatchetLimits(
            MAX_RECEIVER_CHAINS=5,
            MAX_MESSAGE_KEYS=3,
            MAX_FORWARD_JUMPS=25_000,
        ),
    )
    messages = [alice.encrypt(f"m{i}".encode()) for i in range(10)]
    snap = snap_state(bob)
    with pytest.raises(TooManySkippedKeys):
        bob.decrypt(messages[9])
    assert snap_state(bob) == snap
    assert bob.decrypt(messages[0]) == b"m0"


def test_bad_signed_prekey_signature():
    """libsignal test_bad_signed_pre_key_signature."""
    suite = make_suite("double")
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(bob)
    opk = OneTimePreKey.generate(suite)
    x3dh = ExtendedTripleDiffieHellman(suite)
    bundle = x3dh.create_bundle(bob, spk, opk)
    bad = PreKeyBundle(
        identity_signing=bundle.identity_signing,
        identity_agreement=bundle.identity_agreement,
        signed_prekey=bundle.signed_prekey,
        signed_prekey_signature=bytes(
            b ^ 0xFF for b in bundle.signed_prekey_signature
        ),
        one_time_prekey=bundle.one_time_prekey,
    )
    with pytest.raises(InvalidSignature):
        x3dh.initiate(alice, bad)


def test_corrupted_first_message_accept_then_honest_retry(pair):
    """libsignal bad_message_bundle / failed prekey decrypt does not stick."""
    kind = pair[0]
    suite = make_suite(kind)
    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(bob_id)
    opk = OneTimePreKey.generate(suite)
    if kind == "triple":
        pq = suite.generate_pq_prekey(bob_id)
        bundle = suite.create_bundle(bob_id, spk, opk, pq)
        alice, initial = Session.initiate(alice_id, bundle)
        first = alice.encrypt(b"first-ok")
        corrupted = forge_tampered(
            first,
            ciphertext=bytes([first.ciphertext[0] ^ 0x01]) + first.ciphertext[1:],
        )
        with pytest.raises(InvalidMessage):
            Session.accept(
                bob_id,
                spk,
                initial,
                corrupted,
                opk,
                our_pq_prekey=pq,
            )
        # Honest first message still establishes a session (OPK not library-consumed).
        bob, plain = Session.accept(
            bob_id,
            spk,
            initial,
            first,
            opk,
            our_pq_prekey=pq,
        )
    else:
        bundle = suite.create_bundle(bob_id, spk, opk)
        alice, initial = Session.initiate(alice_id, bundle)
        first = alice.encrypt(b"first-ok")
        corrupted = forge_tampered(
            first,
            ciphertext=bytes([first.ciphertext[0] ^ 0x01]) + first.ciphertext[1:],
        )
        with pytest.raises(InvalidMessage):
            Session.accept(bob_id, spk, initial, corrupted, opk)
        # Honest first message still establishes a session (OPK not library-consumed).
        bob, plain = Session.accept(bob_id, spk, initial, first, opk)
    assert plain == b"first-ok"
    assert bob.decrypt(alice.encrypt(b"follow")) == b"follow"


def _copy_initial(initial, **overrides):
    """Clone an initial message, preserving type (X3DH or PQXDH)."""
    fields = dict(
        identity_signing=initial.identity_signing,
        identity_agreement=initial.identity_agreement,
        ephemeral_public=initial.ephemeral_public,
        kem_ciphertexts=initial.kem_ciphertexts,
        signature=initial.signature,
        ratchet_public=initial.ratchet_public,
    )
    if isinstance(initial, InitialMessagePQXDH):
        fields["pq_ciphertext"] = initial.pq_ciphertext
        fields.update(overrides)
        return InitialMessagePQXDH(**fields)
    fields.update(overrides)
    return InitialMessageX3DH(**fields)


def test_corrupted_initial_message_rejected(pair):
    """Tampered initial signature cannot open a session."""
    kind = pair[0]
    suite = make_suite(kind)
    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(bob_id)
    opk = OneTimePreKey.generate(suite)
    if kind == "triple":
        pq = suite.generate_pq_prekey(bob_id)
        bundle = suite.create_bundle(bob_id, spk, opk, pq)
        alice, initial = Session.initiate(alice_id, bundle)
        first = alice.encrypt(b"x")
        bad_initial = _copy_initial(
            initial,
            signature=bytes([initial.signature[0] ^ 0x5A]) + initial.signature[1:],
        )
        with pytest.raises(InvalidSignature):
            Session.accept(
                bob_id,
                spk,
                bad_initial,
                first,
                opk,
                our_pq_prekey=pq,
            )
    else:
        bundle = suite.create_bundle(bob_id, spk, opk)
        alice, initial = Session.initiate(alice_id, bundle)
        first = alice.encrypt(b"x")
        bad_initial = _copy_initial(
            initial,
            signature=bytes([initial.signature[0] ^ 0x5A]) + initial.signature[1:],
        )
        with pytest.raises(InvalidSignature):
            Session.accept(bob_id, spk, bad_initial, first, opk)


def test_initial_ratchet_public_swap_rejected(pair):
    """Swapping signed ratchet_public breaks initiator binding."""
    kind = pair[0]
    suite = make_suite(kind)
    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(bob_id)
    opk = OneTimePreKey.generate(suite)
    if kind == "triple":
        pq = suite.generate_pq_prekey(bob_id)
        bundle = suite.create_bundle(bob_id, spk, opk, pq)
        alice, initial = Session.initiate(alice_id, bundle)
        first = alice.encrypt(b"x")
        fake = suite.kem.generate_keypair()
        swapped = _copy_initial(initial, ratchet_public=fake.public.data)
        with pytest.raises(InvalidSignature):
            Session.accept(
                bob_id,
                spk,
                swapped,
                first,
                opk,
                our_pq_prekey=pq,
            )
    else:
        bundle = suite.create_bundle(bob_id, spk, opk)
        alice, initial = Session.initiate(alice_id, bundle)
        first = alice.encrypt(b"x")
        fake = suite.kem.generate_keypair()
        swapped = _copy_initial(initial, ratchet_public=fake.public.data)
        with pytest.raises(InvalidSignature):
            Session.accept(bob_id, spk, swapped, first, opk)



def test_longer_bidirectional_session_with_held_messages(pair):
    """libsignal test_longer_sessions intent: multi-turn + late delivery."""
    kind, alice, bob, suite = pair
    if kind == "double":
        # Hold across DH turns: Double Ratchet PN/skipped keys cover this.
        held = []
        for i in range(25):
            outbound = alice.encrypt(f"A{i}".encode())
            if i in (2, 9, 17, 22):
                held.append((i, outbound))
            else:
                assert bob.decrypt(outbound) == f"A{i}".encode()
            inbound = bob.encrypt(f"B{i}".encode())
            assert alice.decrypt(inbound) == f"B{i}".encode()
        for i, msg in held:
            assert bob.decrypt(msg) == f"A{i}".encode()
        return

    # Triple: multi-turn ping-pong. Same-chain holds across SPQR epoch seals
    # are covered by test_out_of_order_and_late_delivery / test_triple_*.
    for i in range(25):
        assert bob.decrypt(alice.encrypt(f"A{i}".encode())) == f"A{i}".encode()
        assert alice.decrypt(bob.encrypt(f"B{i}".encode())) == f"B{i}".encode()


def test_associated_data_mismatch_on_accept(pair):
    kind = pair[0]
    suite = make_suite(kind)
    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(bob_id)
    opk = OneTimePreKey.generate(suite)
    extra = b"channel-7"
    if kind == "triple":
        pq = suite.generate_pq_prekey(bob_id)
        bundle = suite.create_bundle(bob_id, spk, opk, pq)
        alice, initial = Session.initiate(alice_id, bundle)
        first = alice.encrypt(b"ad-first", associated_data=extra)
        with pytest.raises(InvalidMessage):
            Session.accept(
                bob_id,
                spk,
                initial,
                first,
                opk,
                our_pq_prekey=pq,
            )
        with pytest.raises(InvalidMessage):
            Session.accept(
                bob_id,
                spk,
                initial,
                first,
                opk,
                associated_data=b"wrong",
                our_pq_prekey=pq,
            )
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
        first = alice.encrypt(b"ad-first", associated_data=extra)
        with pytest.raises(InvalidMessage):
            Session.accept(bob_id, spk, initial, first, opk)
        with pytest.raises(InvalidMessage):
            Session.accept(
                bob_id,
                spk,
                initial,
                first,
                opk,
                associated_data=b"wrong",
            )
        bob, plain = Session.accept(
            bob_id,
            spk,
            initial,
            first,
            opk,
            associated_data=extra,
        )
    assert plain == b"ad-first"


def test_wrong_spk_on_respond(pair):
    """Wrong SPK material fails closed on accept (shared secret / MAC)."""
    kind = pair[0]
    suite = make_suite(kind)
    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(bob_id)
    opk = OneTimePreKey.generate(suite)
    if kind == "triple":
        pq = suite.generate_pq_prekey(bob_id)
        bundle = suite.create_bundle(bob_id, spk, opk, pq)
        alice, initial = Session.initiate(alice_id, bundle)
        first = alice.encrypt(b"x")
        wrong_spk = SignedPreKey.generate(bob_id)
        with pytest.raises((InvalidKey, InvalidSignature, InvalidMessage)):
            Session.accept(
                bob_id,
                wrong_spk,
                initial,
                first,
                opk,
                our_pq_prekey=pq,
            )
    else:
        bundle = suite.create_bundle(bob_id, spk, opk)
        alice, initial = Session.initiate(alice_id, bundle)
        first = alice.encrypt(b"x")
        wrong_spk = SignedPreKey.generate(bob_id)
        with pytest.raises((InvalidKey, InvalidSignature, InvalidMessage)):
            Session.accept(bob_id, wrong_spk, initial, first, opk)


def test_repeat_first_message_after_accept_rejected(pair):
    """Replay of the establishing first message after session is live."""
    kind = pair[0]
    alice, bob, *_rest, first = open_pair(kind)
    snap = snap_state(bob)
    with pytest.raises((DuplicateMessage, InvalidMessage)):
        bob.decrypt(first)
    assert snap_state(bob) == snap
