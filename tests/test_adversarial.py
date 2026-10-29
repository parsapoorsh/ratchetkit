"""Attacker-oriented tests: forgery, tamper, replay, limit abuse, relabel.

Each failure path asserts a typed error and that live session cryptographic
state is unchanged so a subsequent honest message still decrypts.

Session-level cases run on both Double and Triple suites. Handshake-only
and suite-construction cases stay classical Double.
"""

import pytest

from ratchetkit.errors import (
    DuplicateMessage,
    InvalidKey,
    InvalidMessage,
    InvalidSignature,
    SerializationError,
    TooFarInFuture,
    TooManySkippedKeys,
)
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.keypair import PublicKey, SigningPublicKey
from ratchetkit.keys.prekey import OneTimePreKey, PreKeyBundle, SignedPreKey
from ratchetkit.ratchet.limits import RatchetLimits
from ratchetkit.handshake import ExtendedTripleDiffieHellman
from ratchetkit.handshake.message import InitialMessageX3DH
from tests.helpers import (
    apply_limits,
    ec_ratchet,
    forge_tampered,
    forge_unknown_header,
    make_suite,
    msg_counter,
    msg_ratchet_public,
    parse_message,
    snap_state,
)


def test_forged_mac_does_not_advance_or_desync(pair):
    kind, alice, bob, suite = pair
    real = alice.encrypt(b"payload")
    forged = forge_tampered(
        real,
        mac=bytes(len(real.mac)),
    )
    before = snap_state(bob)
    with pytest.raises(InvalidMessage):
        bob.decrypt(forged)
    assert snap_state(bob) == before
    assert bob.decrypt(real) == b"payload"
    assert bob.decrypt(alice.encrypt(b"after")) == b"after"


def test_ciphertext_bitflip_rejected_state_intact(pair):
    kind, alice, bob, suite = pair
    real = alice.encrypt(b"bits")
    flipped = forge_tampered(
        real,
        ciphertext=bytes([real.ciphertext[0] ^ 0x01]) + real.ciphertext[1:],
    )
    before = snap_state(bob)
    with pytest.raises(InvalidMessage):
        bob.decrypt(flipped)
    assert snap_state(bob) == before
    assert bob.decrypt(real) == b"bits"


def test_truncated_mac_rejected_state_intact(pair):
    kind, alice, bob, suite = pair
    real = alice.encrypt(b"short-mac")
    short = forge_tampered(real, mac=real.mac[:-1])
    before = snap_state(bob)
    with pytest.raises(InvalidMessage):
        bob.decrypt(short)
    assert snap_state(bob) == before
    assert bob.decrypt(real) == b"short-mac"


def test_forged_unknown_ratchet_public_no_desync(pair):
    kind, alice, bob, suite = pair
    before = snap_state(bob)
    held = alice.encrypt(b"held-shape")
    forged = forge_unknown_header(kind, held, b"\xab" * 32)
    with pytest.raises(InvalidMessage):
        bob.decrypt(forged)
    assert snap_state(bob) == before
    assert bob.decrypt(held) == b"held-shape"
    assert bob.decrypt(alice.encrypt(b"ok")) == b"ok"


def test_low_order_and_highbit_ratchet_publics(pair):
    """libsignal torsion/highbit basekey intent on ratchet headers."""
    kind, alice, bob, suite = pair
    before = snap_state(bob)
    held = alice.encrypt(b"held-shape")
    for label, pub in (
        ("all-zero", b"\x00" * 32),
        ("high-bit", bytes([0x41] * 31 + [0x41 | 0x80])),
    ):
        forged = forge_unknown_header(kind, held, pub)
        with pytest.raises(InvalidMessage):
            bob.decrypt(forged)
        assert snap_state(bob) == before, label
    assert bob.decrypt(held) == b"held-shape"
    assert bob.decrypt(alice.encrypt(b"still")) == b"still"


def test_replay_after_multi_turn_no_desync(pair):
    kind, alice, bob, suite = pair
    transcript = []
    for i in range(5):
        m = alice.encrypt(f"a{i}".encode())
        assert bob.decrypt(m) == f"a{i}".encode()
        transcript.append(m)
        r = bob.encrypt(f"b{i}".encode())
        assert alice.decrypt(r) == f"b{i}".encode()
    before = snap_state(bob)
    with pytest.raises((DuplicateMessage, InvalidMessage)):
        bob.decrypt(transcript[2])
    assert snap_state(bob) == before
    assert bob.decrypt(alice.encrypt(b"continue")) == b"continue"


def test_high_counter_skip_abuse_no_commit(pair):
    kind, alice, bob, suite = pair
    apply_limits(
        bob,
        RatchetLimits(
            MAX_RECEIVER_CHAINS=5,
            MAX_MESSAGE_KEYS=4,
            MAX_FORWARD_JUMPS=25_000,
        ),
    )
    real = alice.encrypt(b"real")
    forged = forge_tampered(
        real,
        counter=msg_counter(real) + 50,
        ciphertext=b"\x00" * 32,
        mac=b"\x00" * len(real.mac),
    )
    before = snap_state(bob)
    with pytest.raises((TooManySkippedKeys, TooFarInFuture, InvalidMessage)):
        bob.decrypt(forged)
    assert snap_state(bob) == before
    assert bob.decrypt(real) == b"real"


def test_forged_previous_counter_skip_abuse(pair):
    """Inflated PN on a new chain must not fill skipped keys on live state."""
    kind, alice, bob, suite = pair
    apply_limits(
        bob,
        RatchetLimits(
            MAX_RECEIVER_CHAINS=5,
            MAX_MESSAGE_KEYS=3,
            MAX_FORWARD_JUMPS=100,
        ),
    )
    # Force a DH ratchet so Alice's next message carries a real PN path.
    assert alice.decrypt(bob.encrypt(b"force")) == b"force"
    nxt = alice.encrypt(b"next")
    forged = forge_tampered(
        nxt,
        previous_counter=80,
    )
    before = snap_state(bob)
    with pytest.raises((TooManySkippedKeys, TooFarInFuture, InvalidMessage)):
        bob.decrypt(forged)
    assert snap_state(bob) == before
    assert bob.decrypt(nxt) == b"next"


def test_identity_agreement_swap_on_initial():
    suite = make_suite("double")
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob)
    opk = OneTimePreKey.generate(1, suite)
    x3dh = ExtendedTripleDiffieHellman(suite)
    bundle = x3dh.create_bundle(bob, spk, opk)
    result = x3dh.initiate(alice, bundle)
    initial = result.initial_message
    eve = IdentityKeyPair.generate(suite)
    tampered = InitialMessageX3DH(
        identity_signing=initial.identity_signing,
        identity_agreement=eve.agreement.public,
        ephemeral_public=initial.ephemeral_public,
        kem_ciphertexts=initial.kem_ciphertexts,
        signed_prekey_id=initial.signed_prekey_id,
        one_time_prekey_id=initial.one_time_prekey_id,
        signature=initial.signature,
        ratchet_public=initial.ratchet_public,
    )
    with pytest.raises(InvalidSignature):
        x3dh.respond(bob, spk, tampered, opk)


def test_identity_signing_algorithm_relabel():
    suite = make_suite("double")
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob)
    opk = OneTimePreKey.generate(1, suite)
    x3dh = ExtendedTripleDiffieHellman(suite)
    bundle = x3dh.create_bundle(bob, spk, opk)
    result = x3dh.initiate(alice, bundle)
    initial = result.initial_message
    tampered = InitialMessageX3DH(
        identity_signing=SigningPublicKey(
            initial.identity_signing.data,
            "rsa2048",
        ),
        identity_agreement=initial.identity_agreement,
        ephemeral_public=initial.ephemeral_public,
        kem_ciphertexts=initial.kem_ciphertexts,
        signed_prekey_id=initial.signed_prekey_id,
        one_time_prekey_id=initial.one_time_prekey_id,
        signature=initial.signature,
        ratchet_public=initial.ratchet_public,
    )
    with pytest.raises(InvalidKey, match="identity signing"):
        x3dh.respond(bob, spk, tampered, opk)


def test_spk_algorithm_relabel_on_bundle():
    suite = make_suite("double")
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob)
    opk = OneTimePreKey.generate(1, suite)
    bundle = suite.create_bundle(bob, spk, opk)
    relabeled = PreKeyBundle(
        identity_signing=bundle.identity_signing,
        identity_agreement=bundle.identity_agreement,
        signed_prekey_id=bundle.signed_prekey_id,
        signed_prekey=PublicKey(bundle.signed_prekey.data, "rsa2048"),
        signed_prekey_signature=bundle.signed_prekey_signature,
        one_time_prekey_id=bundle.one_time_prekey_id,
        one_time_prekey=bundle.one_time_prekey,
    )
    with pytest.raises(InvalidSignature):
        relabeled.verify(suite)


def test_associated_data_mismatch_ongoing_no_desync(pair):
    kind, alice, bob, suite = pair
    extra = b"ticket-9"
    msg = alice.encrypt(b"bound", associated_data=extra)
    before = snap_state(bob)
    with pytest.raises(InvalidMessage):
        bob.decrypt(msg)
    with pytest.raises(InvalidMessage):
        bob.decrypt(msg, associated_data=b"other")
    assert snap_state(bob) == before
    assert bob.decrypt(msg, associated_data=extra) == b"bound"


def test_wire_trailing_bytes_and_corrupt_serialize(pair):
    kind, alice, bob, suite = pair
    msg = alice.encrypt(b"wire")
    raw = msg.to_bytes()
    with pytest.raises(SerializationError):
        parse_message(kind, raw + b"X")
    flipped = bytearray(raw)
    flipped[len(flipped) // 2] ^= 0xFF
    # May fail parse or MAC; either way must not accept as plaintext.
    try:
        bad = parse_message(kind, bytes(flipped))
    except SerializationError:
        return
    before = snap_state(bob)
    with pytest.raises(InvalidMessage):
        bob.decrypt(bad)
    assert snap_state(bob) == before
    assert bob.decrypt(msg) == b"wire"


def test_skipped_key_bad_mac_preserves_cache_entry(pair):
    """Failed MAC on a skipped counter must leave the key for the real message."""
    kind, alice, bob, suite = pair
    messages = [alice.encrypt(f"m{i}".encode()) for i in range(5)]
    assert bob.decrypt(messages[4]) == b"m4"
    assert ec_ratchet(bob).skipped.peek(
        msg_ratchet_public(messages[1]),
        msg_counter(messages[1]),
    ) is not None
    forged = forge_tampered(
        messages[1],
        ciphertext=b"\x00" * 16,
        mac=b"\x00" * len(messages[1].mac),
    )
    before = snap_state(bob)
    with pytest.raises(InvalidMessage):
        bob.decrypt(forged)
    assert snap_state(bob) == before
    assert bob.decrypt(messages[1]) == b"m1"


def test_forward_jump_limit_abuse_then_honest(pair):
    kind, alice, bob, suite = pair
    apply_limits(
        bob,
        RatchetLimits(
            MAX_RECEIVER_CHAINS=5,
            MAX_MESSAGE_KEYS=500,
            MAX_FORWARD_JUMPS=3,
        ),
    )
    messages = [alice.encrypt(f"j{i}".encode()) for i in range(8)]
    index = ec_ratchet(bob).receiver_chains[0].chain_key.index
    too_far = next(
        m
        for m in messages
        if msg_counter(m) - index > ec_ratchet(bob).limits.MAX_FORWARD_JUMPS
    )
    before = snap_state(bob)
    with pytest.raises(TooFarInFuture):
        bob.decrypt(too_far)
    assert snap_state(bob) == before
    assert bob.decrypt(messages[0]) == b"j0"
