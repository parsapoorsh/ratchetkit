"""Shared dual-suite test helpers (Double Ratchet + Triple Ratchet).

Triple/PQ-only modules (test_triple, test_pqxdh, test_spqr, test_scka, kem)
keep their own setup. Everything else should open sessions through here.
"""

from __future__ import annotations

import pytest

from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.prekey import OneTimePreKey, SignedPreKey
from ratchetkit.ratchet.limits import RatchetLimits
from ratchetkit.ratchet.message import (
    DoubleRatchetMessage,
    RatchetMessage,
    TripleRatchetMessage,
)
from ratchetkit.ratchet.protocol.double import DoubleRatchet
from ratchetkit.ratchet.protocol.triple import TripleRatchet
from ratchetkit.session import Session
from ratchetkit.suite import (
    CipherAlg,
    CryptoSuite,
    CryptoSuiteDoubleRatchet,
    CryptoSuiteTripleRatchet,
    HashAlg,
    KeyExchangeAlg,
)


SUITE_KINDS = ("double", "triple")


def make_suite(kind: str = "double", **kwargs) -> CryptoSuite:
    digest = kwargs.pop("digest", HashAlg.SHA256)
    cipher = kwargs.pop("cipher", CipherAlg.AES256)
    key_exchange = kwargs.pop("key_exchange", KeyExchangeAlg.X25519)
    if kind == "double":
        kwargs.pop("pq_key_exchange", None)
        kwargs.pop("scka_chunks", None)
        return CryptoSuiteDoubleRatchet(
            digest=digest,
            cipher=cipher,
            key_exchange=key_exchange,
            **kwargs,
        )
    if kind == "triple":
        pq_key_exchange = kwargs.pop("pq_key_exchange", KeyExchangeAlg.MLKEM768)
        scka_chunks = kwargs.pop("scka_chunks", 2)
        return CryptoSuiteTripleRatchet(
            digest=digest,
            cipher=cipher,
            key_exchange=key_exchange,
            pq_key_exchange=pq_key_exchange,
            scka_chunks=scka_chunks,
            **kwargs,
        )
    raise ValueError(f"unknown suite kind: {kind!r}")


def open_pair(
    kind: str = "double",
    first_plain: bytes = b"hi",
    suite: CryptoSuite | None = None,
    opk_id: int = 1,
    spk_id: int = 1,
):
    """Open Alice/Bob sessions for ``kind`` (double or triple).

    Returns
    ``(alice, bob, suite, alice_id, bob_id, spk, opk, bundle, initial, first)``.
    For double, ``opk`` is always present here (callers that need no-OPK open
    their own handshake). For triple, PQ prekey is generated and consumed.
    """
    suite = suite or make_suite(kind)
    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(spk_id, bob_id)
    opk = OneTimePreKey.generate(opk_id, suite)
    if kind == "triple":
        assert isinstance(suite, CryptoSuiteTripleRatchet)
        pq = suite.generate_pq_prekey(1, bob_id)
        bundle = suite.create_bundle(bob_id, spk, opk, pq)
        alice, initial = Session.initiate(alice_id, bundle)
        first = alice.encrypt(first_plain)
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
        first = alice.encrypt(first_plain)
        bob, plain = Session.accept(bob_id, spk, initial, first, opk)
    assert plain == first_plain
    return alice, bob, suite, alice_id, bob_id, spk, opk, bundle, initial, first


@pytest.fixture(params=SUITE_KINDS)
def pair(request):
    """``(kind, alice, bob, suite)`` for each suite kind."""
    kind = request.param
    alice, bob, suite, *_ = open_pair(kind)
    return kind, alice, bob, suite


def ec_ratchet(session: Session) -> DoubleRatchet:
    """Classical Double Ratchet half (whole ratchet on double suites)."""
    ratchet = session.ratchet
    if isinstance(ratchet, TripleRatchet):
        return ratchet.ec
    assert isinstance(ratchet, DoubleRatchet)
    return ratchet


def apply_limits(session: Session, limits: RatchetLimits) -> None:
    """Install limits on the classical half (and SPQR when present)."""
    ratchet = session.ratchet
    if isinstance(ratchet, TripleRatchet):
        ratchet.ec.limits = limits
        ratchet.ec.skipped.limits = limits
        ratchet.spqr.limits = limits
        return
    assert isinstance(ratchet, DoubleRatchet)
    ratchet.limits = limits
    ratchet.skipped.limits = limits


def snap_state(session: Session) -> tuple:
    """Comparable crypto state snapshot via the EC half."""
    r = ec_ratchet(session)
    our = None
    if r.our_ratchet_key is not None:
        our = r.our_ratchet_key.public.data
    idx = None
    if r.receiver_chains:
        idx = r.receiver_chains[0].chain_key.index
    send_idx = None
    if r.sender_chain is not None:
        send_idx = r.sender_chain.chain_key.index
    return (
        r.root_key.key,
        our,
        idx,
        send_idx,
        r.previous_counter,
        len(r.skipped.entries),
        tuple(sorted(r.skipped.entries.keys())),
    )


def msg_counter(message: RatchetMessage) -> int:
    if isinstance(message, TripleRatchetMessage):
        return message.ec_message.counter
    assert isinstance(message, DoubleRatchetMessage)
    return message.counter


def msg_previous_counter(message: RatchetMessage) -> int:
    if isinstance(message, TripleRatchetMessage):
        return message.ec_message.previous_counter
    assert isinstance(message, DoubleRatchetMessage)
    return message.previous_counter


def msg_ratchet_public(message: RatchetMessage) -> bytes:
    if isinstance(message, TripleRatchetMessage):
        return message.ec_message.ratchet_public
    assert isinstance(message, DoubleRatchetMessage)
    return message.ratchet_public


def forge_tampered(
    real: RatchetMessage,
    *,
    ciphertext: bytes | None = None,
    mac: bytes | None = None,
    counter: int | None = None,
    previous_counter: int | None = None,
    ratchet_public: bytes | None = None,
) -> RatchetMessage:
    """Copy ``real`` with selected header/body fields replaced."""
    if isinstance(real, DoubleRatchetMessage):
        return DoubleRatchetMessage(
            ratchet_public=(
                real.ratchet_public if ratchet_public is None else ratchet_public
            ),
            previous_counter=(
                real.previous_counter
                if previous_counter is None
                else previous_counter
            ),
            counter=real.counter if counter is None else counter,
            ciphertext=real.ciphertext if ciphertext is None else ciphertext,
            mac=real.mac if mac is None else mac,
        )
    assert isinstance(real, TripleRatchetMessage)
    ec = real.ec_message
    return TripleRatchetMessage(
        ec_message=DoubleRatchetMessage(
            ratchet_public=(
                ec.ratchet_public if ratchet_public is None else ratchet_public
            ),
            previous_counter=(
                ec.previous_counter
                if previous_counter is None
                else previous_counter
            ),
            counter=ec.counter if counter is None else counter,
            ciphertext=b"",
            mac=b"",
        ),
        spqr_header=real.spqr_header,
        ciphertext=real.ciphertext if ciphertext is None else ciphertext,
        mac=real.mac if mac is None else mac,
    )


def forge_unknown_header(
    kind: str,
    template: RatchetMessage,
    ratchet_public: bytes,
    *,
    mac_len: int = 16,
) -> RatchetMessage:
    """Forged message with an unknown EC ratchet public (state must not move)."""
    if kind == "double":
        return DoubleRatchetMessage(
            ratchet_public=ratchet_public,
            previous_counter=0,
            counter=0,
            ciphertext=b"\x00" * 32,
            mac=b"\x00" * mac_len,
        )
    assert isinstance(template, TripleRatchetMessage)
    return TripleRatchetMessage(
        ec_message=DoubleRatchetMessage(
            ratchet_public=ratchet_public,
            previous_counter=0,
            counter=0,
            ciphertext=b"",
            mac=b"",
        ),
        spqr_header=template.spqr_header,
        ciphertext=b"\x00" * 32,
        mac=b"\x00" * mac_len,
    )


def message_type_for(kind: str):
    if kind == "triple":
        return TripleRatchetMessage
    return DoubleRatchetMessage


def parse_message(kind: str, data: bytes) -> RatchetMessage:
    return message_type_for(kind).from_bytes(data)
