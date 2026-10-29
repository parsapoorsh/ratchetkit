#!/usr/bin/env python3
"""Single-thread encrypt/decrypt throughput for ratchetkit sessions.

Run from the repo root (or anywhere with ratchetkit installed)::

    python scripts/bench.py
    ./scripts/bench.py
"""

from __future__ import annotations

import platform
import sys
import time
from dataclasses import dataclass
from pathlib import Path

# Allow `./scripts/bench.py` without an editable install.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.prekey import OneTimePreKey, SignedPreKey
from ratchetkit.session import Session
from ratchetkit.suite import (
    CipherAlg,
    CryptoSuiteDoubleRatchet,
    CryptoSuiteTripleRatchet,
    HashAlg,
    KeyExchangeAlg,
)


def double_suite():
    return CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
    )


def triple_suite():
    return CryptoSuiteTripleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
        pq_key_exchange=KeyExchangeAlg.MLKEM768,
        scka_chunks=8,
    )


def open_pair(suite):
    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob_id)
    opk = OneTimePreKey.generate(1, suite)
    if isinstance(suite, CryptoSuiteTripleRatchet):
        pq = suite.generate_pq_prekey(1, bob_id)
        bundle = suite.create_bundle(bob_id, spk, opk, pq)
        alice, initial = Session.initiate(alice_id, bundle)
        first = alice.encrypt(b"setup")
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
        first = alice.encrypt(b"setup")
        bob, plain = Session.accept(bob_id, spk, initial, first, opk)
    assert plain == b"setup"
    reply = bob.encrypt(b"ack")
    assert alice.decrypt(reply) == b"ack"
    return alice, bob


@dataclass
class Result:
    name: str
    payload: int
    mode: str
    msgs: int
    seconds: float
    bytes_total: int

    @property
    def msg_s(self) -> float:
        return self.msgs / self.seconds if self.seconds else 0.0

    @property
    def mb_s(self) -> float:
        return (self.bytes_total / self.seconds) / (1024 * 1024) if self.seconds else 0.0


def fmt(r: Result) -> str:
    return (
        f"{r.name:8s} {r.mode:10s} payload={r.payload:7d}B  "
        f"msgs={r.msgs:7d}  time={r.seconds:6.3f}s  "
        f"{r.msg_s:10,.1f} msg/s  {r.mb_s:8.2f} MB/s"
    )


def run_until(min_seconds: float, min_iters: int, body):
    """body() -> None; returns (iters, elapsed)."""
    for _ in range(16):
        body()
    n = 0
    t0 = time.perf_counter()
    while True:
        body()
        n += 1
        elapsed = time.perf_counter() - t0
        if n >= min_iters and elapsed >= min_seconds:
            return n, elapsed


def bench_encrypt_only(suite, payload: bytes, min_seconds: float, min_iters: int):
    alice, bob = open_pair(suite)

    def once():
        alice.encrypt(payload)

    n, t = run_until(min_seconds, min_iters, once)
    return Result("?", len(payload), "encrypt", n, t, n * len(payload))


def bench_decrypt_only(suite, payload: bytes, min_seconds: float, min_iters: int):
    """Time only decrypt; encrypt is outside the timed section each iter."""
    alice, bob = open_pair(suite)
    for _ in range(16):
        msg = alice.encrypt(payload)
        assert bob.decrypt(msg) == payload

    n = 0
    timed = 0.0
    t_wall0 = time.perf_counter()
    while True:
        msg = alice.encrypt(payload)
        t0 = time.perf_counter()
        out = bob.decrypt(msg)
        timed += time.perf_counter() - t0
        if out != payload:
            raise RuntimeError("mismatch")
        n += 1
        if n >= min_iters and timed >= min_seconds:
            break
        if time.perf_counter() - t_wall0 > min_seconds * 8 and n >= min_iters:
            break
    return Result("?", len(payload), "decrypt", n, timed, n * len(payload))


def bench_send_recv(suite, payload: bytes, min_seconds: float, min_iters: int):
    """One-way send+recv (encrypt then decrypt), both timed."""
    alice, bob = open_pair(suite)

    def once():
        msg = alice.encrypt(payload)
        assert bob.decrypt(msg) == payload

    n, t = run_until(min_seconds, min_iters, once)
    return Result("?", len(payload), "send+recv", n, t, n * len(payload))


def bench_roundtrip(suite, payload: bytes, min_seconds: float, min_iters: int):
    """A->B and B->A; msg count = 2 per iter."""
    alice, bob = open_pair(suite)

    def once():
        m1 = alice.encrypt(payload)
        assert bob.decrypt(m1) == payload
        m2 = bob.encrypt(payload)
        assert alice.decrypt(m2) == payload

    n, t = run_until(min_seconds, min_iters, once)
    msgs = n * 2
    return Result("?", len(payload), "roundtrip", msgs, t, msgs * len(payload))


def main():
    print("=== ratchetkit single-thread throughput ===")
    print(f"python  : {sys.version.split()[0]}")
    print(f"platform: {platform.platform()}")
    print(f"machine : {platform.machine()}")
    try:
        cpu = (
            open("/proc/cpuinfo")
            .read()
            .split("model name")[1]
            .split(":")[1]
            .splitlines()[0]
            .strip()
        )
        print(f"cpu     : {cpu}")
    except Exception:
        pass
    print("thread  : 1 (this process only)")
    print()
    print("Modes:")
    print("  encrypt   - sender.encrypt only (session not mirrored)")
    print("  decrypt   - time bob.decrypt only; encrypt outside timer")
    print("  send+recv - encrypt then decrypt one way, both timed")
    print("  roundtrip - A->B + B->A; msg/s counts both directions")
    print()

    payloads = [64, 1024, 16 * 1024, 64 * 1024, 256 * 1024]
    suites = [
        ("double", double_suite),
        ("triple", triple_suite),
    ]
    min_seconds = 1.5
    min_iters = 200
    results = []

    for sname, suite_fn in suites:
        print(f"--- {sname} ---", flush=True)
        for n in payloads:
            payload = bytes(n)  # fixed zeros; avoids urandom cost in loop setup
            for mode_fn, label in (
                (bench_encrypt_only, "encrypt"),
                (bench_decrypt_only, "decrypt"),
                (bench_send_recv, "send+recv"),
                (bench_roundtrip, "roundtrip"),
            ):
                r = mode_fn(suite_fn(), payload, min_seconds, min_iters)
                r.name = sname
                r.mode = label
                results.append(r)
                print(fmt(r), flush=True)
            print(flush=True)

    print("=== summary table ===")
    print(f"{'suite':8s} {'mode':10s} {'bytes':>8s} {'msg/s':>12s} {'MB/s':>10s}")
    for r in results:
        print(f"{r.name:8s} {r.mode:10s} {r.payload:8d} {r.msg_s:12,.1f} {r.mb_s:10.2f}")

    print()
    print("MB/s = payload_bytes * msgs / time / 1024^2 (not wire size).")
    print("Single-thread Python process on this host.")


if __name__ == "__main__":
    main()
