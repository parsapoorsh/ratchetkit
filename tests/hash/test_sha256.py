"""Sha256 algorithm smoke test."""

from ratchetkit.algorithms.hash.base import Sha256


def test_sha256_digest():
    assert Sha256.new(b"abc").hexdigest() == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert Sha256.digest_size == 32
