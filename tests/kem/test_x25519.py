"""X25519 KEM smoke test."""

from ratchetkit.algorithms.hash.sha256 import Sha256
from ratchetkit.algorithms.kem.x25519 import X25519
from ratchetkit.algorithms.signing.ed25519 import Ed25519


def test_x25519_encapsulate_roundtrip():
    kem = X25519()
    pair = kem.generate_keypair()
    secret, ct = kem.encapsulate(pair.public)
    assert kem.decapsulate(pair, ct) == secret

    signer = Ed25519()
    signing = signer.generate_keypair()
    sig = signer.sign(signing, b"msg", Sha256)
    signer.verify(signing.public, b"msg", sig, Sha256)
