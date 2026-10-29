"""RSA-3072 KEM smoke test."""

from ratchetkit.algorithms.hash.sha256 import Sha256
from ratchetkit.algorithms.kem.rsa3072 import Rsa3072


def test_rsa3072_encapsulate_roundtrip():
    kem = Rsa3072()
    pair = kem.generate_keypair()
    secret, ct = kem.encapsulate(pair.public)
    assert kem.decapsulate(pair.private, ct) == secret

    signing = kem.generate_signing_keypair()
    sig = kem.sign(signing.private, b"msg", Sha256)
    kem.verify(signing.public, b"msg", sig, Sha256)
