"""RSA-3072 KEM smoke test."""

from ratchetkit.algorithms.hash.sha256 import Sha256
from ratchetkit.algorithms.kem.rsa3072 import Rsa3072
from ratchetkit.algorithms.signing.rsa_pss import RsaPss3072


def test_rsa3072_encapsulate_roundtrip():
    kem = Rsa3072()
    pair = kem.generate_keypair()
    secret, ct = kem.encapsulate(pair.public)
    assert kem.decapsulate(pair, ct) == secret

    signer = RsaPss3072()
    signing = signer.generate_keypair()
    sig = signer.sign(signing, b"msg", Sha256)
    signer.verify(signing.public, b"msg", sig, Sha256)
