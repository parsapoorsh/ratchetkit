"""ML-KEM-1024 (FIPS 203)."""
from __future__ import annotations


from cryptography.hazmat.primitives.asymmetric import mlkem

from ratchetkit.algorithms.kem.mlkem_base import MlkemBackend
from ratchetkit.suite.algs import KeyExchangeAlg


class Mlkem1024(MlkemBackend):
    algorithm = KeyExchangeAlg.MLKEM1024
    kem_private_cls = mlkem.MLKEM1024PrivateKey
    kem_public_cls = mlkem.MLKEM1024PublicKey
