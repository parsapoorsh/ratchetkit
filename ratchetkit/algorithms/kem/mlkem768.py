"""ML-KEM-768. (FIPS 203)."""
from __future__ import annotations


from cryptography.hazmat.primitives.asymmetric import mlkem

from ratchetkit.algorithms.kem.mlkem_base import MlkemBackend
from ratchetkit.suite.algs import KeyExchangeAlg


class Mlkem768(MlkemBackend):
    algorithm = KeyExchangeAlg.MLKEM768
    kem_private_cls = mlkem.MLKEM768PrivateKey
    kem_public_cls = mlkem.MLKEM768PublicKey
