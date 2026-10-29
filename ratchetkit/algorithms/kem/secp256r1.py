"""SECP256R1 ECDH."""
from __future__ import annotations


from cryptography.hazmat.primitives.asymmetric import ec

from ratchetkit.algorithms.kem.ec_base import EcKem
from ratchetkit.suite.algs import KeyExchangeAlg


class Secp256r1(EcKem):
    algorithm = KeyExchangeAlg.SECP256R1
    curve = ec.SECP256R1()
