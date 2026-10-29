"""RSA-3072 OAEP encapsulation + RSA-PSS signatures."""

from __future__ import annotations

from ratchetkit.algorithms.kem.rsa_base import RsaKem


class Rsa3072(RsaKem):
    name = "rsa3072"
    key_size = 3072
