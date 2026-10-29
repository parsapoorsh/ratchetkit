"""AES-128 cipher algorithm."""
from __future__ import annotations


from cryptography.hazmat.primitives.ciphers import algorithms

from ratchetkit.algorithms.cipher.base import CipherAlgorithm


class Aes128(CipherAlgorithm):
    name = "aes128"
    key_size = 16
    block_size = 16
    nonce_size = 16
    algorithm = algorithms.AES
