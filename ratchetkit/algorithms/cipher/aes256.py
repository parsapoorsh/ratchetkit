"""AES-256 cipher algorithm."""
from __future__ import annotations


from cryptography.hazmat.primitives.ciphers import algorithms

from ratchetkit.algorithms.cipher.base import CipherAlgorithm


class Aes256(CipherAlgorithm):
    name = "aes256"
    key_size = 32
    block_size = 16
    nonce_size = 16
    algorithm = algorithms.AES
