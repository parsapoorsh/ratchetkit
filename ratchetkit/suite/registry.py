"""Static backend class tables for suite algorithm enums.

Maps are built at import time. ``keys.keypair`` must not import this module
at top level (only inside ``KeyPair.public`` / ``SigningKeyPair.public``) so
KEM modules can import ``KeyPair`` while this module imports those KEMs.
"""

from __future__ import annotations

from ratchetkit.algorithms.cipher.base import (
    Aes128,
    Aes256,
    Camellia128,
    Camellia256,
)
from ratchetkit.algorithms.cipher.chacha20 import ChaCha20
from ratchetkit.algorithms.hash.base import (
    Blake2b,
    Sha256,
    Sha3256,
    Sha384,
    Sha512,
)
from ratchetkit.algorithms.kem.ec_base import Secp256r1, Secp384r1, Secp521r1
from ratchetkit.algorithms.kem.mlkem_base import Mlkem1024, Mlkem768
from ratchetkit.algorithms.kem.rsa_base import Rsa2048, Rsa3072, Rsa4096
from ratchetkit.algorithms.kem.x25519 import X25519
from ratchetkit.algorithms.kem.x448 import X448
from ratchetkit.algorithms.signing.ecdsa import (
    EcdsaSecp256r1,
    EcdsaSecp384r1,
    EcdsaSecp521r1,
)
from ratchetkit.algorithms.signing.ed25519 import Ed25519
from ratchetkit.algorithms.signing.ed448 import Ed448
from ratchetkit.algorithms.signing.mldsa import Mldsa65, Mldsa87
from ratchetkit.algorithms.signing.rsa_pss import RsaPss2048, RsaPss3072, RsaPss4096
from ratchetkit.suite.algs import CipherAlg, HashAlg, KeyExchangeAlg, SigningAlg

HASH = {
    HashAlg.SHA256: Sha256,
    HashAlg.SHA384: Sha384,
    HashAlg.SHA512: Sha512,
    HashAlg.SHA3_256: Sha3256,
    HashAlg.BLAKE2B: Blake2b,
}

CIPHER = {
    CipherAlg.AES128: Aes128,
    CipherAlg.AES256: Aes256,
    CipherAlg.CAMELLIA128: Camellia128,
    CipherAlg.CAMELLIA256: Camellia256,
    CipherAlg.CHACHA20: ChaCha20,
}

KEY_EXCHANGE = {
    KeyExchangeAlg.X25519: X25519,
    KeyExchangeAlg.X448: X448,
    KeyExchangeAlg.SECP256R1: Secp256r1,
    KeyExchangeAlg.SECP384R1: Secp384r1,
    KeyExchangeAlg.SECP521R1: Secp521r1,
    KeyExchangeAlg.RSA2048: Rsa2048,
    KeyExchangeAlg.RSA3072: Rsa3072,
    KeyExchangeAlg.RSA4096: Rsa4096,
    KeyExchangeAlg.MLKEM768: Mlkem768,
    KeyExchangeAlg.MLKEM1024: Mlkem1024,
}

SIGNING = {
    SigningAlg.ED25519: Ed25519,
    SigningAlg.ED448: Ed448,
    SigningAlg.ECDSA_SECP256R1: EcdsaSecp256r1,
    SigningAlg.ECDSA_SECP384R1: EcdsaSecp384r1,
    SigningAlg.ECDSA_SECP521R1: EcdsaSecp521r1,
    SigningAlg.RSA_PSS_2048: RsaPss2048,
    SigningAlg.RSA_PSS_3072: RsaPss3072,
    SigningAlg.RSA_PSS_4096: RsaPss4096,
    SigningAlg.MLDSA65: Mldsa65,
    SigningAlg.MLDSA87: Mldsa87,
}
