"""KDF and chain-key derivation tests."""

from ratchetkit.algorithms.hash.sha256 import Sha256
from ratchetkit.kdf import Kdf
from ratchetkit.keys.chain import ChainKey
from ratchetkit.suite import (
    SigningAlg,
    ChainKeySeed,
    CipherAlg,
    CryptoSuiteDoubleRatchet,
    HashAlg,
    KdfLabel,
    KeyExchangeAlg,
)


def test_hmac_and_hkdf_basic():
    kdf = Kdf(HashAlg.SHA256)
    tag = kdf.hmac_digest(b"key", b"data")
    assert len(tag) == Sha256.digest_size
    okm = kdf.hkdf(b"ikm", 42, salt=b"salt", info=KdfLabel.X3DH)
    assert len(okm) == 42


def test_chain_key_derivation_vector():
    """Port of libsignal ratchet/keys.rs chain-key HMAC step.

    MessageKeys cipher and MAC material in libsignal is expanded with the ASCII
    info string ``WhisperMessageKeys``; our KdfLabel bytes differ, so only the
    pure HMAC(chain, 0x01/0x02) stepping is asserted against their vectors.
    """
    seed = bytes(
        [
            0x8A,
            0xB7,
            0x2D,
            0x6F,
            0x4C,
            0xC5,
            0xAC,
            0x0D,
            0x38,
            0x7E,
            0xAF,
            0x46,
            0x33,
            0x78,
            0xDD,
            0xB2,
            0x8E,
            0xDD,
            0x07,
            0x38,
            0x5B,
            0x1C,
            0xB0,
            0x12,
            0x50,
            0xC7,
            0x15,
            0x98,
            0x2E,
            0x7A,
            0xD4,
            0x8F,
        ]
    )
    next_chain_key = bytes(
        [
            0x28,
            0xE8,
            0xF8,
            0xFE,
            0xE5,
            0x4B,
            0x80,
            0x1E,
            0xEF,
            0x7C,
            0x5C,
            0xFB,
            0x2F,
            0x17,
            0xF3,
            0x2C,
            0x7B,
            0x33,
            0x44,
            0x85,
            0xBB,
            0xB7,
            0x0F,
            0xAC,
            0x6E,
            0xC1,
            0x03,
            0x42,
            0xA2,
            0x46,
            0xD1,
            0x5D,
        ]
    )

    suite = CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
        signing=SigningAlg.ED25519,
    )
    chain = ChainKey(seed, 0, suite)
    assert chain.key == seed
    assert chain.index == 0
    assert chain.next_chain_key().key == next_chain_key
    assert chain.next_chain_key().index == 1
    assert chain.message_keys().counter == 0
    assert chain.next_chain_key().message_keys().counter == 1
    # HMAC(seed, CHAIN_KEY_SEED) is exactly next_chain_key
    kdf = Kdf(HashAlg.SHA256)
    assert kdf.hmac_digest(seed, ChainKeySeed.CHAIN_KEY_SEED) == next_chain_key
