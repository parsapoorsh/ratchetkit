# ratchetkit

Python **X3DH** / **PQXDH** key agreement + **Double Ratchet**,
**Sparse Post-Quantum Ratchet (SPQR)**, and **Triple Ratchet** with pluggable
crypto primitives.

Not Signal-wire-compatible: no protobuf, no session-record format.
Includes native PQXDH (classical DH + signed PQ prekey) for Triple suites.
Triple Ratchet follows Signal Double Ratchet rev 4 §5-§6 and the hybrid design
in [ePrint 2025/078](https://eprint.iacr.org/2025/078).

Licensed under **AGPL-3.0-only** (same family as libsignal).

## Install

```bash
pip install ratchetkit
```

Requires Python 3.10+ and `cryptography>=45` (ML-KEM / ML-DSA).

### Development

```bash
pip install -e ".[dev]"
```

## Quick start (classical Double Ratchet)

```python
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.prekey import OneTimePreKey, SignedPreKey
from ratchetkit.session import Session
from ratchetkit.suite import CipherAlg, HashAlg, KeyExchangeAlg, SigningAlg
from ratchetkit.suite.double import CryptoSuiteDoubleRatchet

suite = CryptoSuiteDoubleRatchet(
    digest=HashAlg.SHA256,
    cipher=CipherAlg.AES256,
    key_exchange=KeyExchangeAlg.X25519,
    signing=SigningAlg.ED25519,
)

alice = IdentityKeyPair.generate(suite)
bob = IdentityKeyPair.generate(suite)
spk = SignedPreKey.generate(1, bob)
opk = OneTimePreKey.generate(1, suite)
bundle = suite.create_bundle(bob, spk, opk)

alice_session, initial = Session.initiate(alice, bundle)
msg = alice_session.encrypt(b"hello")
# Wire formats: initial.to_bytes(), msg.to_bytes()

bob_session, plaintext = Session.accept(bob, spk, initial, msg, opk)
assert plaintext == b"hello"

reply = bob_session.encrypt(b"hi back")
assert alice_session.decrypt(reply) == b"hi back"

# Optional per-message AD is appended to the handshake identity AD.
msg = alice_session.encrypt(b"meta", associated_data=b"msg-id:1")
assert bob_session.decrypt(msg, associated_data=b"msg-id:1") == b"meta"

# Persist / restore full session state (includes suite + ratchet keys).
blob = alice_session.to_bytes()
alice_session = Session.from_bytes(blob)
```

## Triple Ratchet (classical + sparse PQ)

Use **`CryptoSuiteTripleRatchet`**: classical Double Ratchet in parallel with a
Sparse PQ Ratchet driven by chunked ML-KEM SCKA. Message keys are combined with
`KDF_HYBRID` before encrypt-then-HMAC. All PQ fields are required

```python
from ratchetkit.suite import CipherAlg, HashAlg, KeyExchangeAlg, SigningAlg
from ratchetkit.suite.triple import CryptoSuiteTripleRatchet

suite = CryptoSuiteTripleRatchet(
    digest=HashAlg.SHA256,
    cipher=CipherAlg.AES256,
    key_exchange=KeyExchangeAlg.X25519,       # classical DH ratchet
    signing=SigningAlg.ED25519,
    pq_key_exchange=KeyExchangeAlg.MLKEM768,  # sparse PQ ratchet
    scka_chunks=8,  # split each ML-KEM payload across 8 app messages
)

alice = IdentityKeyPair.generate(suite)
bob = IdentityKeyPair.generate(suite)
spk = SignedPreKey.generate(1, bob)
opk = OneTimePreKey.generate(1, suite)
pq = suite.generate_pq_prekey(1, bob)
bundle = suite.create_bundle(bob, spk, pq, opk)

alice_session, initial = Session.initiate(alice, bundle)
msg = alice_session.encrypt(b"triple hello")
bob_session, plain = Session.accept(
    bob, spk, initial, msg, opk, our_pq_prekey=pq,
)
assert plain == b"triple hello"
```

`scka_chunks` amortizes large ML-KEM public keys / ciphertexts (same idea as
the Triple Ratchet paper's chunk encoding). Smaller values recover PQ entropy
faster at higher per-message overhead.

## Crypto suites

```python
from ratchetkit.suite import CipherAlg, HashAlg, KeyExchangeAlg, SigningAlg
from ratchetkit.suite.double import CryptoSuiteDoubleRatchet
from ratchetkit.suite.triple import CryptoSuiteTripleRatchet

# Classical Double Ratchet only
double = CryptoSuiteDoubleRatchet(
    digest=HashAlg.SHA512,
    cipher=CipherAlg.CHACHA20,
    key_exchange=KeyExchangeAlg.SECP256R1,
    signing=SigningAlg.ECDSA_SECP256R1,
)

# Triple Ratchet: classical + required PQ half
triple = CryptoSuiteTripleRatchet(
    digest=HashAlg.SHA256,
    cipher=CipherAlg.AES256,
    key_exchange=KeyExchangeAlg.X25519,
    signing=SigningAlg.ED25519,
    pq_key_exchange=KeyExchangeAlg.MLKEM768,
    scka_chunks=8,
)

# KEM-only agreement path still uses Double Ratchet suite (OPK required).
# This is not Triple Ratchet - KEM steps run inside Double Ratchet.
pq_identity = CryptoSuiteDoubleRatchet(
    digest=HashAlg.SHA3_256,
    cipher=CipherAlg.AES256,
    key_exchange=KeyExchangeAlg.MLKEM768,
    signing=SigningAlg.MLDSA65,
)
```

`CryptoSuiteDoubleRatchet` holds digest / cipher / key_exchange / signing /
`kem` / `signer`. `CryptoSuiteTripleRatchet` subclasses it and adds required
`pq_key_exchange`, `scka_chunks`, and `pq_kem`. Agreement and signing are
independent (`KeyExchangeAlg` vs `SigningAlg`).

Block ciphers always use **CTR** inside the cipher algorithm class. Message
authentication is always encrypt-then-HMAC. Cipher keys must be **at least
256 bits** (AES-128 / Camellia-128 are rejected).

Each hash, cipher, KEM, and signing backend lives under
`ratchetkit/algorithms/hash/`, `cipher/`, `kem/`, and `signing/`.

| `KeyExchangeAlg` | Agreement | Notes |
|------------------|-----------|--------|
| `X25519` / `X448` / `SECP...` | DH | classic Double Ratchet |
| `RSA2048` / `RSA3072` / `RSA4096` | RSA-OAEP KEM | OPK required |
| `MLKEM768` / `MLKEM1024` | ML-KEM | OPK required; `cryptography>=45` |

| `SigningAlg` | Notes |
|--------------|--------|
| `ED25519` / `ED448` | Edwards curves |
| `ECDSA_SECP...` | NIST ECDSA |
| `RSA_PSS_2048` / `3072` / `4096` | RSA-PSS |
| `MLDSA65` / `MLDSA87` | ML-DSA; `cryptography>=45` |

For **Triple Ratchet**, use classical `key_exchange` (e.g. X25519) and set
`pq_key_exchange` to `MLKEM768` or `MLKEM1024` on `CryptoSuiteTripleRatchet`.

## Security notes (Double Ratchet alignment)

This is **not** a wire-compatible Signal client. It follows the Double Ratchet
design (trial decrypt, KDF chains, skipped-key handling) with these hardened
behaviors:

| Topic | Behavior |
|-------|----------|
| Trial decrypt | State clones on decrypt; only commits after MAC success |
| Skipped keys | Hard cap (`MAX_MESSAGE_KEYS`); overflow raises, never silently drops |
| Forward jump | Cap (`MAX_FORWARD_JUMPS`) stops skip DoS |
| DH public keys | Invalid / low-order points -> `InvalidMessage` (no state change) |
| Empty / zero secrets | Root, chain, and DH outputs rejected |
| MAC | Encrypt-then-HMAC, constant-time compare; `tag_size` default 16 (min 10) |
| Secure deletion | Python cannot guarantee wipe of GC'd bytes; drop references promptly |
| OPKs | Caller must delete one-time prekeys after a successful accept |

Limits default to libsignal-like values (`RatchetLimits`). Tune carefully:
raising `MAX_MESSAGE_KEYS` / `MAX_FORWARD_JUMPS` increases DoS surface.

## State

The ratchet mutates on every successful encrypt/decrypt. Failed MAC checks do
**not** advance ratchet state.

### Session persistence

`Session.to_bytes()` / `Session.from_bytes()` serialize the full live session:
crypto suite, associated data, and all ratchet state (root/chain keys, skipped
message keys, SPQR/SCKA state for Triple). The blob is self-describing (suite
is inside), so restore does not need a separate suite argument.

```python
blob = session.to_bytes()          # secret key material - store encrypted
session = Session.from_bytes(blob)
```

Treat the blob as secret. This is **not** a Signal session-record format and is
not stable across library major versions unless documented otherwise.

Callers must delete one-time prekeys after a successful accept (the library
does not track OPK consumption).

## Layout

```
ratchetkit/
  algorithms/
    hash/     # Sha256, Sha512, ...
    cipher/   # Aes256, ChaCha20, ...
    kem/      # X25519, Secp256r1, Rsa2048, Mlkem768, ...
    signing/  # Ed25519, Ecdsa, RsaPss, Mldsa, ...
  suite/      # Double + Triple suites, alg enums, registry
  keys/       # ChainKey, RootKey, MessageKeys, PreKeyBundle, ...
  handshake/  # X3DH + PQXDH handshakes
  scka/       # Chunked ML-KEM Sparse Continuous Key Agreement
  packing.py  # Constructor base + ConstructorId
  ratchet/
    message/    # RatchetMessage ABC, Double + Triple wire codecs
    protocol/   # Ratchet ABC, DoubleRatchet, TripleRatchet
    spqr.py     # SparsePostQuantumRatchet
  session.py  # Session facade
```

A Unix-socket Alice/Bob demo lives under `example/demo1/`.

## Tests

```bash
pytest
```
