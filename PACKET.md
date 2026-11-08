# Packet formats

Handshake packets, prekey bundles, and session-state blobs start with a
4-byte **constructor id** (`ConstructorId` in `ratchetkit/packing.py`).
Ratchet messages and SCKA chunk frames do not: the live suite selects
the parser. Integers are **big-endian**. Trailing bytes after a complete
constructed object are rejected.

This is not a Signal protobuf / session-record format.

Two families of blobs:

| Family | Used for | Byte-string prefix |
|--------|----------|--------------------|
| Protocol packets | handshake, published bundles | `bytes16` (`u16` length) |
| Ratchet messages | Double / Triple ciphertext | fixed DH public, varint counters, tail MAC |
| Persistence blobs | `Session.to_bytes()` and nested ratchet/suite state | `bytes32` (`u32` length) |

---

## Conventions

| Token | Encoding |
|-------|----------|
| `u8` | 1 byte |
| `u16` | 2 bytes, big-endian |
| `u32` | 4 bytes, big-endian |
| `varint` | unsigned LEB128 (7 data bits per byte, high bit continues) |
| `bool` | `u8`: `0x00` false, `0x01` true; any other value is invalid |
| `bytes16` | `u16 length` then `length` bytes. Max `0xFFFF`. |
| `bytes32` | `u32 length` then `length` bytes. Max `0xFFFFFFFF`. |
| `opt<T>` | `bool present`; if true, `T` follows |
| `constructor` | `u32` constructor id |

Public keys on protocol packets are stored as **raw key bytes** plus a
separate `u32` algorithm id. Persistence blobs use the nested key
encodings in [Nested key material](#nested-key-material).

Algorithm ids are the permanent `IntEnum` values in `ratchetkit/suite/algs.py`.

### HashAlg

| Id | Name |
|----|------|
| 1 | SHA256 |
| 2 | SHA384 |
| 3 | SHA512 |
| 4 | SHA3_256 |
| 5 | BLAKE2B |

### CipherAlg

| Id | Name |
|----|------|
| 1 | AES128 |
| 2 | AES256 |
| 3 | CAMELLIA128 |
| 4 | CAMELLIA256 |
| 5 | CHACHA20 |

Suites reject 128-bit ciphers (`AES128`, `CAMELLIA128`). Block ciphers
run in CTR. The HMAC tag is the CTR / ChaCha nonce (SIV).

### KeyExchangeAlg

| Id | Name |
|----|------|
| 1 | X25519 |
| 2 | X448 |
| 3 | SECP256R1 |
| 4 | SECP384R1 |
| 5 | SECP521R1 |
| 6 | RSA2048 |
| 7 | RSA4096 |
| 8 | MLKEM768 |
| 9 | MLKEM1024 |
| 10 | RSA3072 |

### SigningAlg

| Id | Name |
|----|------|
| 1 | ED25519 |
| 2 | ED448 |
| 3 | ECDSA_SECP256R1 |
| 4 | ECDSA_SECP384R1 |
| 5 | ECDSA_SECP521R1 |
| 6 | RSA_PSS_2048 |
| 7 | RSA_PSS_4096 |
| 8 | MLDSA65 |
| 9 | MLDSA87 |
| 10 | RSA_PSS_3072 |

---

## Constructor ids

The high 16 bits are `0x524B` (`RK`). Protocol packets live in `0x524B001x`.
Persistence blobs live in `0x524B002x`.

| Id | Name | Class | Family |
|----|------|-------|--------|
| `0x524B0010` | `PREKEY_BUNDLE` | `PreKeyBundle` | protocol |
| `0x524B0011` | `INITIAL_MESSAGE_X3DH` | `InitialMessageX3DH` | protocol |
| `0x524B0015` | `INITIAL_MESSAGE_PQXDH` | `InitialMessagePQXDH` | protocol |
| `0x524B0020` | `SESSION` | `Session` | persistence |
| `0x524B0021` | `SUITE_DOUBLE` | `CryptoSuiteDoubleRatchet` | persistence |
| `0x524B0022` | `SUITE_TRIPLE` | `CryptoSuiteTripleRatchet` | persistence |
| `0x524B0023` | `DOUBLE_RATCHET` | `DoubleRatchet` | persistence |
| `0x524B0024` | `TRIPLE_RATCHET` | `TripleRatchet` | persistence |
| `0x524B0025` | `SPQR` | `SparsePostQuantumRatchet` | persistence |
| `0x524B0026` | `SCKA` | `ChunkedKemScka` | persistence |

Parse constructed objects by reading the leading `u32` and dispatching.
An unknown id is a serialization error. Ratchet messages are parsed with
`suite.Message.from_bytes(blob, suite)`.

---

## Protocol packets

These are the blobs a peer actually sends. Handshake and bundle types
use `to_bytes()` / `from_bytes()`. Ratchet messages use
`suite.Message.from_bytes(blob, suite)`.

### PreKeyBundle (`0x524B0010`)

Published identity material for X3DH or PQXDH initiation.
`suite.create_bundle(...)` builds it; the initiator verifies signatures
before `Session.initiate`.

```
constructor                 u32     0x524B0010
identity_signing            bytes16
identity_signing_alg        u8      SigningAlg
has_agreement               bool
  identity_agreement        bytes16          if has_agreement
  identity_agreement_alg    u8      KeyExchangeAlg
signed_prekey_id            u16
signed_prekey               bytes16
signed_prekey_alg           u8      KeyExchangeAlg
signed_prekey_signature     bytes16
has_opk                     bool
  one_time_prekey_id        u16              if has_opk
  one_time_prekey           bytes16
  one_time_prekey_alg       u8      KeyExchangeAlg
has_pq                      bool             omitted on older bundles
  pq_prekey_id              u16              if has_pq
  pq_prekey                 bytes16
  pq_prekey_alg             u8      KeyExchangeAlg
  pq_prekey_signature       bytes16
```

`has_agreement` is false for KEM-only identity (no DH public).
`has_opk` is false when the bundle has no one-time prekey.

`has_pq` may be absent: if the parser is at end-of-blob after the OPK
section, PQ fields are treated as missing (classical X3DH bundle). A
present `0x00` means "no PQ prekey"; `0x01` requires all four PQ fields.

The signed-prekey signature covers `u8(signed_prekey_alg) || signed_prekey`.
The PQ prekey signature covers `u8(pq_prekey_alg) || pq_prekey`. Both
are verified with `identity_signing`.

---

### InitialMessageX3DH (`0x524B0011`)

First handshake message from initiator to responder (public half only).
Returned by `Session.initiate` for a Double Ratchet suite.

```
constructor                 u32     0x524B0011
identity_signing            bytes16
identity_signing_alg        u8      SigningAlg
has_agreement               bool
  identity_agreement        bytes16          if has_agreement
  identity_agreement_alg    u8      KeyExchangeAlg
ephemeral_public            bytes16
ephemeral_alg               u8      KeyExchangeAlg
kem_ct_count                u8
  kem_ciphertext            bytes16          kem_ct_count times
signed_prekey_id            u16
has_opk                     bool
  one_time_prekey_id        u16              if has_opk
signature                   bytes16
has_ratchet                 bool
  ratchet_public            bytes16          if has_ratchet
```

`kem_ciphertexts` holds encapsulations to the responder's signed prekey
and optional one-time prekey on KEM-only suites. DH suites send
`kem_ct_count = 0`.

`ratchet_public` is the initiator's first Double Ratchet public (DH
public, or KEM public+CT via [RatchetHeader](#ratchetheader-kem)).
`Session.accept` requires it.

The initiator signature covers:

```
identity_agreement_data || ephemeral_public || signed_prekey_public
  || concat(kem_ciphertexts) || ratchet_public
```

PQXDH also appends `pq_ciphertext` to that material (see next packet).

---

### InitialMessagePQXDH (`0x524B0015`)

PQXDH first message: the full X3DH body, then PQ fields.
Returned by `Session.initiate` for a Triple Ratchet suite.
`pq_ciphertext` is required and must be non-empty.

```
constructor                 u32     0x524B0015
...X3DH body (same fields as InitialMessageX3DH after its constructor)...
pq_prekey_id                u16
pq_ciphertext               bytes16
```

The constructor is `INITIAL_MESSAGE_PQXDH`, so the X3DH body starts
immediately after those 4 bytes (no nested X3DH constructor).

---

### DoubleRatchetMessage

Application ciphertext for a classical Double Ratchet session.
No constructor id; the session suite selects the parser
(`suite.Message.from_bytes(blob, suite)`).

```
ratchet_public              bytes   DH: kem.public_size; KEM: RatchetHeader
previous_counter            varint
counter                     varint
ciphertext                  bytes   until last tag_size bytes
mac                         bytes   suite.tag_size, last
```

`header_bytes()` (authenticated under the MAC) is:

```
ratchet_public
previous_counter            varint
counter                     varint
```

`ratchet_public` is a [RatchetHeader](#ratchetheader-kem): raw DH public
(`kem.public_size` bytes, no length prefix) for DH suites, or
length-prefixed KEM public + encapsulation CT.

`previous_counter` is the sending chain index from the previous ratchet
step (skip bookkeeping). `counter` is this message's chain index.

Ciphertext is stream encryption (ChaCha20 or block cipher in CTR) under
the per-message cipher key. HMAC is computed first over

```
associated_data || header_bytes || plaintext
```

truncated to `suite.tag_size` (default 16, min 10). That tag is the CTR /
ChaCha nonce (padded with zeros on the right if shorter than the nonce,
or truncated on the left if longer). The tag is sent after the ciphertext
with no length prefix. Session AD is
`initiator_signing_public || responder_signing_public`; extra per-message
AD is appended.

---

### TripleRatchetMessage

Hybrid message: EC Double Ratchet header + SPQR header + one ciphertext
encrypted under `KDF_HYBRID(ec_mk, pq_mk)`. No constructor id.

```
ec_header                   bytes   Double Ratchet header_bytes
spqr_header                 bytes   SpqrHeader (self-describing)
ciphertext                  bytes   until last tag_size bytes
mac                         bytes   suite.tag_size, last
```

`ec_header` is **not** a full `DoubleRatchetMessage`. It is only:

```
ratchet_public              bytes   same rule as Double Ratchet
previous_counter            varint
counter                     varint
```

`spqr_header` is an [SpqrHeader](#spqrheader).

`header_bytes()` for the MAC is `ec_header || spqr_header`.
MAC coverage is the same rule as Double Ratchet:
`associated_data || header_bytes || plaintext` (tag is the CTR nonce).

---

### ChunkFrame

One SCKA chunk (or ack-only frame) carried inside `SpqrHeader.scka_msg`.
ML-KEM public keys / ciphertexts are split across `n_chunks` application
messages. No constructor id; `n_chunks` comes from the suite.

```
flags                       u8
key_epoch                   varint
chunk_index                 varint
ack_count                   varint
payload_len                 varint
data_len                    varint
data                        bytes   data_len bytes
```

| Flag | Value | Meaning |
|------|-------|---------|
| `FLAG_PAYLOAD` | `0x01` | `data` is one indexed chunk of a KEM payload |
| `FLAG_ACK_ONLY` | `0x02` | no payload; `data` is empty |

`payload_len` is the unpadded reconstructed payload length (needed
because chunks are zero-padded to equal width). Reconstruction requires
all `n_chunks` distinct `chunk_index` values for the same `key_epoch`.

---

## Nested protocol encodings

These have no constructor of their own. They appear inside protocol
fields.

### RatchetHeader (KEM)

Opaque `ratchet_public` on Double Ratchet messages.

**DH suites:** the field is the raw public key.

**KEM-only suites:**

```
public_len                  u16
public                      bytes
ciphertext_len              u16
ciphertext                  bytes
```

Chain identity for skipped-key lookup is the encapsulation ciphertext.

### SpqrHeader

Sparse PQ ratchet header inside `TripleRatchetMessage`.

```
t_s                         varint  sending key epoch
previous2_counter           varint  period in the epoch before last
previous_counter            varint  period in the previous sending epoch
counter                     varint  period in t_s
scka_msg                    bytes   a ChunkFrame (self-describing)
```

### SCKA payload (reconstructed)

After joining chunks, the payload is a typed KEM exchange:

**Bootstrap** (kind 0) — advertise a public key:

```
kind                        u8      0
public_len                  u16
public                      bytes
```

**Exchange** (kind 1) — encapsulation plus the next local public:

```
kind                        u8      1
ciphertext_len              u16
ciphertext                  bytes
public_len                  u16
public                      bytes
```

---

## Persistence blobs

`Session.to_bytes()` writes a self-describing secret blob: suite,
associated data, and full ratchet state. Treat it as key material.
The format is not stable across library major versions unless documented
otherwise.

All nested byte strings in this section use `bytes32`.

### Session (`0x524B0020`)

```
constructor                 u32     0x524B0020
suite                       bytes32   SUITE_DOUBLE or SUITE_TRIPLE blob
associated_data             bytes32
ratchet                     bytes32   DOUBLE_RATCHET or TRIPLE_RATCHET blob
```

`from_bytes` reads the suite constructor first, then restores the
matching ratchet type. A Triple suite blob must nest a Triple ratchet.

---

### CryptoSuiteDoubleRatchet (`0x524B0021`)

```
constructor                 u32     0x524B0021
digest                      u32     HashAlg
cipher                      u32     CipherAlg
key_exchange                u32     KeyExchangeAlg
signing                     u32     SigningAlg
tag_size                    u32
```

---

### CryptoSuiteTripleRatchet (`0x524B0022`)

```
constructor                 u32     0x524B0022
digest                      u32     HashAlg
cipher                      u32     CipherAlg
key_exchange                u32     KeyExchangeAlg
signing                     u32     SigningAlg
tag_size                    u32
pq_key_exchange             u32     KeyExchangeAlg
scka_chunks                 u32
```

---

### DoubleRatchet (`0x524B0023`)

```
constructor                 u32     0x524B0023
root_key                    bytes32   RootKey
previous_counter            u32
limits                      bytes32   RatchetLimits
sender_chain                opt<bytes32>   SenderChain
receiver_count              u32
  receiver_chain            bytes32   ReceiverChain, receiver_count times
skipped                     bytes32   SkippedMessageKeys
our_ratchet_key             opt<bytes32>   KeyPair
sender_header               opt<bytes32>   opaque RatchetHeader bytes
their_kem_public            opt<bytes32>   PublicKey (KEM-only)
```

---

### TripleRatchet (`0x524B0024`)

```
constructor                 u32     0x524B0024
ec                          bytes32   DOUBLE_RATCHET blob
spqr                        bytes32   SPQR blob
```

---

### SparsePostQuantumRatchet (`0x524B0025`)

```
constructor                 u32     0x524B0025
root_key                    bytes32
direction                   u8      0 = A2B, 1 = B2A
mixed_epoch                 u32
t_s                         u32
t_r                         u32
t_curr                      u32
previous_counter            u32
previous2_counter           u32
limits                      bytes32   RatchetLimits
scka                        bytes32   SCKA blob
chains                      bytes32   see below
skipped                     bytes32   see below
```

`chains` body:

```
count                       u32
  epoch                     u32
  epoch_chains              bytes32   EpochChains
                    (count times, epochs sorted ascending)
```

`skipped` body:

```
count                       u32
  epoch                     u32
  counter                   u32
  keys                      bytes32   MessageKeys
                    (count times, insertion order)
```

---

### ChunkedKemScka (`0x524B0026`)

```
constructor                 u32     0x524B0026
n_chunks                    u32
is_cka_sender               bool
our_key                     opt<bytes32>   KeyPair
their_public                opt<bytes32>   PublicKey
epoch                       u32
send_chunks                 opt<bytes32>   see below
send_chunk_index            u32
send_payload_len            u32
send_key_epoch              u32
pending_send_secret         opt<bytes32>
pending_mix_secret          opt<bytes32>
recv_chunks                 bytes32        see below
recv_payload_len            u32
recv_key_epoch              u32
peer_ack                    u32
```

`send_chunks` body (when present):

```
count                       u32
  chunk                     bytes32        count times
```

`recv_chunks` body:

```
count                       u32
  index                     u32
  chunk                     bytes32        count times, indices sorted
```

---

## Nested key material

These encodings have no constructor. They are always wrapped in
`bytes32` by the parent persistence blob.

### PublicKey / SigningPublicKey

```
algorithm                   u32     KeyExchangeAlg or SigningAlg
data                        bytes32
```

### KeyPair / SigningKeyPair

```
algorithm                   u32
private                     bytes32
public                      bytes32 raw public key bytes (not a nested PublicKey)
```

### RootKey

```
key                         bytes32   digest_size bytes, nonzero
```

### ChainKey

```
key                         bytes32   digest_size bytes, nonzero
index                       u32
```

### MessageKeys

```
cipher_key                  bytes32
mac_key                     bytes32
counter                     u32
```

### SenderChain

```
ratchet_key                 bytes32   KeyPair
chain_key                   bytes32   ChainKey
```

### ReceiverChain

```
ratchet_public              bytes32   PublicKey
chain_key                   bytes32   ChainKey
```

### EpochChains

```
has_send                    bool
  send                      bytes32   ChainKey, if has_send
has_receive                 bool
  receive                   bytes32   ChainKey, if has_receive
```

### RatchetLimits

```
MAX_FORWARD_JUMPS           u32     default 25000
MAX_MESSAGE_KEYS            u32     default 2000
MAX_RECEIVER_CHAINS         u32     default 5
```

### SkippedMessageKeys

```
limits                      bytes32   RatchetLimits
count                       u32
  ratchet_id                bytes32
  counter                   u32
  keys                      bytes32   MessageKeys (keys.counter must equal counter)
                    (count times, insertion order)
```

---

## Typical sizes (informational)

Field lengths follow the suite. Common values:

| Material | Size |
|----------|------|
| X25519 public | 32 |
| Ed25519 public | 32 |
| Ed25519 signature | 64 |
| ML-KEM-768 public | 1184 |
| ML-KEM-768 ciphertext | 1088 |
| AES-256 key / ChaCha20 key | 32 |
| AES-256 CTR nonce (from tag) | 16 |
| ChaCha20 nonce | 12 |
| SHA-256 digest / HMAC | 32 |
| MAC tag on the wire | `tag_size` (default 16) |

A Double Ratchet message with X25519 + AES-256 + 16-byte tag is:

```
32 (ratchet_public) + varint previous + varint counter
  + len(ciphertext) + 16 (mac)
```

For counters below 128 that is 50 bytes of overhead plus the ciphertext.

---

## Source map

| Packet | Source |
|--------|--------|
| Constructor ids, `bytes32` helpers | `ratchetkit/packing.py` |
| PreKeyBundle | `ratchetkit/keys/prekey.py` |
| InitialMessageX3DH / PQXDH | `ratchetkit/handshake/message.py` |
| DoubleRatchetMessage | `ratchetkit/ratchet/message/double.py` |
| TripleRatchetMessage | `ratchetkit/ratchet/message/triple.py` |
| ChunkFrame | `ratchetkit/scka/chunk.py` |
| RatchetHeader | `ratchetkit/ratchet/header.py` |
| SpqrHeader | `ratchetkit/ratchet/spqr.py` |
| SCKA payload | `ratchetkit/scka/kem_scka.py` |
| Session | `ratchetkit/session.py` |
| Suites | `ratchetkit/suite/double.py`, `suite/triple.py` |
| Double / Triple ratchet state | `ratchetkit/ratchet/protocol/double.py`, `protocol/triple.py` |
