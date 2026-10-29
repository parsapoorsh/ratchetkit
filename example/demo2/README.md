# Session resume + out-of-order demo

Shows two things demo1 does not:

1. **Session persistence** — `Session.to_bytes()` / `Session.from_bytes()`
2. **Out-of-order delivery** — skipped message keys when counters arrive late

No sockets. Phase 1 writes session blobs and a small on-disk mailbox; phase 2
restores the sessions (no new X3DH/PQXDH) and drains the mailbox shuffled.

Both phases load the same suite from `suite_config.ACTIVE_SUITE`. Classical
Double Ratchet:

```python
# example/demo2/suite_config.py
ACTIVE_SUITE = demo_suite  # X25519 Double Ratchet
```

Default is Triple Ratchet (`demo_suite_triple`).

## Run

Install the library first (from the repo root):

```bash
pip install -e ".[dev]"
```

Then:

```bash
python -m example.demo2.run_demo
```

Or the two phases by hand:

```bash
python -m example.demo2.phase_checkpoint
python -m example.demo2.phase_resume
```

State lands under `example/demo2/state/` (`alice.session`, `bob.session`,
`mailbox/msg_*.bin`). Treat session files as **secret key material**.

## What the demo shows

1. **Handshake + short chat** in process A (X3DH or PQXDH once).
2. Alice encrypts `m0`, `m1`, `m2` while Bob is “offline”; frames go to the mailbox.
3. Both sessions are **checkpointed** to disk; process A exits.
4. Process B **restores** from blobs — same ratchet state, no new handshake.
5. Bob decrypts mailbox order **`m2`, `m0`, `m1`**:
   - `m2` first → skipped-key cache grows (keys for counters 0 and 1)
   - `m0` / `m1` consume those keys → `skipped` returns to 0
6. Chat continues on the restored sessions; blobs are written again.

Logs print `counter`, ratchet fingerprint, and `skipped=` so you can watch the
cache fill and drain.
