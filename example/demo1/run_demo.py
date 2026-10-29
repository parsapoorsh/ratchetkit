#!/usr/bin/env python3
"""Start server and client; print their logs interleaved as they happen."""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SOCKET = HERE / "ratchetkit.sock"


def pump(stream, lock: threading.Lock) -> None:
    """Read lines from a process and print them under a lock."""
    if stream is None:
        return
    for line in stream:
        with lock:
            sys.stdout.write(line)
            sys.stdout.flush()


def main() -> int:
    if SOCKET.exists():
        SOCKET.unlink()

    lock = threading.Lock()
    # Run as modules so example.* imports work; ratchetkit must be installed.
    python = sys.executable
    server = subprocess.Popen(
        [python, "-u", "-m", "example.server"],
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    server_thread = threading.Thread(
        target=pump,
        args=(server.stdout, lock),
        daemon=True,
    )
    server_thread.start()

    for attempt in range(100):
        if SOCKET.exists():
            break
        if server.poll() is not None:
            server_thread.join(timeout=1)
            return 1
        time.sleep(0.05)
    else:
        server.kill()
        print("timeout waiting for server socket")
        return 1

    client = subprocess.Popen(
        [python, "-u", "-m", "example.client"],
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    client_thread = threading.Thread(
        target=pump,
        args=(client.stdout, lock),
        daemon=True,
    )
    client_thread.start()

    client_rc = client.wait(timeout=30)
    client_thread.join(timeout=2)

    try:
        server_rc = server.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server.kill()
        server_rc = server.wait(timeout=2)

    server_thread.join(timeout=2)

    ok = client_rc == 0 and server_rc == 0
    print("demo OK" if ok else "demo FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
