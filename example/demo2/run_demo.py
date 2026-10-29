#!/usr/bin/env python3
"""Run checkpoint then resume phases back-to-back."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent


def run_phase(module: str) -> int:
    sys.stdout.write("\n")
    sys.stdout.write("=" * 60 + "\n")
    sys.stdout.write(f"  {module}\n")
    sys.stdout.write("=" * 60 + "\n")
    sys.stdout.flush()
    result = subprocess.run(
        [sys.executable, "-u", "-m", module],
        cwd=str(ROOT),
        check=False,
    )
    return result.returncode


def main() -> int:
    rc = run_phase("example.demo2.phase_checkpoint")
    if rc != 0:
        print("demo FAILED (checkpoint)", flush=True)
        return rc
    rc = run_phase("example.demo2.phase_resume")
    if rc != 0:
        print("demo FAILED (resume)", flush=True)
        return rc
    print("\ndemo OK", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
