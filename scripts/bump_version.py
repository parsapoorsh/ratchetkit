#!/usr/bin/env python3
"""Bump package version, commit, and create an annotated git tag.

Usage (from repo root)::

    python scripts/bump_version.py v1.3.0
    ./scripts/bump_version.py 1.3.0

Updates:
  - pyproject.toml  ``version = "..."``
  - ratchetkit/__init__.py  ``__version__ = "..."``

Then stages those files, commits, and creates an annotated tag.
Does not push.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PYPROJECT = ROOT / "pyproject.toml"
INIT = ROOT / "ratchetkit" / "__init__.py"

TAG_RE = re.compile(r"^v?(\d+\.\d+\.\d+(?:[a-zA-Z0-9._-]*)?)$")
VERSION_TOML_RE = re.compile(
    r'^(version\s*=\s*")[^"]*(")',
    re.MULTILINE,
)
VERSION_INIT_RE = re.compile(
    r'^(__version__\s*=\s*")[^"]*(")',
    re.MULTILINE,
)


def parse_tag(raw: str) -> tuple[str, str]:
    """Return (tag_name with v-prefix, bare version string)."""
    raw = raw.strip()
    match = TAG_RE.match(raw)
    if not match:
        raise SystemExit(
            f"invalid tag {raw!r}; expected something like v1.3.0 or 1.3.0"
        )
    version = match.group(1)
    tag = f"v{version}"
    return tag, version


def replace_one(path: Path, pattern: re.Pattern[str], version: str) -> None:
    text = path.read_text(encoding="utf-8")
    new_text, n = pattern.subn(rf"\g<1>{version}\2", text, count=1)
    if n != 1:
        raise SystemExit(f"could not find a single version assignment in {path}")
    if new_text == text:
        raise SystemExit(f"version in {path} is already {version!r}")
    path.write_text(new_text, encoding="utf-8")


def run(args: list[str]) -> None:
    print("+", " ".join(args))
    subprocess.run(
        args,
        cwd=ROOT,
        check=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Bump version files, commit, and tag (no push).",
    )
    parser.add_argument(
        "tag",
        help="version tag, e.g. v1.3.0 or 1.3.0",
    )
    args = parser.parse_args()

    tag, version = parse_tag(args.tag)

    # Refuse dirty tree outside the files we own.
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    dirty = [line for line in status.splitlines() if line.strip()]
    if dirty:
        raise SystemExit(
            "working tree is dirty; commit or stash first:\n" + "\n".join(dirty)
        )

    # Refuse existing tag.
    existing = subprocess.run(
        ["git", "rev-parse", "-q", "--verify", f"refs/tags/{tag}"],
        cwd=ROOT,
        capture_output=True,
    )
    if existing.returncode == 0:
        raise SystemExit(f"tag {tag} already exists")

    replace_one(PYPROJECT, VERSION_TOML_RE, version)
    replace_one(INIT, VERSION_INIT_RE, version)

    run(["git", "add", "--", str(PYPROJECT.relative_to(ROOT)), str(INIT.relative_to(ROOT))])
    run([
        "git",
        "commit",
        "-m",
        f"Bump version to {version}",
    ])
    run([
        "git",
        "tag",
        "-a",
        tag,
        "-m",
        f"Release {tag}",
    ])

    print(f"bumped to {version}, committed, tagged {tag} (not pushed)")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        sys.exit(exc.returncode)
