"""Load OpenSSL-generated algorithm goldens."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

GOLDENS_PATH = Path(__file__).with_name("openssl_goldens.json")


@pytest.fixture(scope="module")
def goldens() -> dict:
    return json.loads(GOLDENS_PATH.read_text())
