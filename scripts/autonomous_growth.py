"""Deny-only compatibility probe; legacy implementation is not distributed."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))


def _deny_legacy_execution():
    from forgestra_safety import require

    require("product_creation")


_deny_legacy_execution()


def create_repository(destination, files):
    from local_generation import write_creator_output

    return write_creator_output(destination, files)
